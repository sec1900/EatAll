"""扫描事件检测 + POC 版本对比（二期）。

核心语义：
- 扫描事件（episode）= 同一 src_ip 的会话簇，按空闲间隔分割（> EPISODE_GAP_SEC 视为新一轮扫描）
- 事件键 (src_ip, tool_guess)——同 IP 的不同工具各自独立对比
- 相邻事件 diff：new = 本次有上次无（对方升级的新 POC）、removed = 本次无上次有、
  unchanged = 交集；同一扫描器再次扫描时新增清单即"升级了哪些 POC"
- 全局库快照：sha256(排序的 "模板文件名:yaml内容hash")，hash 变化即库版本变化

幂等：scan_id = scan-{src_ip}-{ts_start}，重复计算只更新不重复插入。
注意：pocs.source_session_ids 每模板最多保留 256 个会话 id，重扫描极频繁的
模板其早期会话可能被截断，事件-POC 映射有轻微损失（可接受）。
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Optional

from db import DB

logger = logging.getLogger("eatall.scans")

# 空闲间隔超过该值视为新一轮扫描（秒）。
# 可用环境变量 EATALL_EPISODE_GAP_SEC 覆盖（慢扫描器调大、演示/测试调小）。
EPISODE_GAP_SEC = int(os.environ.get("EATALL_EPISODE_GAP_SEC", "120"))


def _is_loopback(ip: str) -> bool:
    """回环来源（本机自测）不参与版本记录——版本 = 外部扫描器的升级历史。"""
    return ip == "::1" or ip == "127.0.0.1" or ip.startswith("127.")


def _now_ms() -> int:
    return int(time.time() * 1000)


# ---------- 事件检测 ----------

def detect_episodes(
    sessions: list[tuple[str, str, int]], gap_ms: int
) -> list[dict]:
    """按 src_ip 分组、ts 排序、gap 分割为扫描事件。

    sessions: [(session_id, src_ip, ts_start), ...]
    返回: [{src_ip, ts_start, ts_end, session_ids, conn_count}, ...]
    """
    by_src: dict[str, list[tuple[int, str]]] = {}
    for sid, ip, ts in sessions:
        by_src.setdefault(ip, []).append((ts, sid))

    episodes: list[dict] = []
    for ip in sorted(by_src):
        rows = sorted(by_src[ip])
        if not rows:
            continue
        cur = {
            "src_ip": ip,
            "ts_start": rows[0][0],
            "ts_end": rows[0][0],
            "session_ids": [rows[0][1]],
            "conn_count": 1,
        }
        for ts, sid in rows[1:]:
            if ts - cur["ts_end"] > gap_ms:
                episodes.append(cur)
                cur = {
                    "src_ip": ip,
                    "ts_start": ts,
                    "ts_end": ts,
                    "session_ids": [sid],
                    "conn_count": 1,
                }
            else:
                cur["ts_end"] = ts
                cur["session_ids"].append(sid)
                cur["conn_count"] += 1
        episodes.append(cur)
    return episodes


def _assign_tool(db: DB, episode: dict) -> str:
    """取事件窗口内 tool_conf 最高的 flow 的 tool_guess。"""
    rows = db.conn.execute(
        """SELECT tool_guess, tool_conf FROM flows
           WHERE src_ip = ? AND ts_start <= ? AND ts_end >= ?""",
        (episode["src_ip"], episode["ts_end"], episode["ts_start"]),
    ).fetchall()
    best, best_conf = "", -1.0
    for r in rows:
        conf = r["tool_conf"] or 0.0
        if conf > best_conf and r["tool_guess"]:
            best, best_conf = r["tool_guess"], conf
    return best


# ---------- POC 集 ----------

def _poc_index(db: DB) -> dict[str, set[str]]:
    """session_id -> {模板文件名}（pocs.source_session_ids 建索引）。"""
    index: dict[str, set[str]] = {}
    for r in db.get_pocs():
        fname = os.path.basename(r["template_path"] or "")
        if not fname:
            continue
        for sid in json.loads(r["source_session_ids"] or "[]"):
            index.setdefault(sid, set()).add(fname)
    return index


def _episode_poc_ids(index: dict[str, set[str]], episode: dict) -> list[str]:
    files: set[str] = set()
    for sid in episode["session_ids"]:
        files |= index.get(sid, set())
    return sorted(files)


# ---------- diff ----------

def _diff_episodes(
    db: DB, episodes: list[dict], index: dict[str, set[str]], now_ms: int
) -> list[dict]:
    """计算闭合事件的 POC 集 + 相邻 (src_ip, tool) diff。

    返回可直接 upsert 的 scan 字典列表。
    """
    # 只处理闭合事件（该 IP 无新会话且距 now 超过 gap）
    gap = EPISODE_GAP_SEC * 1000
    closed = [e for e in episodes if now_ms - e["ts_end"] > gap]
    if not closed:
        return []

    # 补 tool_guess
    # (src_ip, tool) 分组按时间排序
    groups: dict[tuple[str, str], list[dict]] = {}
    for e in closed:
        e2 = dict(e)
        e2["tool_guess"] = _assign_tool(db, e)
        groups.setdefault((e2["src_ip"], e2["tool_guess"]), []).append(e2)

    scans: list[dict] = []
    for (_ip, _tool), seq in groups.items():
        prev_files: set[str] = set()
        for e in sorted(seq, key=lambda x: x["ts_start"]):
            files = _episode_poc_ids(index, e)
            cur = set(files)
            new_pocs = sorted(cur - prev_files)
            removed_pocs = sorted(prev_files - cur)
            scans.append({
                "scan_id": f"scan-{e['src_ip']}-{e['ts_start']}",
                "src_ip": e["src_ip"],
                "tool_guess": e["tool_guess"],
                "ts_start": e["ts_start"],
                "ts_end": e["ts_end"],
                "conn_count": e["conn_count"],
                "session_ids": e["session_ids"],
                "poc_ids": files,
                "new_pocs": new_pocs,
                "removed_pocs": removed_pocs,
                "poc_count": len(files),
                "new_count": len(new_pocs),
                "removed_count": len(removed_pocs),
            })
            prev_files = cur
    return scans


# ---------- 探活流量过滤 ----------

def _filter_health_check(sessions: list, detail: dict, min_repeat: int = 3) -> list:
    """剔除高频重复同路径的 HTTP 探活会话（health check / 前端轮询 / 监控探针）。

    特征：同一 (src_ip, dst_port, 路径) 组合重复 ≥ min_repeat 次——真实攻击扫描
    的路径是多样化的，固定路径高频重复是探活噪音。这些会话仍入库（不丢证据），
    只是不参与扫描事件分割（否则永不闭合）。
    注意：非 HTTP 会话不参与过滤——爆破/批量探测本身就是同协议重复连接，那是攻击信号。
    """
    from collections import Counter
    path_of = {}
    for s in sessions:
        sid = s[0]  # sessions 是 (session_id, src_ip, ts_start) 元组
        r = detail.get(sid)
        if r is None or r["proto"] not in ("http", "tls-http"):
            continue  # 非 HTTP：保留（爆破重复连接是攻击信号）
        p = _parsed_of(r)
        path = p.get("path", "")
        if not path:
            continue  # 空路径（未解析/非标准）不参与探活判定
        path_of[sid] = (r["src_ip"], r["dst_port"], path)
    counts = Counter(path_of.values())
    health = {sid for sid in path_of if counts[path_of[sid]] >= min_repeat}
    if health:
        logger.info("过滤探活会话 %d 条（高频重复同路径）", len(health))
    return [s for s in sessions if s[0] not in health]


# ---------- 端口聚合与攻击分类 ----------

# 非 HTTP 攻击意图词表（http 复用 poc_builder.http_builder.detect_vulns）
_REDIS_ATTACK_CMDS = {"INFO", "CONFIG", "KEYS", "FLUSHALL", "FLUSHDB", "SLAVEOF", "REPLCONF"}
_DNS_ENUM_MIN = 10  # 批量不同 qname 判定枚举


def _parsed_of(row) -> dict:
    try:
        out = json.loads(row["parsed_json"] or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}
    return out if isinstance(out, dict) else {}  # "null" 也是合法 JSON → None


def _classify_port(proto: str, sess: list) -> list:
    """按端口会话聚合判定攻击/探测意图。sess: 同一 dst_port 的会话行列表。

    蜜罐无真实漏洞——"攻击"= 攻击性探测/爆破尝试/未授权探测/POC 请求。
    """
    attacks: list[str] = []
    n = len(sess)
    if proto == "http" or proto == "tls-http":
        from classify import classify
        for s in sess:
            p = _parsed_of(s)
            text = f"{p.get('method', '')} {p.get('path', '')}"
            r = classify(text)
            if r["kind"] == "unknown":
                attacks.append("unknown_attack")  # 可疑但无法归类——绝不静默归探测
                break
            if r["kind"] != "probe":
                attacks.append("poc_attempt")
                break
        if not attacks:
            attacks.append("probe")
    elif proto == "ssh":
        # 短连接批量 kexinit（认证阶段未实现，会话在 kexinit 后挂起）→ 爆破探测特征
        if n >= 5:
            attacks.append("ssh_brute_probe")
        else:
            attacks.append("probe")
    elif proto == "mysql":
        users = {p.get("login", {}).get("username") for s in sess
                 if (p := _parsed_of(s)).get("login", {}).get("username")}
        if len(users) >= 3:
            attacks.append("mysql_brute")
        else:
            attacks.append("probe")
    elif proto == "redis":
        cmds = {c[0].upper() for s in sess for c in _parsed_of(s).get("commands", []) if c}
        if cmds & _REDIS_ATTACK_CMDS:
            attacks.append("unauthorized_probe")
        else:
            attacks.append("probe")
    elif proto == "ftp":
        pairs = sum(1 for s in sess for c in _parsed_of(s).get("commands", [])
                    if c.get("cmd") == "USER")
        if pairs >= 3:
            attacks.append("ftp_brute")
        else:
            attacks.append("probe")
    elif proto == "smb":
        if any(_parsed_of(s).get("session_setup") for s in sess) or n >= 3:
            attacks.append("smb_probe")
        else:
            attacks.append("probe")
    elif proto == "dns":
        # or [] 防御：历史数据里 queries 可能为 null（Go nil 切片序列化）
        qnames = {q.get("qname") for s in sess for q in (_parsed_of(s).get("queries") or []) if q.get("qname")}
        if len(qnames) >= _DNS_ENUM_MIN:
            attacks.append("dns_enum")
        else:
            attacks.append("probe")
    else:  # generic / 未知
        # 连接即断、无 payload → 端口探测特征
        short = sum(1 for s in sess if (s["client_len"] or 0) < 16)
        attacks.append("port_probe" if short >= max(1, n // 2) else "probe")
    return attacks


def _port_sample(proto: str, sess: list) -> dict:
    """每端口第一条有意义的探测内容（供界面展示）。"""
    for s in sess:
        p = _parsed_of(s)
        if proto == "http" or proto == "tls-http":
            path = p.get("path", "")
            if path and path != "/":
                return {"path": path[:200], "method": p.get("method", "")}
        elif proto == "ssh":
            if p.get("client_id"):
                return {"client_id": p["client_id"][:100]}
        elif proto == "mysql":
            if p.get("login", {}).get("username"):
                return {"username": p["login"]["username"][:64]}
        elif proto == "redis":
            cmds = p.get("commands", [])
            if cmds:
                return {"command": " ".join(cmds[0])[:200]}
        elif proto == "ftp":
            cmds = p.get("commands", [])
            if cmds:
                c = cmds[0]
                return {"command": f"{c.get('cmd','')} {c.get('arg','')}".strip()[:120]}
        elif proto == "smb":
            if p.get("dialects"):
                return {"dialects": p["dialects"][:8]}
        elif proto == "dns":
            qs = p.get("queries", [])
            if qs:
                return {"qname": qs[0].get("qname", "")[:120]}
    return {}


def _aggregate_ports(sess_details: list) -> dict:
    """事件会话 → {dst_port: {proto, banner, conn_count, attacks, sample}}。"""
    ports: dict[int, dict] = {}
    for s in sess_details:
        port = s["dst_port"]
        p = ports.setdefault(port, {
            "proto": s["proto"], "banner": s["banner"] or "",
            "conn_count": 0, "sess": [],
        })
        p["conn_count"] += 1
        p["sess"].append(s)
    out = {}
    for port, p in ports.items():
        out[port] = {
            "dst_port": port,
            "proto": p["proto"],
            "banner": p["banner"],
            "conn_count": p["conn_count"],
            "attacks": _classify_port(p["proto"], p["sess"]),
            "sample": _port_sample(p["proto"], p["sess"]),
        }
    return out


# ---------- 库快照 ----------

def _lib_hash(db: DB) -> tuple[int, str]:
    """返回 (poc_count, lib_hash)。hash = sha256(排序的 "文件名:yaml内容sha256")。"""
    entries = []
    count = 0
    for r in db.get_pocs():
        fname = os.path.basename(r["template_path"] or "")
        if not fname:
            continue
        yaml_text = r["template_yaml"] or ""
        entries.append(f"{fname}:{hashlib.sha256(yaml_text.encode('utf-8')).hexdigest()}")
        count += 1
    h = hashlib.sha256("\n".join(sorted(entries)).encode("utf-8")).hexdigest()[:16]
    return count, h


# ---------- 入口 ----------

def compute_scans(db: DB, now_ms: Optional[int] = None) -> dict:
    """计算扫描事件 diff + 端口清单/攻击分类 + 库快照。幂等。"""
    now = now_ms or _now_ms()

    # 1. 事件检测（带端口/协议/解析明细，供攻击分类；先剔除探活噪音）
    rows = db.conn.execute(
        "SELECT session_id, src_ip, ts_start, dst_port, proto, banner,"
        " length(client_bytes) AS client_len, parsed_json FROM sessions"
    ).fetchall()
    detail = {r["session_id"]: r for r in rows}
    sessions = [(r["session_id"], r["src_ip"], r["ts_start"]) for r in rows]
    sessions = [s for s in sessions if not _is_loopback(s[1])]  # 回环自测不参与版本
    sessions = _filter_health_check(sessions, detail)
    episodes = detect_episodes(sessions, EPISODE_GAP_SEC * 1000)

    # 2. POC 索引 + diff（事件带端口明细）
    index = _poc_index(db)
    scans = _diff_episodes(db, episodes, index, now)
    for s in scans:
        sess_detail = [detail[sid] for sid in s["session_ids"] if sid in detail]
        ports = _aggregate_ports(sess_detail)
        s["ports_hit"] = sorted(ports.keys())
        s["_ports_detail"] = ports

    # 3. 判定新闭合扫描（须在 upsert 之前查，否则全部已存在）
    new_scans = [s for s in scans if db.get_scan(s["scan_id"]) is None]

    # 4. 幂等 upsert（事件 + 端口明细）
    ports_written = 0
    for s in scans:
        db.upsert_scan(scan=s)
        for port_info in s["_ports_detail"].values():
            db.upsert_scan_port(
                scan_id=s["scan_id"], dst_port=port_info["dst_port"],
                proto=port_info["proto"], banner=port_info["banner"],
                conn_count=port_info["conn_count"],
                attacks=port_info["attacks"], sample=port_info["sample"],
            )
            ports_written += 1

    # 5. 版本快照：每个新闭合的扫描事件记一条（扫一次记一个版本）。
    #    无新扫描不落快照——避免管道轮询导致版本线随库持续吸收而疯狂翻新。
    count, h = _lib_hash(db)
    for s in new_scans:
        db.upsert_lib_snapshot(
            ts=s["ts_end"], poc_count=count, lib_hash=h,
            scan_id=s["scan_id"], src_ip=s["src_ip"], tool=s["tool_guess"],
        )

    # 6. 预计算网站探测思路/利用链（闭合事件不可变，一次算好存库；
    #    详情请求直接读，不再每次重算 4s）。分析函数只依赖 parsed_json/ts_start。
    for s in new_scans:
        sess_rows = [dict(detail[sid]) for sid in s["session_ids"] if sid in detail]
        if not sess_rows:
            continue
        from webscan import analyze_webscan
        from chain import analyze_chains
        wp = analyze_webscan(sess_rows[-3000:]) or None
        ch = analyze_chains(sess_rows) or None
        db.update_scan_analysis(
            scan_id=s["scan_id"],
            web_probe_json=json.dumps(wp, ensure_ascii=False) if wp else None,
            chains_json=json.dumps(ch, ensure_ascii=False) if ch else None,
        )

    return {
        "episodes": len(episodes),
        "scans_written": len(scans),
        "ports_written": ports_written,
        "poc_count": count,
        "lib_hash": h,
    }
