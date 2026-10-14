"""EatAll 展示界面服务端：纯标准库 HTTP 服务 + JSON API。

绑定 0.0.0.0 默认（局域网可访问）；界面暴露捕获的攻击数据，仅限受信网络。

API:
  GET /                        → 单页前端
  GET /api/overview            → 卡片统计 + 最近活动 + 协议分布 + TOP 来源
  GET /api/sessions?src&proto&limit&offset → 分页会话（过滤）
  GET /api/sessions/<id>       → 会话详情（parsed/原始字节 hex+ascii）
  GET /api/flows               → 扫描器（指纹）列表
  GET /api/pocs?search&severity&status&limit&offset → POC 库
  GET /api/pocs/<filename>     → 模板 YAML 原文（从 DB 取，不碰文件系统）
  GET /api/scans               → 扫描事件（版本控制视图）
  GET /api/scans/<id>          → 事件明细（新增/移除 POC 详情）
  GET /api/lib                 → 全局库快照版本线
"""
from __future__ import annotations

import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, unquote

# 允许从 pipeline/ 直接运行: python dashboard/server.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import DB  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"
BYTES_PREVIEW = 64 * 1024  # 原始字节展示上限
INFO_RE = re.compile(
    r"^info:\s*\n\s*name:\s*\"?([^\"]+?)\"?\s*\n\s*author:.*?\n\s*severity:\s*(\w+)",
    re.M | re.S,
)
TAGS_RE = re.compile(r"^\s*tags:\s*(.+)$", re.M)

_ts_cache: dict = {}  # 模板信息缓存（文件名 → {name, severity, tags}），带 TTL


def _parse_template_info(yaml_text: str) -> dict:
    m = INFO_RE.search(yaml_text or "")
    tags_m = TAGS_RE.search(yaml_text or "")
    return {
        "name": (m.group(1).strip() if m else ""),
        "severity": (m.group(2).strip() if m else "unknown"),
        "tags": (tags_m.group(1).strip() if tags_m else ""),
    }


def _exploit_type(yaml_text: str) -> str:
    """分层分类引擎：rce / sql_injection / traversal / xss / brute / ssrf /
    deserialization / expression / obfuscation / unknown / probe。"""
    from classify import classify
    return classify(yaml_text or "")["kind"]


def _poc_info_map(db: DB, ttl: float = 5.0) -> dict:
    """filename → {name, severity, tags}，5s TTL 缓存。"""
    now = time.time()
    cache = _ts_cache.get("map")
    if cache and now - cache[0] < ttl:
        return cache[1]
    info_map = {}
    for r in db.get_pocs():
        fname = Path(r["template_path"] or "").name
        if not fname:
            continue
        info_map[fname] = _parse_template_info(r["template_yaml"] or "")
    _ts_cache["map"] = (now, info_map)
    return info_map


def _hex_ascii(data: bytes) -> dict:
    """原始字节 → hex + ascii 双视图（超限截断）。"""
    truncated = len(data) > BYTES_PREVIEW
    data = data[:BYTES_PREVIEW]
    ascii_view = "".join(
        chr(b) if 32 <= b < 127 else "." for b in data
    )
    return {
        "hex": data.hex(" "),
        "ascii": ascii_view,
        "len": len(data),
        "truncated": truncated,
    }


# ---------- 任务执行引擎（控制台：浏览器触发 scanner/clone/attack）----------

class TaskRunner:
    """后台执行 scanner/clone/attack 脚本，状态供前端轮询。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._task = None  # {id, type, status, log, result, started, finished}
        self._seq = 0

    def start(self, task_type: str, args: list[str], cwd: str) -> dict:
        with self._lock:
            if self._task and self._task["status"] in ("running", "queued"):
                return {"error": "已有任务在运行，请等待完成"}
            self._seq += 1
            task = {
                "id": f"task-{self._seq}",
                "type": task_type,
                "status": "queued",
                "log": [],
                "result": "",
                "started": None,
                "finished": None,
            }
            self._task = task
        threading.Thread(target=self._run, args=(task, args, cwd), daemon=True).start()
        return {"ok": True, "id": task["id"]}

    def _run(self, task: dict, args: list[str], cwd: str):
        task["status"] = "running"
        task["started"] = time.time()
        import subprocess
        try:
            proc = subprocess.Popen(
                [sys.executable] + args, cwd=cwd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                task["log"].append(line.rstrip())
                if len(task["log"]) > 500:
                    task["log"] = task["log"][-500:]
            proc.wait()
            task["result"] = f"exit={proc.returncode}"
        except Exception as exc:  # noqa: BLE001
            task["log"].append(f"ERROR: {exc}")
            task["result"] = "error"
        finally:
            task["status"] = "done"
            task["finished"] = time.time()

    def status(self) -> dict:
        with self._lock:
            if not self._task:
                return {"running": False, "task": None}
            t = dict(self._task)
            return {"running": t["status"] in ("running", "queued"), "task": t}

    def clear(self):
        with self._lock:
            self._task = None


# 全局任务执行器
_runner = TaskRunner()


class Api:
    """API 数据层。线程本地连接：每个请求线程独立只读连接
    （ThreadingHTTPServer 的 worker 线程不能用主线程创建的 SQLite 连接）。"""

    def __init__(self, db: Optional[DB] = None):
        self._local = threading.local()
        if db is not None:
            # 测试注入：复用外部连接（同线程内使用）
            self._local.conn = db
        # 扫描事件详情缓存（大事件 webprobe/利用链计算重；闭合事件内容不可变）
        self._detail_cache: dict[str, tuple[float, dict]] = {}
        self._DETAIL_CACHE_TTL = 60.0

    @property
    def db(self) -> DB:
        if not hasattr(self._local, "conn"):
            self._local.conn = DB()
        return self._local.conn

    # ---------- overview ----------
    def overview(self) -> dict:
        db = self.db
        day_ago = int(time.time() * 1000) - 24 * 3600_000
        recent = db.list_sessions(limit=20)
        latest = db.latest_lib_snapshot()
        return {
            "session_total": db.session_count(),
            "session_today": db.sessions_since(day_ago),
            "flow_count": db.flow_count(),
            "poc_count": db.poc_count(),
            "scan_count": db.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            "lib_hash": latest["lib_hash"] if latest else "",
            "lib_ts": latest["ts"] if latest else None,
            "recent": [dict(r) for r in recent],
            "protocols": [dict(r) for r in db.protocol_distribution()],
            "top_srcs": [dict(r) for r in db.top_srcs()],
        }

    # ---------- sessions ----------
    def sessions(self, q: dict) -> dict:
        limit = int(q.get("limit", ["50"])[0] or 50)
        offset = int(q.get("offset", ["0"])[0] or 0)
        src = q.get("src", [None])[0] or None
        proto = q.get("proto", [None])[0] or None
        kw = q.get("q", [None])[0] or None
        total = self.db.session_count_filtered(src, proto, kw)
        rows = self.db.list_sessions(src=src, proto=proto, kw=kw, limit=limit, offset=offset)
        return {"total": total, "items": [dict(r) for r in rows]}

    def session_detail(self, sid: str) -> Optional[dict]:
        r = self.db.get_session_by_id(sid)
        if r is None:
            return None
        out = dict(r)
        out["client"] = _hex_ascii(r["client_bytes"] or b"")
        out["server"] = _hex_ascii(r["server_bytes"] or b"")
        del out["client_bytes"], out["server_bytes"]
        try:
            out["parsed"] = json.loads(r["parsed_json"] or "{}")
        except json.JSONDecodeError:
            out["parsed"] = {}
        return out

    # ---------- flows ----------
    def flows(self, q: dict = None) -> dict:
        q = q or {}
        search = q.get("search", [None])[0] or None
        limit = int(q.get("limit", ["50"])[0] or 50)
        offset = int(q.get("offset", ["0"])[0] or 0)
        rows = self.db.list_flows(limit=10000)
        items = []
        for r in rows:
            d = dict(r)
            d["ports_hit"] = json.loads(r["ports_hit"] or "[]")
            d["behaviors"] = json.loads(r["behaviors"] or "[]")
            items.append(d)
        if search:
            s = search.lower()
            items = [
                d for d in items
                if s in (d["src_ip"] or "").lower()
                or s in (d.get("tool_guess") or "").lower()
                or s in " ".join(d["ports_hit"]).lower()
            ]
        total = len(items)
        return {"total": total, "items": items[offset:offset + limit]}

    # ---------- pocs ----------
    def pocs(self, q: dict) -> dict:
        search = q.get("search", [None])[0] or None
        severity = q.get("severity", [None])[0] or None
        status = q.get("status", [None])[0] or None
        exploit = q.get("exploit", [None])[0] or None
        limit = int(q.get("limit", ["200"])[0] or 200)
        offset = int(q.get("offset", ["0"])[0] or 0)
        # exploit/severity 过滤在 SQL 分页之后会截断——需要过滤时放大读取量
        fetch_limit = 5000 if (exploit or severity) else limit
        rows = self.db.list_pocs_full(search=search, status=status,
                                      limit=fetch_limit, offset=offset)
        items = []
        for r in rows:
            info = _parse_template_info(r["template_yaml"] or "")
            if severity and info["severity"] != severity:
                continue
            et = _exploit_type(r["template_yaml"] or "")
            if exploit and et != exploit:
                continue
            items.append({
                "poc_id": r["poc_id"],
                "filename": Path(r["template_path"] or "").name,
                "type": r["type"],
                "name": info["name"],
                "severity": info["severity"],
                "tags": info["tags"],
                "exploit_type": _exploit_type(r["template_yaml"] or ""),
                "status": r["status"],
                "confidence": r["confidence"],
                "hit_count": r["hit_count"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
            })
        total = len(items)
        return {"total": total, "items": items}

    def poc_yaml(self, filename: str) -> Optional[str]:
        for r in self.db.get_pocs():
            if Path(r["template_path"] or "").name == filename:
                return r["template_yaml"] or ""
        return None

    # ---------- scans（版本控制） ----------
    def scans(self) -> dict:
        """版本历史列表（瘦身：不带 session_ids/poc_ids 大数组，计数替代；
        new_detail 只给前 20 条预览——完整清单在详情接口）。"""
        info_map = _poc_info_map(self.db)
        items = []
        for r in self.db.list_scans():
            d = dict(r)
            for key in ("session_ids", "poc_ids", "new_pocs", "removed_pocs", "ports_hit"):
                d[key] = json.loads(r[key] or "[]")
            d["session_count"] = len(d["session_ids"])
            del d["session_ids"], d["poc_ids"]
            d["new_detail"] = [
                {"file": f, **_poc_info_map_get(info_map, f)} for f in d["new_pocs"][:20]
            ]
            d["removed_detail"] = [
                {"file": f, **_poc_info_map_get(info_map, f)} for f in d["removed_pocs"][:20]
            ]
            del d["new_pocs"], d["removed_pocs"]
            items.append(d)
        return {"items": items}

    def scan_detail(self, scan_id: str) -> Optional[dict]:
        # 详情缓存（闭合事件不可变；大事件 webprobe/利用链计算重，避免每次点开 4s）
        now = time.time()
        hit = self._detail_cache.get(scan_id)
        if hit is not None and now - hit[0] < self._DETAIL_CACHE_TTL:
            return hit[1]
        d = self._scan_detail_uncached(scan_id)
        if d is not None:
            self._detail_cache[scan_id] = (now, d)
            if len(self._detail_cache) > 200:
                self._detail_cache.clear()  # 防膨胀：超过 200 条整体清空
        return d

    def _scan_detail_uncached(self, scan_id: str) -> Optional[dict]:
        r = self.db.get_scan(scan_id)
        if r is None:
            return None
        info_map = _poc_info_map(self.db)
        d = dict(r)
        for key in ("session_ids", "poc_ids", "new_pocs", "removed_pocs", "ports_hit"):
            d[key] = json.loads(r[key] or "[]")
        d["new_detail"] = [
            {"file": f, **_poc_info_map_get(info_map, f)} for f in d["new_pocs"]
        ]
        d["removed_detail"] = [
            {"file": f, **_poc_info_map_get(info_map, f)} for f in d["removed_pocs"]
        ]
        # 列表接口瘦身：详情预览最多 20 条（完整清单在 new_pocs/removed_pocs 数组里）
        d["new_detail"] = d["new_detail"][:20]
        d["removed_detail"] = d["removed_detail"][:20]
        # 网站探测思路/利用链：优先读扫描闭合时预计算的结果（秒开）；
        # 旧数据没有则现场算（历史大事件首次访问较慢，仅一次）
        d["web_probe"] = json.loads(r["web_probe_json"]) if r["web_probe_json"] else None
        d["chains"] = json.loads(r["chains_json"]) if r["chains_json"] else None
        sess_rows = []
        if d["web_probe"] is None or not d["chains"]:
            # 兜底路径才需要事件会话（大事件分批查询）
            sid_set = set(d["session_ids"])
            batch = list(sid_set)
            for i in range(0, len(batch), 800):
                chunk = batch[i:i + 800]
                sess_rows += self.db.conn.execute(
                    "SELECT * FROM sessions WHERE session_id IN (%s)"
                    % ",".join("?" * len(chunk)), tuple(chunk)
                ).fetchall()
        if d["web_probe"] is None and sess_rows:
            from webscan import analyze_webscan
            d["web_probe"] = analyze_webscan([dict(r) for r in sess_rows[-3000:]])
        if not d["chains"] and sess_rows:
            from chain import analyze_chains
            d["chains"] = analyze_chains(list(sess_rows))
        # 事件 × 端口明细（攻击标记 + 探测样例）
        d["ports"] = []
        for p in self.db.get_scan_ports(scan_id):
            pd = dict(p)
            pd["attacks"] = json.loads(p["attacks"] or "[]")
            pd["sample"] = json.loads(p["sample"] or "{}")
            d["ports"].append(pd)
        # 非 HTTP POC（tcp/network/dns）标注原始字节级重建；类型从文件名前缀判断
        d["poc_ids_nonhttp"] = [
            {"file": f, **_poc_info_map_get(info_map, f)}
            for f in d["poc_ids"]
            if _poc_type_of(f) in ("tcp", "network", "dns")
        ]
        return d

    # ---------- lib snapshots ----------
    def lib(self) -> dict:
        rows = self.db.list_lib_snapshots()
        items = []
        prev = None
        for r in rows:
            d = dict(r)
            d["changed"] = prev is not None and prev["lib_hash"] != d["lib_hash"]
            items.append(d)
            prev = d
        return {"items": items}

    # ---------- 实时吸收监控 ----------
    def absorb(self) -> dict:
        """被扫描实时状态：活跃来源 + 最近吸收的 POC + 今日统计。"""
        db = self.db
        now_ms = int(time.time() * 1000)
        five_min = now_ms - 300_000
        # 活跃来源（5 分钟内）
        sources = db.conn.execute(
            """SELECT src_ip, COUNT(*) conns, MAX(ts_start) last_ts FROM sessions
               WHERE ts_start >= ? GROUP BY src_ip ORDER BY last_ts DESC LIMIT 5""",
            (five_min,),
        ).fetchall()
        # 最近吸收/更新的 POC（5 分钟内）
        recent = db.conn.execute(
            """SELECT template_path, template_yaml, last_seen FROM pocs
               WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT 15""",
            (five_min,),
        ).fetchall()
        # 今日新增统计
        day_ago = now_ms - 86400_000
        new_today = db.conn.execute(
            "SELECT COUNT(*) FROM pocs WHERE first_seen >= ?", (day_ago,)
        ).fetchone()[0]
        # 活跃扫描事件（未闭合的最新事件）
        active_scan = db.conn.execute(
            """SELECT src_ip, ts_start, ts_end, conn_count FROM scans
               ORDER BY ts_start DESC LIMIT 1"""
        ).fetchone()
        return {
            "active_sources": [dict(r) for r in sources],
            "recent_pocs": [
                {
                    "file": Path(r["template_path"] or "").name,
                    "exploit_type": _exploit_type(r["template_yaml"] or ""),
                    "severity": _parse_template_info(r["template_yaml"] or "")["severity"],
                    "last_seen": r["last_seen"],
                } for r in recent
            ],
            "new_today": new_today,
            "active_scan": dict(active_scan) if active_scan else None,
        }

    # ---------- 控制台执行 ----------
    def exec_scan(self, q: dict) -> dict:
        """浏览器触发 scanner.py。"""
        target = q.get("target", [""])[0].strip()
        if not target:
            return {"error": "缺少目标"}
        args = ["scripts/scanner.py", "-t", target]
        ports = q.get("ports", [""])[0].strip()
        if ports:
            args += ["-p", ports]
        exploit = q.get("exploit", [""])[0].strip()
        if exploit:
            args += ["-e", exploit]
        if q.get("nmap", ["0"])[0] == "1":
            args.append("--nmap")
        if q.get("backfill", ["0"])[0] == "1":
            args.append("--backfill")
        limit = q.get("limit", ["300"])[0]
        if limit:
            args += ["-n", limit]
        return _runner.start("scan", args, str(Path(__file__).resolve().parents[2]))

    def exec_attack(self, q: dict) -> dict:
        target = q.get("target", [""])[0].strip()
        if not target:
            return {"error": "缺少目标"}
        args = ["scripts/attack.py", "-t", target]
        port = q.get("from_port", [""])[0].strip()
        if port:
            args += ["-p", port]
        exploit = q.get("exploit", [""])[0].strip()
        if exploit:
            args += ["-e", exploit]
        vendor = q.get("vendor", [""])[0].strip()
        if vendor:
            args += ["-v", vendor]
        limit = q.get("limit", ["200"])[0]
        if limit:
            args += ["-n", limit]
        return _runner.start("attack", args, str(Path(__file__).resolve().parents[2]))

    def exec_clone(self, q: dict) -> dict:
        url = q.get("url", [""])[0].strip()
        if not url:
            return {"error": "缺少目标 URL"}
        args = ["scripts/clone.py", "-u", url]
        port = q.get("port", [""])[0].strip()
        if port:
            args += ["-p", port]
        name = q.get("name", [""])[0].strip()
        if name:
            args += ["-n", name]
        return _runner.start("clone", args, str(Path(__file__).resolve().parents[2]))

    def exec_status(self) -> dict:
        return _runner.status()

    def exec_clear(self):
        _runner.clear()
        return {"ok": True}

    def reports(self) -> dict:
        """扫描报告/结果文件列表。"""
        data_dir = Path(__file__).resolve().parents[2] / "data"
        files = []
        for pattern in ("scan_report_*.html", "scan_result.txt", "attack_result.txt"):
            for f in sorted(data_dir.glob(pattern), key=lambda x: x.stat().st_mtime, reverse=True)[:15]:
                files.append({"name": f.name, "size": f.stat().st_size,
                              "mtime": f.stat().st_mtime})
        return {"items": files}

    def report_content(self, name: str) -> Optional[str]:
        data_dir = Path(__file__).resolve().parents[2] / "data"
        f = data_dir / name
        if not f.is_file() or f.suffix not in (".html", ".txt"):
            return None
        return f.read_text(encoding="utf-8", errors="replace")

    # 服务检测/重启脚本（用 -File 方式避免内联引号问题）
    @staticmethod
    def _run_ps(script_name: str, timeout: int = 60) -> str:
        import subprocess as sp
        script = Path(__file__).resolve().parents[2] / "scripts" / script_name
        r = sp.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
                   capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")

    def service_status(self) -> dict:
        """代理/管道/dashboard 状态。"""
        out = {"eatal-proxy": None, "pipeline": None, "dashboard": None}
        key_map = {"proxy": "eatal-proxy", "pipeline": "pipeline", "dashboard": "dashboard"}
        try:
            text = self._run_ps("service-check.ps1", timeout=15)
            for part in text.replace("\n", ";").split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    if k in key_map:
                        out[key_map[k]] = v.strip().lower() == "true"
        except Exception:  # noqa: BLE001
            pass
        return out

    def service_restart(self) -> dict:
        """一键重启蜜罐代理（重新加载 banners/config 配置）。

        注意：重启命令的权限 = 启动代理时的权限；若代理原以管理员启动，
        此处可能因权限不足失败（会返回错误信息）。
        """
        try:
            text = self._run_ps("service-restart.ps1", timeout=60)
            import re as _re
            m = _re.search(r"proxy_count=(\d+)", text)
            count = int(m.group(1)) if m else 0
            if count > 0:
                return {"ok": True, "message": f"蜜罐已重启（进程数 {count}）"}
            return {"error": f"重启失败: {text.strip()[:200]}"}
        except Exception as exc:  # noqa: BLE001
            return {"error": f"重启异常: {exc}"}

    # ---------- 端口矩阵 ----------
    def ports(self, q: dict = None) -> dict:
        """端口被探测情况（端口 × 协议 × banner × 会话数 × 最近时间），支持搜索/分页。"""
        q = q or {}
        search = q.get("search", [None])[0] or None
        limit = int(q.get("limit", ["100"])[0] or 100)
        offset = int(q.get("offset", ["0"])[0] or 0)
        where, args = "", []
        if search:
            like = f"%{search}%"
            where = ("WHERE CAST(dst_port AS TEXT) LIKE ? OR proto LIKE ? OR banner LIKE ?")
            args = [like, like, like]
        rows = self.db.conn.execute(
            f"""SELECT dst_port, MAX(proto) AS proto, MAX(banner) AS banner, COUNT(*) AS n,
                       MAX(ts_start) AS last_ts
                FROM sessions {where} GROUP BY dst_port ORDER BY dst_port LIMIT ? OFFSET ?""",
            args + [int(limit), int(offset)],
        ).fetchall()
        total = self.db.conn.execute(
            f"SELECT COUNT(*) FROM (SELECT 1 FROM sessions {where} GROUP BY dst_port)", args
        ).fetchone()[0]
        return {"total": total, "items": [dict(r) for r in rows]}

    def port_detail(self, port: int, limit: int = 100) -> Optional[dict]:
        """单端口探测明细：会话列表 + parsed 摘要 + 关联 POC 模板。"""
        sess_rows = self.db.conn.execute(
            "SELECT * FROM sessions WHERE dst_port = ? ORDER BY ts_start DESC LIMIT ?",
            (port, int(limit)),
        ).fetchall()
        sess = []
        for r in sess_rows:
            d = dict(r)
            d["parsed"] = _safe_parsed(r["parsed_json"])
            d["client_len"] = len(r["client_bytes"] or b"")
            d["server_len"] = len(r["server_bytes"] or b"")
            del d["client_bytes"], d["server_bytes"]
            sess.append(d)
        # 关联 POC（tcp/network/dns 模板由该端口的会话触发）
        poc_files = []
        sess_ids = {s["session_id"] for s in sess}
        for r in self.db.get_pocs():
            sids = json.loads(r["source_session_ids"] or "[]")
            if sids and sess_ids & set(sids):
                fname = Path(r["template_path"] or "").name
                if fname:
                    info = _parse_template_info(r["template_yaml"] or "")
                    poc_files.append({
                        "file": fname, "type": r["type"],
                        "name": info["name"], "severity": info["severity"],
                    })
        banner = self.db.conn.execute(
            "SELECT proto, banner FROM sessions WHERE dst_port = ? ORDER BY ts_start DESC LIMIT 1",
            (port,),
        ).fetchone()
        return {
            "dst_port": port,
            "proto": banner["proto"] if banner else "",
            "banner": banner["banner"] if banner else "",
            "session_count": len(sess),
            "sessions": sess,
            "pocs": poc_files,
        }


def _safe_parsed(parsed_json: str) -> dict:
    try:
        return json.loads(parsed_json or "{}")
    except json.JSONDecodeError:
        return {}


def _poc_type_of(fname: str) -> str:
    """模板类型：文件名前缀 poc-{type}-*。"""
    parts = fname.split("-")
    if len(parts) >= 2 and parts[0] == "poc" and parts[1] in ("http", "tcp", "network", "dns"):
        return parts[1]
    return "http"


def _poc_info_map_get(info_map: dict, fname: str) -> dict:
    info = info_map.get(fname, {})
    return {
        "name": info.get("name", fname),
        "severity": info.get("severity", "unknown"),
        "tags": info.get("tags", ""),
    }


class Handler(BaseHTTPRequestHandler):
    api: Api = None  # 由 main() 注入

    def log_message(self, fmt, *args):  # 静默访问日志（管道日志足够）
        pass

    def _send_json(self, obj: dict, status: int = 200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text: str, ctype: str, status: int = 200):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, name: str):
        path = STATIC_DIR / name
        if not path.is_file():
            self.send_error(404)
            return
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
        }.get(path.suffix, "application/octet-stream")
        self._send_text(path.read_text(encoding="utf-8"), ctype)

    def _route(self, path: str, q: dict):
        api = self.api
        if path == "/" or path == "/index.html":
            self._send_static("index.html")
            return
        if path == "/app.js":
            self._send_static("app.js")
            return
        if path == "/style.css":
            self._send_static("style.css")
            return
        if path == "/api/overview":
            self._send_json(api.overview())
            return
        if path == "/api/sessions":
            self._send_json(api.sessions(q))
            return
        if path.startswith("/api/sessions/"):
            d = api.session_detail(unquote(path[len("/api/sessions/"):]))
            self._send_json(d, 200 if d else 404)
            return
        if path == "/api/flows":
            self._send_json(api.flows(q))
            return
        if path == "/api/pocs":
            self._send_json(api.pocs(q))
            return
        if path.startswith("/api/pocs/"):
            yaml_text = api.poc_yaml(unquote(path[len("/api/pocs/"):]))
            self._send_json({"yaml": yaml_text or ""}, 200 if yaml_text is not None else 404)
            return
        if path == "/api/scans":
            self._send_json(api.scans())
            return
        if path.startswith("/api/scans/"):
            d = api.scan_detail(unquote(path[len("/api/scans/"):]))
            self._send_json(d, 200 if d else 404)
            return
        if path == "/api/lib":
            self._send_json(api.lib())
            return
        if path == "/api/ports":
            self._send_json(api.ports(q))
            return
        if path.startswith("/api/ports/"):
            try:
                port = int(unquote(path[len("/api/ports/"):]))
            except ValueError:
                self.send_error(404)
                return
            d = api.port_detail(port)
            self._send_json(d, 200 if d else 404)
            return
        if path == "/api/exec/scan":
            self._send_json(api.exec_scan(q))
            return
        if path == "/api/exec/attack":
            self._send_json(api.exec_attack(q))
            return
        if path == "/api/exec/clone":
            self._send_json(api.exec_clone(q))
            return
        if path == "/api/exec/status":
            self._send_json(api.exec_status())
            return
        if path == "/api/exec/clear":
            self._send_json(api.exec_clear())
            return
        if path == "/api/reports":
            self._send_json(api.reports())
            return
        if path.startswith("/api/reports/"):
            content = api.report_content(unquote(path[len("/api/reports/"):]))
            if content is None:
                self.send_error(404)
                return
            name = path.rsplit("/", 1)[-1]
            ctype = "text/html; charset=utf-8" if name.endswith(".html") else "text/plain; charset=utf-8"
            self._send_text(content, ctype)
            return
        if path == "/api/service":
            self._send_json(api.service_status())
            return
        if path == "/api/service/restart":
            self._send_json(api.service_restart())
            return
        if path == "/api/absorb":
            self._send_json(api.absorb())
            return
        self.send_error(404)

    def do_GET(self):
        try:
            path, _, query = self.path.partition("?")
            q = parse_qs(query)
            self._route(path, q)
        except Exception as exc:  # noqa: BLE001
            self._send_json({"error": str(exc)}, 500)

    do_POST = do_GET


def serve(*, host: str = "0.0.0.0", port: int = 9090, db: Optional[DB] = None) -> None:
    Handler.api = Api(db)
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"[eatal] dashboard: http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="EatAll 展示界面")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9090)
    args = parser.parse_args()
    serve(host=args.host, port=args.port)
