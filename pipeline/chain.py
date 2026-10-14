"""行为层：利用链识别（六期-3）。

单请求分类看"内容"，这里看"序列"——同一来源对同一目标的多步攻击模式：
  1. 上传-执行链：POST 上传 webshell → 后续访问/执行（webshell 确认）
  2. 认证爆破链：同一认证端点 ≥5 次不同凭据
  3. 探测→利用链：先纯探测（clean）→ 后攻击 payload（先探后打）
  4. 命令执行链：RCE payload 后跟命令参数变体（利用确认后的深入）

输出：[{type, path, steps, method_seq, detail, first_ts, last_ts}]
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from urllib.parse import unquote

from classify import classify

WEBSHELL_MARKERS = ["<?php", "<%", "<%@", "echo ", "system(", "shell_exec",
                    "cmd.exe", "/bin/sh", "powershell", "webshell", "jsp", "aspx"]
UPLOAD_EXT = (".jsp", ".jspx", ".php", ".asp", ".aspx", ".war", ".sh", ".py", ".phtml")
CRED_PARAMS = ("username", "user", "login", "account", "email", "passwd",
               "password", "pwd", "j_username", "os_username")
CMD_PARAMS = ("cmd", "exec", "command", "action", "do", "run", "execute")


def _parsed(row) -> dict:
    try:
        raw = row.get("parsed_json") if isinstance(row, dict) else row["parsed_json"]
        out = json.loads(raw or "{}")
    except (json.JSONDecodeError, AttributeError, TypeError, KeyError):
        return {}
    return out if isinstance(out, dict) else {}


def _base_path(path: str) -> str:
    if "?" in path:
        path = path.split("?", 1)[0]
    return path


def _body_text(parsed: dict) -> str:
    import base64
    try:
        return base64.b64decode(parsed.get("body_b64") or "").decode("utf-8", "replace")
    except (ValueError, TypeError):
        return ""


def analyze_chains(sessions: list) -> list:
    """识别事件会话中的利用链。sessions: HTTP 会话行（含 parsed_json、ts_start）。

    注意：上传-执行链的 follow-up（访问上传的文件）跨路径——必须先全局扫描上传，
    再按路径分组做爆破/探测-利用链。
    """
    items = []
    for r in sessions:
        if not isinstance(r, dict):
            r = dict(r)  # sqlite3.Row → dict（统一 .get 语义）
        p = _parsed(r)
        if p.get("path"):
            items.append((r, p))
    items.sort(key=lambda x: x[0].get("ts_start") or 0)
    if len(items) < 2:
        return []

    chains = []
    # 1. 上传-执行链（全局，跨路径）
    chain = _upload_chain_global(items)
    upload_paths = set()
    if chain:
        chains.append(chain)
        upload_paths.add(chain["path"])

    # 2/3. 按路径分组：爆破链 / 探测→利用链（上传路径已被覆盖，跳过避免冗余）
    by_path: dict[str, list] = defaultdict(list)
    for r, p in items:
        by_path[_base_path(p.get("path", ""))].append((r, p))
    for path, group in by_path.items():
        if len(group) < 2 or path in upload_paths:
            continue
        chain = _brute_chain(path, group)
        if chain:
            chains.append(chain)
            continue
        chain = _probe_exploit_chain(path, group)
        if chain:
            chains.append(chain)

    # 4. 应用级攻击簇：同一目录前缀下 ≥3 个不同路径且含攻击 payload
    #    （WebLogic 的 console/wls-wsat/ws_utc 是分散路径，单路径次数少但同属一个应用）
    chain = _cluster_chain(items)
    if chain:
        chains.append(chain)
    return chains


def _cluster_chain(items: list) -> dict | None:
    clusters: dict[str, list] = defaultdict(list)
    for r, p in items:
        path = str(p.get("path", ""))
        parts = path.strip("/").split("/")
        key = parts[0] if parts and parts[0] else None  # "/console/" 也归 console
        if key and key not in ("favicon.ico", "robots.txt", ".DS_Store"):
            clusters[key].append((r, p))
    best = None
    for key, group in clusters.items():
        paths = {_base_path(x[1].get("path", "")) for x in group}
        kinds = set()
        for _, p in group:
            text = unquote(f"{p.get('method', '')} {p.get('path', '')}")
            cls = classify(text)["kind"]
            if cls != "probe":
                kinds.add(cls)
        if len(paths) >= 3 and kinds and len(group) >= 3:
            score = len(paths) * 10 + len(group)
            if best is None or score > best[0]:
                best = (score, {
                    "type": "app_cluster_attack",
                    "path": f"/{key}/",
                    "steps": len(group),
                    "method_seq": "→".join(x[1].get("method", "?") for x in group),
                    "detail": f"应用级攻击簇：/{key}/ 下 {len(paths)} 个路径 ×{len(group)} 请求（{sorted(kinds)[0]}）",
                    "first_ts": group[0][0].get("ts_start"),
                    "last_ts": group[-1][0].get("ts_start"),
                })
    return best[1] if best else None


def _upload_chain_global(items: list) -> dict | None:
    """跨路径全局扫描上传-执行链：POST 上传 webshell → 后续访问/执行。"""
    upload_idx = None
    upload_path = ""
    for i, (r, p) in enumerate(items):
        if p.get("method", "").upper() == "POST":
            body = _body_text(p)
            all_text = unquote(f"{p.get('path', '')} {body}").lower()
            is_upload = (
                "multipart/form-data" in str(p.get("headers", {}).get("Content-Type", "")).lower()
                or any(m in all_text for m in ("<?php", "<%", "filename=", "shell", "webshell"))
                or any(p.get("path", "").lower().endswith(e) for e in UPLOAD_EXT)
            )
            if is_upload:
                upload_idx = i
                upload_path = _base_path(p.get("path", ""))
                break
    if upload_idx is None:
        return None
    # 后续是否有访问/执行（webshell 确认）——跨路径
    for r, p in items[upload_idx + 1:]:
        method = p.get("method", "").upper()
        path_low = unquote(str(p.get("path", ""))).lower()
        if method in ("GET", "POST") and (
            any(c in path_low for c in ("cmd=", "exec=", "action=", "do="))
            or upload_path.split("/")[-1] in path_low  # 访问上传的文件
        ):
            return {
                "type": "upload_exec",
                "path": upload_path,
                "steps": len(items),
                "method_seq": "→".join(x[1].get("method", "?") for x in items),
                "detail": f"上传后执行（POST {upload_path} → {method} {p.get('path','')[:50]}）",
                "first_ts": items[0][0].get("ts_start"),
                "last_ts": items[-1][0].get("ts_start"),
            }
    return {
        "type": "upload_only",
        "path": upload_path,
        "steps": len(items),
        "method_seq": "→".join(x[1].get("method", "?") for x in items),
        "detail": f"文件上传尝试（POST {upload_path}，含 webshell 特征）",
        "first_ts": items[0][0].get("ts_start"),
        "last_ts": items[-1][0].get("ts_start"),
    }


def _brute_chain(path: str, items: list) -> dict | None:
    """认证爆破：同一端点 ≥5 次不同凭据。"""
    cred_seen: dict[str, set] = defaultdict(set)
    for r, p in items:
        text = unquote(f"{p.get('path', '')} {_body_text(p)}")
        for name in CRED_PARAMS:
            m = re.search(rf"(?:^|[?&]){name}=([^&\s]+)", text, re.I)
            if m:
                cred_seen[name].add(m.group(1))
    total = sum(len(v) for v in cred_seen.values())
    if total >= 5 and items[0][1].get("method", "").upper() in ("POST", "GET"):
        params = "|".join(f"{k}×{len(v)}" for k, v in cred_seen.items() if v)
        return {
            "type": "brute",
            "path": path,
            "steps": len(items),
            "method_seq": "→".join(x[1].get("method", "?") for x in items),
            "detail": f"认证爆破：{total} 组凭据变体（{params}）",
            "first_ts": items[0][0].get("ts_start"),
            "last_ts": items[-1][0].get("ts_start"),
        }
    return None


def _probe_exploit_chain(path: str, items: list) -> dict | None:
    """先探后打 / 重复确认：同一路径先纯探测后攻击，或大量重复攻击（响应驱动深入）。"""
    seen_clean = False
    exploit_kinds = set()
    for r, p in items:
        text = unquote(f"{p.get('method', '')} {p.get('path', '')} {_body_text(p)}")
        cls = classify(text)["kind"]
        if cls == "probe":
            seen_clean = True
        else:
            exploit_kinds.add(cls)
        if seen_clean and exploit_kinds:
            seq = "→".join(x[1].get("method", "?") for x in items)
            return {
                "type": "probe_exploit",
                "path": path,
                "steps": len(items),
                "method_seq": seq,
                "detail": f"先探测后攻击：{path}（{len(items)} 步，探测→{sorted(exploit_kinds)[0]}）",
                "first_ts": items[0][0].get("ts_start"),
                "last_ts": items[-1][0].get("ts_start"),
            }
    # 重复确认：同路径 ≥10 次且含攻击 payload（响应驱动深入验证）
    if len(items) >= 10 and exploit_kinds:
        return {
            "type": "repeated_attack",
            "path": path,
            "steps": len(items),
            "method_seq": "→".join(x[1].get("method", "?") for x in items),
            "detail": f"重复确认攻击：{path} ×{len(items)}（{sorted(exploit_kinds)[0]}）",
            "first_ts": items[0][0].get("ts_start"),
            "last_ts": items[-1][0].get("ts_start"),
        }
    return None
