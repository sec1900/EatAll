"""HTTP 模板重建。

- method/path 原样；query 高熵值 → {{randstr}}
- headers 剔除 User-Agent/Host/Connection/Content-Length；动态值 → {{randstr}}
- body 动态值 → {{randstr}}
- matcher 取 ≥2 独立会话共现稳定串（word）；单会话退化为该会话自身稳定串
- 漏洞特征词（Ognl/${/thinkphp/eval(/cmd.exe//bin/sh/sleep(/union select）
  → severity/tags 提升
"""
from __future__ import annotations

import base64
import re
from typing import Optional

from decoders.http import server_status
from .emit import make_poc_id, sanitize_segment
from .normalize import (
    is_dynamic_token,
    normalized_req_hash,
    printable_words,
    stable_bytes_over_sessions,
)

# 模板中剔除的易变请求头（与去重哈希剔除集一致）
EXCLUDED_HEADERS = {"user-agent", "host", "connection", "content-length"}

# nuclei 可接受的 HTTP method 白名单（标准 + WebDAV + 常见扩展）。
# 蜜罐端口上常混入二进制协议（SMB/TLS/Redis……），Go 容错解析会把二进制
# 首行拆出"伪 method"，这类会话不应产出 http 模板（nuclei 校验直接拒绝），
# 由编排层改走 tcp 模板重建。
KNOWN_METHODS = {
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT",
    "TRACE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK",
    "UNLOCK", "M-SEARCH", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE", "REPORT",
    "ACL", "BASELINE", "MERGE", "MKACTIVITY", "CHECKOUT", "CHECKIN", "LABEL",
    "ORDERPATCH", "SEARCH", "VERSION-CONTROL", "PURGE", "REBIND", "UNBIND",
    "LINK", "UNLINK", "PRI",
}
_METHOD_RE = re.compile(r"^[A-Za-z]{2,16}$")


def is_valid_http_method(method: str) -> bool:
    """method 是否可作为 nuclei http 模板动词。"""
    return bool(_METHOD_RE.match(method or "")) and method.upper() in KNOWN_METHODS

# 漏洞特征词 → severity/tags 提升
# 注："shell" 子串过松（Shellshock/路径名都会误中），用精确的 "shellshock"
CRITICAL_WORDS = (
    "ognl", "jndi", "log4j", "union select", "sleep(", "eval(", "cmd.exe",
    "/bin/sh", "bash -i", "shellshock",
)
HIGH_WORDS = (
    "thinkphp", "struts", "weblogic", "wls-wsat", "actuator", "solr",
    "druid", "phpinfo", "phpmyadmin", "wp-login", ".git/config",
)

# vendor 判定（id 命名用；优先级即顺序）
_VENDOR_RULES = [
    ("struts2", re.compile(r"struts2-showcase|struts|ognl|\.action", re.I)),
    ("thinkphp", re.compile(r"thinkphp", re.I)),
    ("weblogic", re.compile(r"weblogic|wls-wsat", re.I)),
    ("log4j", re.compile(r"log4j|jndi", re.I)),
    ("actuator", re.compile(r"actuator", re.I)),
    ("solr", re.compile(r"solr", re.I)),
    ("druid", re.compile(r"druid", re.I)),
    ("phpinfo", re.compile(r"phpinfo", re.I)),
    ("git", re.compile(r"\.git/", re.I)),
    ("wp", re.compile(r"wp-", re.I)),
    ("phpmyadmin", re.compile(r"phpmyadmin|pma_", re.I)),
    ("php", re.compile(r"\.php\b|\.php\?", re.I)),
]

# 特征名（id 用）非法字符清洗
_FEATURE_CLEAN_RE = re.compile(r"[^a-z0-9]+")


def detect_vulns(text: str) -> list[str]:
    """在 path/query/body/headers 文本中找漏洞特征词（小写匹配）。"""
    low = text.lower()
    hits = []
    for w in CRITICAL_WORDS + HIGH_WORDS:
        if w in low:
            hits.append(w)
    return hits


def severity_for(hits: list[str]) -> str:
    if any(w in CRITICAL_WORDS for w in hits):
        return "critical"
    if any(w in HIGH_WORDS for w in hits):
        return "high"
    return "low"


def vendor_for(text: str) -> str:
    for vendor, rx in _VENDOR_RULES:
        if rx.search(text):
            return vendor
    return "generic"


def feature_for(hits: list[str], path: str) -> str:
    """id 特征名：优先命中漏洞词，其次路径末段。"""
    if hits:
        # 取置信度最高的命中（critical 词优先）
        for w in CRITICAL_WORDS + HIGH_WORDS:
            if w in hits:
                return sanitize_segment(w)
    stem = path.split("?")[0].rstrip("/").split("/")[-1]
    if stem and stem != "/":
        return sanitize_segment(stem)
    return "probe"


def _parameterize_query(query: str) -> str:
    """query 高熵参数值 → {{randstr}}。"""
    if not query:
        return query
    parts = []
    for pair in query.split("&"):
        if not pair:
            continue
        if "=" in pair:
            k, v = pair.split("=", 1)
            if is_dynamic_token(v):
                v = "{{randstr}}"
        else:
            k, v = pair, ""
        parts.append(f"{k}={v}")
    return "&".join(parts)


def _template_value(v: str) -> str:
    """普通值（header/body）：动态 token → {{randstr}}。"""
    return "{{randstr}}" if is_dynamic_token(v) else v


def _body_tpl(body: bytes) -> Optional[str]:
    """body 模板：二进制体跳过；文本中动态值 → {{randstr}}。"""
    if not body:
        return None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None  # 二进制 body 不做模板化（信息在 matcher）
    return _repl(text)


_DYN_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    r"|(?<![0-9a-fA-F])[0-9a-fA-F]{24,}(?![0-9a-fA-F])"
    r"|(?<![0-9])1[0-9]{12}(?![0-9])"
    r"|(?:phpsessid|jsessionid|csrf(?:token)?|_sid|sessionid|token)=[0-9a-fA-F]{8,}",
    re.I,
)


def _repl(text: str) -> str:
    """把文本中的动态 token 替换为 {{randstr}}（模板形式，非 {dyn}）。"""
    return _DYN_RE.sub("{{randstr}}", text)


def _response_body(server: bytes) -> bytes:
    """响应 body（头部区之后）。"""
    idx = server.find(b"\r\n\r\n")
    if idx == -1:
        return b""
    return server[idx + 4 :]


def _matcher(cluster: list, server_bytes_list: list[bytes]) -> tuple[Optional[dict], str]:
    """matcher：≥2 会话 → LCS 稳定串 word；单会话 → 自身稳定串；无则状态码。

    关键：word matcher 默认 part=body，候选词必须实际出现在响应 body 中，
    否则模板永远匹配不上（虚假 matcher）。
    """
    if len(server_bytes_list) >= 2:
        stable = stable_bytes_over_sessions(server_bytes_list)
        words = printable_words(stable)
        source = "multi-session-lcs"
    else:
        words = printable_words(server_bytes_list[0])
        source = "single-session"
    body = _response_body(server_bytes_list[0])
    if words:
        words = [w for w in words if w.encode("ascii", "replace") in body]
        if words:
            return {"type": "word", "part": "body", "words": words[:3]}, source
    status = server_status(server_bytes_list[0])
    if status is not None:
        return {"type": "status", "status": [status]}, "status-code"
    return None, "none"


def build_http_template(
    cluster: list,
    hash8: str,
) -> Optional[dict]:
    """由同一去重键的会话簇构建 nuclei http 模板；数据不足返回 None。"""
    first = cluster[0]
    parsed = first["parsed"] or {}

    method = str(parsed.get("method") or "GET").upper()
    if not is_valid_http_method(method):
        return None  # 伪 method（二进制协议混入 http 端口）→ 编排层转 tcp 重建
    path = str(parsed.get("path") or "/")
    headers = parsed.get("headers") or {}
    body = base64.b64decode(parsed.get("body_b64") or "")

    # ---- 请求模板化 ----
    if "?" in path:
        path_part, query = path.split("?", 1)
        path_tpl = path_part + "?" + _parameterize_query(query) if query else path_part
    else:
        path_tpl = path

    headers_tpl: dict[str, str] = {}
    for k, v in headers.items():
        if k.strip().lower() in EXCLUDED_HEADERS:
            continue
        headers_tpl[k] = _template_value(str(v))

    body_tpl = _body_tpl(body)

    # ---- matcher ----
    server_bytes_list = [r["server_bytes"] for r in cluster]
    matcher, matcher_source = _matcher(cluster, server_bytes_list)

    # ---- 特征 / severity / tags ----
    probe_text = f"{path} {path_tpl} {body_tpl or ''} {json_dumps(headers_tpl)}"
    hits = detect_vulns(probe_text)
    severity = severity_for(hits)
    vendor = vendor_for(probe_text)

    # ---- 可执行化：相对路径拼 {{BaseURL}}（nuclei 无法直接解析带 query 的相对路径）----
    path_exec = path_tpl
    if path_exec and path_exec != "*" and not path_exec.startswith("{{") and not path_exec.lower().startswith("http://") and not path_exec.lower().startswith("https://"):
        path_exec = "{{BaseURL}}" + path_exec
    feature = feature_for(hits, path)
    ips = sorted({r["src_ip"] for r in cluster if r["src_ip"]})

    poc_id = make_poc_id("http", vendor, feature, hash8)
    feature = sanitize_segment(feature) or "probe"  # info 描述用（审计）
    tags = ",".join(
        filter(
            None,
            ["eatall", "honeypot", vendor, severity] + [h.replace(" ", "-")[:16] for h in hits[:3]],
        )
    )

    http_block: dict = {"method": method, "path": [path_exec]}
    if headers_tpl:
        http_block["headers"] = headers_tpl
    if body_tpl:
        http_block["body"] = body_tpl
    if matcher:
        http_block["matchers"] = [matcher]

    template = {
        "id": poc_id,
        "info": {
            "name": f"EatAll absorbed {vendor} probe: {method} {path_tpl}",
            "author": "eatall-pipeline",
            "severity": severity,
            "description": (
                f"Captured by EatAll honeypot from {','.join(ips[:5])} "
                f"(sessions={len(cluster)}, matcher={matcher_source}). "
                f"Features: {', '.join(hits) if hits else 'path-probe'}."
            ),
            "tags": tags,
        },
        "http": [http_block],
    }
    return template


def json_dumps(obj) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False)
