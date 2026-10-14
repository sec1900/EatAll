"""分层攻击分类引擎（六期-2）。

分层漏斗：
  第1层 特征匹配   已知特征词表 → 快速命中已知攻击（扫描器 POC 库 = 已知特征集合）
  第2层 结构检测   编码金字塔 / 表达式语法 / SQL 结构 / 命令结构 → 不依赖具体关键词，
                  覆盖混淆与变体型 payload
  第5层 未知兜底   有可疑特征但无法归类的 → "unknown"（绝不静默归 probe）
                  probe = 无明显攻击特征（纯路径/版本探测）

输出：{kind, confidence, matched}，kind ∈ rce/sql_injection/traversal/xss/brute/
      ssrf/expression/unknown/probe
"""
from __future__ import annotations

import math
import re

# ---- 第 1 层：特征词（对齐常见扫描器 payload 特征）----
FEATURE_KINDS: list[tuple[str, list[str]]] = [
    ("rce", [
        "wls-wsat", "ws_utc", "jmxinvoker", "ysoserial", "ognl", "${jndi",
        "jndi:", "java.lang.runtime", "runtime.getruntime", "cmd=", ";id",
        "|whoami", "bash -c", "exec(", "system(", "/bin/sh", "cmd.exe",
        "whoami", "net user", "powershell", "eval(", "assert(", "phpinfo()",
    ]),
    ("sql_injection", [
        "union select", "union all select", "sleep(", "and 1=1", "or 1=1",
        "information_schema", "benchmark(", "extractvalue(", "updatexml(",
        "waitfor delay", "concat(", "group_concat", "load_file(", "into outfile",
        "into dumpfile", "select @@version", "database()", "user()", "0x",
        "sys.schema", "pg_sleep", "dbms_pipe",
    ]),
    ("traversal", [
        "windows/win.ini", "web-inf", "web.xml", "boot.ini",
        "c:\\windows", "..\\", "%2e%2e", "..%5c", "%252e%252e",
    ]),
    ("ssrf", [
        "file://", "gopher://", "dict://", "169.254.169.254", "127.0.0.1:80",
        "localhost:8080", "burpcollaborator", "oast.", "interact.sh",
    ]),
    ("xss", [
        "<script", "</script>", "onerror", "onload=", "alert(", "javascript:",
        "svg/onload", "img src=x", "document.cookie", "prompt(", "confirm(",
    ]),
    ("brute", [
        "passwd=", "password=", "pwd=", "user=", "authorization: basic",
        "j_username", "j_password", "os_username", "os_password",
    ]),
    ("deserialization", [
        "com.sun.rowset", "jdbcrowsetimpl", "com.sun.org.apache",
        "org.apache.commons.collections", "weblogic.jndi", "rmi://", "ldap://",
    ]),
]

# ---- 第 2 层：结构检测（正则，不依赖具体关键词）----
STRUCT_PATTERNS: list[tuple[str, list[re.Pattern]]] = [
    # 表达式语法：OGNL/SpEL/模板/命令替换——不管表达式里是什么
    ("expression", [
        re.compile(r"%\{[^}]{3,}\}"),      # OGNL
        re.compile(r"\$\{[^}]{3,}\}"),     # SpEL/JNDI/模板
        re.compile(r"#\{[^}]{3,}\}"),      # 模板
        re.compile(r"\{\{[^}]{3,}\}\}"),   # Jinja2/SSTI
        re.compile(r"\$\([^)]{3,}\)"),     # 命令替换
    ]),
    # SQL 结构：引号闭合 + 关键字模式（不要求具体函数名）
    ("sql_injection", [
        re.compile(r"'\s*(or|and|union|select|order|having|group)\s", re.I),
        re.compile(r"'\s*;\s*(select|union|insert|update|delete|drop)\b", re.I),
        re.compile(r'"\s*(or|and|union|select)\s', re.I),
        re.compile(r"'\s*=\s*'", re.I),
        re.compile(r"'\s*--", re.I),
        re.compile(r"'\s*#", re.I),
        re.compile(r"\d+\s*;\s*select\b", re.I),
    ]),
    # 命令结构：分隔符 + 命令词
    ("rce", [
        re.compile(r";\s*(id|whoami|cat|ls|ping|nc|bash|curl|wget|echo|env|uname)\b", re.I),
        re.compile(r"\|\s*(id|whoami|cat|sh|bash|nc|curl|wget)\b", re.I),
        re.compile(r"&&\s*(id|whoami|cat|bash|nc)\b", re.I),
        re.compile(r"%0a|%0d%0a", re.I),
    ]),
    # 编码金字塔：多层编码 / Unicode 混淆 / HTML 实体
    ("obfuscation", [
        re.compile(r"%252[56]", re.I),        # 双层 URL 编码
        re.compile(r"%25[0-9a-f]{2}", re.I),
        re.compile(r"%u[0-9a-f]{4}", re.I),   # Unicode 编码
        re.compile(r"&#x?[0-9a-f]{2,6};", re.I),  # HTML 实体
        re.compile(r"\\x[0-9a-f]{2}", re.I),  # hex 转义
    ]),
    # 路径遍历结构（不依赖具体文件名）
    ("traversal", [
        re.compile(r"(\.\./){2,}"),
        re.compile(r"(\.\.%2f){2,}", re.I),
        re.compile(r"(\.\.\\\\){2,}"),
    ]),
]


def shannon_entropy(s: str) -> float:
    """Shannon 熵（高熵 = 混淆/加密 payload 特征）。"""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def classify(text: str) -> dict:
    """分层分类。text: 请求全文（path+body+headers 拼接，URL 解码前+后各一次）。

    返回 {kind, confidence, matched}：
      kind: rce/sql_injection/traversal/xss/brute/ssrf/deserialization/
            expression/obfuscation/unknown/probe
      unknown = 有可疑特征（高熵/混淆）但无法归类——绝不静默归 probe
      probe = 无明显攻击特征
    """
    low = text.lower()

    # ---- 第 1 层：特征词 ----
    for kind, pats in FEATURE_KINDS:
        if any(p in low for p in pats):
            return {"kind": kind, "confidence": 0.9, "matched": f"feature:{kind}"}

    # ---- 第 2 层：结构检测 ----
    for kind, patterns in STRUCT_PATTERNS:
        for p in patterns:
            if p.search(text):
                return {"kind": kind, "confidence": 0.7, "matched": f"structure:{kind}"}

    # ---- 第 5 层：未知兜底 ----
    # 纯 hex/base64 长串 = 随机 token/ID，不标 unknown（正常流量特征）
    if re.fullmatch(r"[0-9a-fA-F]{24,}", text):
        return {"kind": "probe", "confidence": 0.8, "matched": "hex-token"}
    if re.fullmatch(r"[A-Za-z0-9+/]{40,}={0,2}", text):
        return {"kind": "probe", "confidence": 0.8, "matched": "b64-token"}
    # 高熵 payload 或短小可疑串（如大量连续 %XX）
    if len(text) >= 24:
        h = shannon_entropy(text)
        if h > 4.5:
            return {"kind": "unknown", "confidence": 0.5, "matched": "entropy:high"}
    if re.search(r"(%[0-9a-f]{2}){6,}", text, re.I):
        return {"kind": "unknown", "confidence": 0.5, "matched": "encoding:dense"}

    return {"kind": "probe", "confidence": 0.9, "matched": "clean"}


def is_exploit(kind: str) -> bool:
    """是否利用型（非纯探测）。unknown 视为潜在利用。"""
    return kind not in ("probe",)
