"""POC 重建地基：动态值识别 + 稳定字节求取 + 去重哈希。

- 高熵串（Shannon>4.5 且 ≥8B）、UUID、时间戳、24+ hex → {dyn} 占位符
- 多会话 LCS 求稳定字节（≥16B 才作为模板输入）
- 去重键：归一化请求的 sha256
"""
from __future__ import annotations

import hashlib
import re

from decoders.shannon import is_high_entropy_str

# 稳定字节最低长度（多会话 LCS 结果不足则丢弃）
MIN_STABLE_BYTES = 16
# LCS 输入截断上限（性能护栏，256KB）
LCS_INPUT_CAP = 256 * 1024

# ---------- 动态值识别 ----------

_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
# 24+ 连续 hex（sha1/md5 摘要、长随机 token）
_HEX24_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{24,}(?![0-9a-fA-F])")
# 13 位 unix 毫秒时间戳（2001-09-09 ~ 2033-05-18 区间），10 位秒级
_MS_TS_RE = re.compile(r"(?<![0-9])1[0-9]{12}(?![0-9])")
_S_TS_RE = re.compile(r"(?<![0-9])1[0-9]{9}(?![0-9])")
# ISO 时间串
_ISO_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?")
# 常见会话 cookie：PHPSESSID/JSESSIONID/ASP.NET_SessionId/csrf 等 token 值
_SESSION_TOKEN_RE = re.compile(
    r"(?i)(?:phpsessid|jsessionid|asp\.net_sessionid|csrf(?:token)?|xsrf|_sid|sessionid|token)=([0-9a-fA-F]{8,})"
)

_DYN = "{dyn}"


def is_dynamic_token(value: str) -> bool:
    """判定字符串是否为动态值：UUID / 时间戳 / 24+ hex / 高熵（>4.5 且 ≥8B）。"""
    if not value:
        return False
    if len(value) < 8:
        return False
    if _UUID_RE.search(value):
        return True
    if _MS_TS_RE.search(value) or _S_TS_RE.search(value) or _ISO_TS_RE.search(value):
        return True
    if _HEX24_RE.search(value):
        return True
    if _SESSION_TOKEN_RE.search(value):
        return True
    return is_high_entropy_str(value)


def normalize_text(text: str) -> str:
    """归一化文本：所有动态值 → {dyn}（用于去重哈希与 matcher 推断）。"""
    if not text:
        return text
    out = _UUID_RE.sub(_DYN, text)
    out = _MS_TS_RE.sub(_DYN, out)
    out = _S_TS_RE.sub(_DYN, out)
    out = _ISO_TS_RE.sub(_DYN, out)
    out = _HEX24_RE.sub(_DYN, out)
    out = _SESSION_TOKEN_RE.sub(
        lambda m: m.group(0)[: len(m.group(0)) - len(m.group(1))] + _DYN, out
    )
    return out


# 二进制动态块判定：16B 滑动窗口，要求「非可打印字节占比高」且「去重字节占比高」。
# （熵窗口法不可行：16B 窗口熵上限仅 4.0，永远达不到 4.5 阈值；
#   仅看去重率会把可打印文本误判为随机——文本的 16B 窗口去重率同样偏高）
# 8B 滑动窗口：16B 窗口混入静态字节后去重率骤降，只能识别出随机区前 8B；
# 8B 窗口配合低阈值能覆盖整个随机区（8B 纯随机 → 去重率 ~7/8）。
_DYN_WINDOW = 8
_DYN_MIN_DISTINCT = 6
_DYN_MIN_NONPRINT = 3


def _is_dynamic_window(data: bytes, pos: int) -> bool:
    window = data[pos : pos + _DYN_WINDOW]
    if len(window) < _DYN_WINDOW:
        return False
    distinct = len(set(window))
    if distinct < _DYN_MIN_DISTINCT:
        return False
    nonprint = sum(1 for b in window if b < 32 or b > 126)
    return nonprint >= _DYN_MIN_NONPRINT


def _printable(data: bytes) -> bool:
    """整块可打印（含 \\t\\n\\r）判定。"""
    return bool(data) and all(32 <= b < 127 or b in (9, 10, 13) for b in data)


def _is_fuzzy_window(data: bytes, pos: int) -> bool:
    """模糊窗口：去重率下降但仍含非打印字节（随机尾 + 零填充等）。

    随机区的非打印字节占比存在抖动（8B 窗口非打印数可从 3 抖到 1），
    若起点/边界只认"动态"窗口，{dyn} 区域边界会随随机内容漂移 → 哈希不稳定。
    可打印文本窗口（nonprint=0）不会开启模糊判定，版本行/banner 不受影响。
    """
    window = data[pos : pos + _DYN_WINDOW]
    if len(window) < _DYN_WINDOW:
        return False
    distinct = len(set(window))
    nonprint = sum(1 for b in window if b < 32 or b > 126)
    return distinct >= 2 and nonprint >= 1


def _is_absorb_window(data: bytes, pos: int) -> bool:
    """延续吸收条件：窗口内只要含非打印字节即继续吸收。

    随机区后的零填充（distinct=1 的纯 0 窗口）也必须吸收——随机区尾部字节
    恰好为 0x00 时窗口去重率会从 2 掉到 1，若不吸收边界将随随机值漂移。
    纯可打印窗口（nonprint=0）停止吸收：算法列表等长段文本不会被误并。
    """
    window = data[pos : pos + _DYN_WINDOW]
    if len(window) < _DYN_WINDOW:
        return False
    return any(b < 32 or b > 126 for b in window)


def normalize_binary(data: bytes) -> bytes:
    """二进制归一化：随机字节块（cookie/salt/padding 等）→ {dyn} 占位。

    用于 tcp/network 去重键——同一攻击重扫时随机字段不导致去重失效。
    动态区结束后再容忍吸收 _DYN_TAIL_GRACE 个静态字节（动态区尾部往往
    残存个别随机字节，若不吸收会导致哈希不稳定）。
    可打印文本（如 SSH 版本行）字节去重率同样偏高，可能被 {dyn} 化——
    仅影响哈希值一致性，不影响 matcher（matcher 不经过此处）。
    """
    if not data:
        return data
    n = len(data)
    # 第一遍：收集动态区 [start, end)，长度 ≥1（<8 的短区在合并后统一裁决）
    runs: list[tuple[int, int]] = []
    i = 0
    while i < n:
        if _is_dynamic_window(data, i) or _is_fuzzy_window(data, i):
            k = i
            # 延续条件比起点宽松（含任意非打印字节即吸收），保证 {dyn} 区域
            # 边界只取决于"结构位置"而非随机字节值
            while k < n and _is_absorb_window(data, k):
                k += 1
            runs.append((i, k))
            i = k
        else:
            i += 1
    # 第二遍：合并相邻动态区。随机区中偶发 8B 纯可打印突发会把一个随机区
    # 分裂成两段（间隔 = 突发长度 ≤16B 视为同一随机区）；长段可打印文本
    # （算法列表等）间隔远超 16B，不会被误并。
    merged: list[tuple[int, int]] = []
    for start, end in runs:
        if merged and start - merged[-1][1] <= 16:
            merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    # 第三遍：输出。合并后 ≥8B 才替换为 {dyn}（短区仅当并入相邻区后达标；
    # 孤立短区保留原文——它要么是协议头部要么概率可忽略）
    out = bytearray()
    pos = 0
    for start, end in merged:
        out.extend(data[pos:start])
        if end - start >= 8:
            out.extend(b"{dyn}")
        else:
            out.extend(data[start:end])
        pos = end
    out.extend(data[pos:])
    return bytes(out)


# ---------- 多会话 LCS 稳定字节 ----------

def longest_common_substring(a: bytes, b: bytes) -> bytes:
    """两字节串的最长公共子串（Rabin-Karp 二分 + 哈希验证，近似线性）。

    输入截断到 LCS_INPUT_CAP 保护性能；结果 <4B 视为无意义返回 b''。
    """
    if not a or not b:
        return b""
    a = a[:LCS_INPUT_CAP]
    b = b[:LCS_INPUT_CAP]
    lo, hi = 1, min(len(a), len(b))
    best: bytes = b""
    while lo <= hi:
        mid = (lo + hi) // 2
        cand = _common_substring_of_len(a, b, mid)
        if cand is not None:
            best = cand
            lo = mid + 1
        else:
            hi = mid - 1
    return best if len(best) >= 4 else b""


_BASE = 911382323
_MOD = (1 << 61) - 1


def _common_substring_of_len(a: bytes, b: bytes, length: int) -> bytes | None:
    if length > len(a) or length > len(b):
        return None
    # 构建 a 的长度为 length 的子串哈希 → 位置映射
    hashes: dict[int, list[int]] = {}
    h, pow_b = 0, 1
    for i in range(length):
        h = (h * _BASE + a[i]) % _MOD
        pow_b = pow_b * _BASE % _MOD
    hashes.setdefault(h, []).append(0)
    for i in range(1, len(a) - length + 1):
        h = (h * _BASE - a[i - 1] * pow_b + a[i + length - 1]) % _MOD
        hashes.setdefault(h, []).append(i)
    # 滑动 b 的子串，命中即直接验证（哈希碰撞由逐一比对排除）
    h = 0
    for i in range(length):
        h = (h * _BASE + b[i]) % _MOD
    if h in hashes:
        for pos in hashes[h]:
            if a[pos : pos + length] == b[0:length]:
                return b[0:length]
    for i in range(1, len(b) - length + 1):
        h = (h * _BASE - b[i - 1] * pow_b + b[i + length - 1]) % _MOD
        if h in hashes:
            for pos in hashes[h]:
                if a[pos : pos + length] == b[i : i + length]:
                    return b[i : i + length]
    return None


def stable_bytes_over_sessions(chunks: list[bytes]) -> bytes:
    """多会话求稳定字节：依次与后续会话做 LCS 收窄。

    仅当最终公共子串 ≥ MIN_STABLE_BYTES 才返回，否则 b''（不作为模板输入）。
    """
    if len(chunks) < 2:
        return b""
    cur = chunks[0][:LCS_INPUT_CAP]
    for c in chunks[1:]:
        cur = longest_common_substring(cur, c)
        if not cur:
            return b""
    return cur if len(cur) >= MIN_STABLE_BYTES else b""


# ---------- 去重哈希 ----------

# 哈希时剔除的易变请求头（与 http_builder 模板剔除集一致）
HASH_EXCLUDED_HEADERS = {"user-agent", "host", "connection", "content-length"}


def normalized_req_hash(
    method: str,
    path: str,
    headers: dict,
    body: str,
) -> str:
    """HTTP 去重键：sha256(method + path + 排序归一化头 + 归一化body)。

    path 含 query 原样进入（query 动态值已归一化）。
    """
    norm_headers = [
        f"{k.strip().lower()}:{normalize_text(str(v))}"
        for k, v in (headers or {}).items()
        if k.strip().lower() not in HASH_EXCLUDED_HEADERS
    ]
    norm_headers.sort()
    norm = "|".join(
        [
            (method or "").upper() or "-",
            normalize_text(path or "/"),
            ",".join(norm_headers),
            normalize_text(body or ""),
        ]
    )
    return hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest()


def tcp_req_hash(proto: str, first_block: bytes) -> str:
    """tcp/network 去重键：sha256(proto + 归一化首块字节)。

    可打印首块（redis/ftp/ssh 版本行）→ 文本归一化（动态 token → {dyn}）；
    二进制首块（mysql 握手/kexinit）→ 二进制归一化（随机块 → {dyn}）。
    """
    block = first_block[:8192]
    if _printable(block):
        norm = normalize_text(block.decode("latin-1", "replace")).encode("latin-1", "replace")
    else:
        norm = normalize_binary(block)
    return hashlib.sha256(f"{proto}|".encode() + norm).hexdigest()


def dns_req_hash(qname_pattern: str, qtype: str) -> str:
    """dns 去重键：sha256(归一化 qname 模式 + qtype)。"""
    return hashlib.sha256(f"{normalize_text(qname_pattern)}|{qtype}".encode()).hexdigest()


# ---------- 可打印串提取 ----------

_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{6,}")


def printable_words(data: bytes, limit: int = 3, min_len: int = 6) -> list[str]:
    """提取字节串中最长的可打印 ASCII 连续段（matcher 候选词）。"""
    runs = [(m.group(0).decode("ascii", "replace")) for m in _PRINTABLE_RUN_RE.finditer(data)]
    runs = [r for r in runs if len(r) >= min_len]
    runs.sort(key=len, reverse=True)
    return runs[:limit]
