"""HTTP 解码器。

复用 Go parsed；畸形请求（未知 method、CR/LF 混用、缺 HTTP 版本、裸 \r）从
原始字节深解析。与 Go 侧 http.go 的容错状态机对齐：逐行读取、Content-Length
与 chunked 以 TE 为准。
"""
from __future__ import annotations

import base64
import re

from .base import BaseDecoder, DecodeError

# 首行：METHOD SP target SP version（method 可为任意 token，容忍畸形）
_FIRST_LINE_RE = re.compile(rb"^(\S+)\s+(\S+)(?:\s+(\S+))?")

# 响应状态行：HTTP/1.1 200 OK
_STATUS_LINE_RE = re.compile(rb"^HTTP/\d\.\d\s+(\d{3})")

# 深解析时 body 截断上限（对齐 Go 侧 max_body_bytes）
MAX_BODY_BYTES = 65536


def _split_lines(raw: bytes) -> list[bytes]:
    """容错逐行切分：\\n / \\r\\n / 裸 \\r 均可作为行终止符。"""
    lines: list[bytes] = []
    i, n = 0, len(raw)
    while i < n:
        j = i
        while j < n and raw[j] not in (10, 13):  # \n \r
            j += 1
        lines.append(raw[i:j])
        if j >= n:
            break
        if raw[j] == 13 and j + 1 < n and raw[j + 1] == 10:
            j += 1  # \r\n
        j += 1
        i = j
    return lines


class HTTPDecoder(BaseDecoder):
    proto = "http"

    def deep_parse(self, client: bytes, server: bytes) -> dict:
        if not client:
            raise DecodeError("empty client bytes")
        lines = _split_lines(client)
        if not lines or not lines[0]:
            raise DecodeError("no request line")

        m = _FIRST_LINE_RE.match(lines[0])
        if not m:
            raise DecodeError(f"unparsable request line: {lines[0][:64]!r}")
        method = m.group(1).decode("latin-1", "replace")
        target = m.group(2).decode("latin-1", "replace")
        version = (m.group(3) or b"").decode("latin-1", "replace")

        # 头部区：跳过首行，直到空行；容忍无 ':' 的行
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                break
            if b":" in line:
                k, v = line.split(b":", 1)
                k = k.decode("latin-1", "replace").strip()
                if k:
                    headers[k] = v.decode("latin-1", "replace").strip()
        # body 起点 = 头部区结束（空行之后）在原始字节中的偏移
        body_start = _header_block_end(client)
        body_raw = client[body_start:]
        body, truncated = _extract_body(body_raw, headers)

        return {
            "method": method,
            "path": target,
            "http_version": version,
            "headers": headers,
            "body_b64": base64.b64encode(body).decode("ascii"),
            "body_truncated": truncated,
            "req_count": 1,
        }


def _line_end_offset(raw: bytes, start: int) -> int:
    """首行结束位置（不含行终止符）的字节偏移。"""
    i = start
    n = len(raw)
    while i < n and raw[i] not in (10, 13):
        i += 1
    return i


def _line_terminator_len(raw: bytes, pos: int) -> int:
    if pos >= len(raw):
        return 0
    if raw[pos] == 13:
        return 2 if pos + 1 < len(raw) and raw[pos + 1] == 10 else 1
    return 1


def _header_block_end(raw: bytes) -> int:
    """定位头部区结束（空行后）在原始字节中的偏移。"""
    i, n = 0, len(raw)
    while i < n:
        j = i
        while j < n and raw[j] not in (10, 13):
            j += 1
        if j == i:  # 空行
            return j + _line_terminator_len(raw, j)
        if j >= n:
            return n
        i = j + _line_terminator_len(raw, j)
    return n


def _extract_body(raw: bytes, headers: dict) -> tuple[bytes, bool]:
    """按 RFC 7230 提取 body：Transfer-Encoding 优先于 Content-Length。"""
    if not raw:
        return b"", False
    te = headers.get("Transfer-Encoding", "").lower()
    if "chunked" in te:
        return _parse_chunked(raw)
    cl = headers.get("Content-Length")
    if cl is not None:
        try:
            n = int(cl.strip())
        except ValueError:
            n = 0
        if n <= 0:
            return b"", False
        if n > MAX_BODY_BYTES:
            return raw[:MAX_BODY_BYTES], True
        return raw[:n], False
    return b"", False


def _parse_chunked(raw: bytes) -> tuple[bytes, bool]:
    """最小 chunked 解析：逐 chunk 读大小行 + 数据，直到 0 结尾或失败截断。"""
    out = bytearray()
    off, n = 0, len(raw)
    while off < n:
        # 大小行：HEX[;ext]\r\n
        end = raw.find(b"\r\n", off)
        if end == -1:
            break
        size_line = raw[off:end].split(b";", 1)[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError:
            break
        if size == 0:
            # 0 chunk 结束；其后可有 CRLF 结尾（RFC 7230），再往后才算截断/多余
            tail = raw[end + 2 :]
            if tail.startswith(b"\r\n"):
                tail = tail[2:]
            return bytes(out), bool(tail)
        start = end + 2
        if start + size + 2 > n:
            # 数据不足：截断标记
            out.extend(raw[start:])
            return bytes(out), True
        out.extend(raw[start : start + size])
        if len(out) > MAX_BODY_BYTES:
            return bytes(out[:MAX_BODY_BYTES]), True
        off = start + size + 2
    return bytes(out[:MAX_BODY_BYTES]), len(out) > MAX_BODY_BYTES


def server_status(server: bytes) -> int | None:
    """从服务端响应字节解析 HTTP 状态码；失败返回 None。"""
    if not server:
        return None
    m = _STATUS_LINE_RE.match(server)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None
