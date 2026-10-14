"""TCP 模板重建（ssh/mysql/redis/ftp/smb/generic）。

- 客户端首块字节（≤8KB）→ inputs.data（可打印原样；二进制 {{hex_decode()}}）
- 服务端稳定字节 hex（≥8B）→ binary matcher；单会话退化为该会话自身
"""
from __future__ import annotations

import binascii
from typing import Optional

from .normalize import printable_words, stable_bytes_over_sessions

MAX_INPUT_BYTES = 8192
MAX_READ_SIZE = 65536


def _printable(data: bytes) -> bool:
    """整块可打印（含 \t\n\r）判定。"""
    if not data:
        return False
    return all(32 <= b < 127 or b in (9, 10, 13) for b in data)


def input_expr(block: bytes) -> str:
    """客户端首块字节 → nuclei inputs.data 表达式。"""
    block = block[:MAX_INPUT_BYTES]
    if _printable(block):
        return block.decode("latin-1", "replace")
    return "{{hex_decode('" + binascii.hexlify(block).decode("ascii") + "')}}"


def _matcher(server_bytes_list: list[bytes]) -> tuple[Optional[dict], str]:
    """binary matcher：多会话 LCS 稳定 hex（≥8B）；单会话自身稳定字节。"""
    if len(server_bytes_list) >= 2:
        stable = stable_bytes_over_sessions(server_bytes_list)
        if len(stable) >= 8:
            return {"type": "binary", "binary": [binascii.hexlify(stable).decode("ascii")]}, "multi-session-lcs"
        return None, "unstable"
    server = server_bytes_list[0]
    words = printable_words(server)
    if words:
        return {"type": "word", "words": words[:2]}, "single-session-word"
    if len(server) >= 8:
        return {"type": "binary", "binary": [binascii.hexlify(server[:64]).decode("ascii")]}, "single-session-binary"
    return None, "too-short"


def build_tcp_template(
    proto: str,
    cluster: list,
    hash8: str,
) -> Optional[dict]:
    """由同一去重键的会话簇构建 nuclei tcp 模板。"""
    first = cluster[0]
    client0 = first["client_bytes"]
    server_bytes_list = [r["server_bytes"] for r in cluster]
    matcher, matcher_source = _matcher(server_bytes_list)

    data_expr = input_expr(client0)
    read_size = max(1024, min(max(len(r["server_bytes"]) for r in cluster), MAX_READ_SIZE))
    ips = sorted({r["src_ip"] for r in cluster if r["src_ip"]})
    poc_id = f"poc-tcp-{proto}-probe-{hash8}"

    tcp_block: dict = {"host": ["{{Hostname}}"], "inputs": [{"data": data_expr}], "read-size": read_size}
    if matcher:
        tcp_block["matchers"] = [matcher]

    return {
        "id": poc_id,
        "info": {
            "name": f"EatAll absorbed {proto} probe ({matcher_source})",
            "author": "eatall-pipeline",
            "severity": "low",
            "description": (
                f"Captured by EatAll honeypot from {','.join(ips[:5])} "
                f"(sessions={len(cluster)}). First client block: {data_expr[:120]}"
            ),
            "tags": f"eatall,honeypot,{proto},tcp",
        },
        "tcp": [tcp_block],
    }
