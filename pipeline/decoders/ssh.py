"""SSH 解码器。

复用 Go parsed（client_id / proto_version / kexinit）；parse_status != ok 时从
原始字节解析：版本行正则 + kexinit 二进制包（RFC 4253 §7.1）。
"""
from __future__ import annotations

from .base import BaseDecoder, DecodeError

# 版本行：SSH-2.0-OpenSSH_9.5（<=255B）
_VERSION_RE = __import__("re").compile(rb"^SSH-([0-9][0-9.]*)-([^\r\n]{0,255})")

# SSH_MSG_KEXINIT 各算法字段名（与 Go 侧 parsed.kexinit 对齐）
_KEX_FIELDS = (
    "kex_algorithms",
    "host_key_algorithms",
    "enc_c2s",
    "enc_s2c",
    "mac_c2s",
    "mac_s2c",
    "compression_c2s",
    "compression_s2c",
)

_MAX_KEX_PACKET = 70000  # kexinit 包长上限（RFC 合理值）


def _read_string(buf: bytes, off: int) -> tuple[str, int]:
    """读 SSH string（uint32 len + bytes），越界抛 DecodeError。"""
    if off + 4 > len(buf):
        raise DecodeError("kexinit truncated at string length")
    n = int.from_bytes(buf[off : off + 4], "big")
    off += 4
    if n < 0 or off + n > len(buf):
        raise DecodeError("kexinit truncated in string body")
    return buf[off : off + n].decode("utf-8", "replace"), off + n


def _parse_kexinit(data: bytes) -> dict | None:
    """解析 kexinit 二进制包 → 算法列表 dict；无法识别返回 None。"""
    if len(data) < 6:
        return None
    pkt_len = int.from_bytes(data[0:4], "big")
    if pkt_len < 5 or pkt_len > _MAX_KEX_PACKET:
        return None
    payload = data[5 : 5 + pkt_len - 1]  # 去掉 padding_length 与 padding
    if len(payload) < 1 or payload[0] != 0x14:  # SSH_MSG_KEXINIT
        return None
    off = 1 + 16  # msg id + 16B cookie
    out: dict = {}
    for field in _KEX_FIELDS:
        try:
            raw, off = _read_string(payload, off)
        except DecodeError:
            return None
        out[field] = [s for s in raw.split(",") if s]
    # first_kex_packet_follows (1B) + reserved (4B) 不再需要
    return out


class SSHDecoder(BaseDecoder):
    proto = "ssh"

    def deep_parse(self, client: bytes, server: bytes) -> dict:
        m = _VERSION_RE.match(client)
        if not m:
            raise DecodeError("no ssh version line")
        parsed = {
            "client_id": m.group(2).decode("latin-1", "replace"),
            "proto_version": m.group(1).decode("ascii", "replace"),
        }
        # 版本行后紧跟二进制包（kexinit）
        nl = client.find(b"\n")
        if nl != -1 and nl + 1 < len(client):
            kex = _parse_kexinit(client[nl + 1 :])
            if kex:
                parsed["kexinit"] = kex
        return parsed
