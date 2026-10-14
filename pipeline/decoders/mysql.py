"""MySQL 解码器。

复用 Go parsed（login: {username, auth_plugin, database}）；否则手工切
HandshakeResponse41 包：caps | max_packet | charset | filler | username
| auth_response | database | plugin。
"""
from __future__ import annotations

from .base import BaseDecoder, DecodeError

# 客户端 capability 位（MySQL 协议）
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00080000


class MySQLDecoder(BaseDecoder):
    proto = "mysql"

    def deep_parse(self, client: bytes, server: bytes) -> dict:
        if len(client) < 4 + 32:
            raise DecodeError("handshake response too short")
        off = 4  # 跳过 4B 包头（packet_len + seq）
        caps = int.from_bytes(client[off : off + 4], "little")
        off += 4
        off += 5  # max_packet(4B) + charset(1B)
        off += 23  # filler(23B)

        def nul_str() -> str:
            nonlocal off
            j = client.find(b"\x00", off)
            if j == -1:
                raise DecodeError("unterminated NUL string")
            s = client[off:j].decode("utf-8", "replace")
            off = j + 1
            return s

        username = nul_str()
        # auth response：CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA → lenenc；否则 NUL 结尾
        if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
            if off >= len(client):
                raise DecodeError("missing lenenc auth length")
            ln = client[off]
            off += 1
            if ln > 250:  # lenenc 首字节 >250 表示多字节长度（数据过大，放弃精确解析）
                raise DecodeError("oversized lenenc auth response")
            off += ln
        else:
            nul_str()
        database = None
        if caps & CLIENT_CONNECT_WITH_DB:
            database = nul_str()
        return {"login": {"username": username, "database": database}, "packet_count": 1}
