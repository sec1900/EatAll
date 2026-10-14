"""FTP 解码器。

复用 Go parsed（commands: [{cmd, arg}]）；否则行式解析：每行 `CMD [arg]`。
记录明文命令序列（含 PASS 密码，用于爆破情报）。
"""
from __future__ import annotations

from .base import BaseDecoder, DecodeError


class FTPDecoder(BaseDecoder):
    proto = "ftp"

    def deep_parse(self, client: bytes, server: bytes) -> dict:
        if not client:
            raise DecodeError("empty client bytes")
        commands: list[dict[str, str]] = []
        for line in client.split(b"\n"):
            line = line.rstrip(b"\r")
            if not line.strip():
                continue
            parts = line.decode("latin-1", "replace").strip().split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""
            commands.append({"cmd": cmd, "arg": arg})
        if not commands:
            raise DecodeError("no commands parsed")
        return {"commands": commands}
