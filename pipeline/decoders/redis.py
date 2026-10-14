"""Redis 解码器。

复用 Go parsed（commands: [[cmd, arg...]]）；否则解析 RESP 数组（*N + $len）
并兼容内联命令（非 '*' 开头的裸命令行）。
"""
from __future__ import annotations

from .base import BaseDecoder, DecodeError


class RedisDecoder(BaseDecoder):
    proto = "redis"

    def deep_parse(self, client: bytes, server: bytes) -> dict:
        cmds: list[list[str]] = []
        off, n = 0, len(client)
        while off < n:
            if client[off] == ord("*"):
                # RESP 数组：*N\r\n $len\r\n<data>\r\n ...
                end = client.find(b"\r\n", off)
                if end == -1:
                    break
                try:
                    cnt = int(client[off + 1 : end])
                except ValueError:
                    break
                off = end + 2
                args: list[str] = []
                for _ in range(cnt):
                    if off >= n or client[off : off + 1] != b"$":
                        break  # 非 bulk 类型（+OK/-ERR 等），跳过
                    end = client.find(b"\r\n", off)
                    if end == -1:
                        raise DecodeError("truncated RESP bulk length")
                    try:
                        ln = int(client[off + 1 : end])
                    except ValueError:
                        raise DecodeError("bad RESP bulk length")
                    off = end + 2
                    if ln < 0 or off + ln + 2 > n:
                        raise DecodeError("truncated RESP bulk body")
                    args.append(client[off : off + ln].decode("utf-8", "replace"))
                    off += ln + 2
                if args:
                    cmds.append(args)
            else:
                # 内联命令：一整行按空白切分
                end = client.find(b"\n", off)
                if end == -1:
                    break
                line = client[off:end].rstrip(b"\r").decode("utf-8", "replace")
                if line.strip():
                    cmds.append(line.split())
                off = end + 1
        if not cmds:
            raise DecodeError("no commands parsed")
        return {"commands": cmds, "responses_sent": None}
