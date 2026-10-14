"""兜底解码器：不做解析，仅保留原始字节（banner 审计）。"""
from __future__ import annotations

from .base import BaseDecoder


class GenericDecoder(BaseDecoder):
    proto = "generic"

    def deep_parse(self, client: bytes, server: bytes) -> dict:
        # generic 协议无结构化信息；空 parsed 即可（decode() 会返回原始状态）
        return {}
