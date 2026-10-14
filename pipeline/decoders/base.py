"""解码器公共基类与调度。

策略：优先复用 Go 侧的 parsed 字段（schema.md 契约）；
parse_status != ok 或 parsed 为空时，从 client_bytes 原始字节深解析（尽力而为）。
"""
from __future__ import annotations

import base64
from typing import Optional, Tuple

# 解析失败异常：深解析无法识别时抛出，由调度层回退到 Go parsed / 空结果
class DecodeError(Exception):
    pass


class BaseDecoder:
    """协议解码器基类。子类实现 deep_parse 即可。"""

    #: 协议名（与 proto_conf 对应）
    proto: str = "generic"

    def deep_parse(self, client: bytes, server: bytes) -> dict:
        """从原始字节深解析，返回与 Go parsed 同构的 dict；失败抛 DecodeError。"""
        raise NotImplementedError

    def decode(self, session: dict) -> Tuple[dict, str]:
        """解码单条会话：优先 Go parsed；否则深解析原始字节。

        返回 (parsed_dict, parse_status)：
        - Go ok 且 parsed 非空  -> 直接复用，状态保持 'ok'
        - 深解析成功            -> 返回深解析结果，状态 'ok'（我们解析器的结论）
        - 两者皆失败            -> 空 dict + 原始状态（failed/partial）
        """
        parsed = session.get("parsed") or {}
        status = session.get("parse_status") or "ok"
        if status == "ok" and parsed:
            return parsed, "ok"
        client = _b64(session.get("client_bytes_b64"))
        server = _b64(session.get("server_bytes_b64"))
        try:
            deep = self.deep_parse(client, server)
        except DecodeError:
            # 深解析失败：保留 Go 侧状态（ok 且无 parsed 视为 failed）
            return parsed, status if status != "ok" else "failed"
        if deep:
            return deep, "ok"
        # 深解析无结果（如 generic 兜底）：维持原始状态
        return parsed, status


def _b64(s: Optional[str]) -> bytes:
    """base64 解码，容错：空值/非法输入返回 b''。"""
    if not s:
        return b""
    try:
        return base64.b64decode(s)
    except Exception:
        return b""


def get_header(headers: Optional[dict], name: str) -> str:
    """大小写不敏感地取 HTTP 头。"""
    if not headers:
        return ""
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == name.lower():
            return str(v)
    return ""
