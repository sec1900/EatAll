"""解码器包：按 proto_conf 调度到各协议解码器。

decode_session(session) -> (parsed_dict, parse_status) 是唯一对外入口：
优先复用 Go parsed；parse_status != ok 时从原始字节深解析。
"""
from __future__ import annotations

from typing import Tuple

from .base import BaseDecoder, DecodeError, get_header  # noqa: F401  (re-export)
from .dns import DNSDecoder, server_answer_ips, server_rcode  # noqa: F401
from .ftp import FTPDecoder  # noqa: F401
from .generic import GenericDecoder  # noqa: F401
from .http import HTTPDecoder, server_status  # noqa: F401
from .mysql import MySQLDecoder  # noqa: F401
from .redis import RedisDecoder  # noqa: F401
from .ssh import SSHDecoder  # noqa: F401

_DECODERS: dict[str, BaseDecoder] = {
    "http": HTTPDecoder(),
    "tls-http": HTTPDecoder(),  # TLS 终止后走 HTTP 语义
    "ssh": SSHDecoder(),
    "mysql": MySQLDecoder(),
    "redis": RedisDecoder(),
    "ftp": FTPDecoder(),
    "dns": DNSDecoder(),
    "smb": GenericDecoder(),  # SMB M3 实现，MVP 仅原始字节
    "generic": GenericDecoder(),
}


def get_decoder(proto: str) -> BaseDecoder:
    return _DECODERS.get(proto or "generic", GenericDecoder())


def decode_session(session: dict) -> Tuple[dict, str]:
    """解码单条会话 → (parsed_dict, parse_status)。任何异常不抛出（容错）。"""
    proto = session.get("proto_conf") or "generic"
    decoder = get_decoder(proto)
    try:
        return decoder.decode(session)
    except Exception:
        # 解码器自身 bug 也不允许拖垮 ingest
        parsed = session.get("parsed") or {}
        status = session.get("parse_status") or "failed"
        return parsed, status
