"""DNS 解码器（UDP）。

复用 Go parsed（queries: [{qname, qtype}]）；否则手解 12B header + 首个
question（QNAME/QTYPE）。另提供服务端响应解析：rcode 与 answer IP
（供 dns_builder 的 matcher 使用）。
"""
from __future__ import annotations

from .base import BaseDecoder, DecodeError

# QTYPE 数字 → 名称（常用子集，nuclei dns 模板 type 字段需要名称）
_QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 99: "SPF", 255: "ANY",
}


class DNSDecoder(BaseDecoder):
    proto = "dns"

    def deep_parse(self, client: bytes, server: bytes) -> dict:
        if len(client) < 12:
            raise DecodeError("dns packet too short")
        # QNAME：长度前缀标签序列，0 结尾
        off = 12
        labels: list[str] = []
        while off < len(client):
            ln = client[off]
            if ln == 0:
                off += 1
                break
            if ln & 0xC0:  # 查询名出现压缩指针，异常
                raise DecodeError("compression pointer in query name")
            off += 1
            if off + ln > len(client):
                raise DecodeError("truncated qname label")
            labels.append(client[off : off + ln].decode("ascii", "replace"))
            off += ln
        if not labels:
            raise DecodeError("no qname")
        if off + 4 > len(client):
            raise DecodeError("truncated qtype/qclass")
        qtype = int.from_bytes(client[off : off + 2], "big")
        return {
            "queries": [
                {
                    "qname": ".".join(labels),
                    "qtype": _QTYPE_NAMES.get(qtype, str(qtype)),
                    "qtype_num": qtype,
                }
            ],
            "replies_sent": 1,
        }


def server_rcode(server: bytes) -> int | None:
    """解析响应头 flags 的 RCODE（低 4 位）；失败返回 None。"""
    if len(server) < 12:
        return None
    flags = int.from_bytes(server[2:4], "big")
    return flags & 0x0F


def server_answer_ips(server: bytes) -> list[str]:
    """从 DNS 响应解析 A/AAAA answer 记录中的 IP 列表（尽力而为）。"""
    if len(server) < 12:
        return []
    qdcount = int.from_bytes(server[4:6], "big")
    ancount = int.from_bytes(server[6:8], "big")
    if ancount == 0:
        return []
    off = 12
    # 跳过 question 区（含压缩指针容错）
    for _ in range(qdcount):
        while off < len(server):
            ln = server[off]
            if ln == 0:
                off += 1
                break
            if ln & 0xC0:
                off += 2
                break
            off += 1 + ln
        off += 4  # qtype + qclass
    ips: list[str] = []
    for _ in range(ancount):
        if off >= len(server):
            break
        if server[off] & 0xC0:
            off += 2  # 名称压缩指针
        else:
            while off < len(server):
                ln = server[off]
                if ln == 0:
                    off += 1
                    break
                if ln & 0xC0:
                    off += 2
                    break
                off += 1 + ln
        if off + 10 > len(server):
            break
        rtype = int.from_bytes(server[off : off + 2], "big")
        rdlen = int.from_bytes(server[off + 8 : off + 10], "big")
        rdata_start = off + 10
        if rdata_start + rdlen > len(server):
            break
        rdata = server[rdata_start : rdata_start + rdlen]
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in rdata))
        elif rtype == 28 and rdlen == 16:
            ips.append(":".join(f"{int.from_bytes(rdata[i:i+2],'big'):x}" for i in range(0, 16, 2)))
        off = rdata_start + rdlen
    return ips
