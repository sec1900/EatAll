"""Network 模板重建（tls-http）。

- TLS ClientHello 提取 SNI（tls.sni 字段优先，其次手解 ClientHello 扩展）
- 首块 TLS application data（解密后）→ inputs.data
- 服务端稳定字节 → binary/word matcher
"""
from __future__ import annotations

from typing import Optional

from .tcp_builder import _matcher, input_expr


def _parse_clienthello_sni(client: bytes) -> Optional[str]:
    """手解 TLS ClientHello 的 server_name 扩展；失败返回 None。"""
    try:
        if len(client) < 5 or client[0] != 0x16:  # handshake record
            return None
        rec_len = int.from_bytes(client[3:5], "big")
        hs = client[5 : 5 + rec_len]
        if len(hs) < 4 or hs[0] != 0x01:  # ClientHello
            return None
        hs_len = int.from_bytes(hs[1:4], "big")
        body = hs[4 : 4 + hs_len]
        if len(body) < 34:  # version(2) + random(32)
            return None
        off = 34
        sid_len = body[off]
        off += 1 + sid_len
        if off + 2 > len(body):
            return None
        cs_len = int.from_bytes(body[off : off + 2], "big")
        off += 2 + cs_len
        if off >= len(body):
            return None
        comp_len = body[off]
        off += 1 + comp_len
        if off + 2 > len(body):
            return None
        ext_len = int.from_bytes(body[off : off + 2], "big")
        off += 2
        end = off + ext_len
        while off + 4 <= end:
            etype = int.from_bytes(body[off : off + 2], "big")
            elen = int.from_bytes(body[off + 2 : off + 4], "big")
            off += 4
            if etype == 0:  # server_name
                if off + elen <= len(body):
                    inner = body[off : off + elen]
                    # inner = [list_len 2B][name_type 1B][name_len 2B][name]
                    if len(inner) >= 5:
                        name_len = int.from_bytes(inner[3:5], "big")
                        name = inner[5 : 5 + name_len]
                        return name.decode("ascii", "replace") if name else None
            off += elen
    except (IndexError, ValueError):
        return None
    return None


def _first_tls_appdata(client: bytes) -> bytes:
    """提取首个 TLS application data record 的 payload（≤8KB）。

    客户端首块通常先有 ClientHello（handshake）等 record，需跳过
    非 application data（0x17）记录继续找。
    """
    out = bytearray()
    off, n = 0, len(client)
    while off + 5 <= n:
        rtype = client[off]
        rlen = int.from_bytes(client[off + 3 : off + 5], "big")
        if off + 5 + rlen > n:
            break  # 记录不完整（半行写入），放弃
        if rtype == 0x17:  # application data
            out.extend(client[off + 5 : off + 5 + rlen])
            break  # 只取首个 appdata 记录
        off += 5 + rlen
    return bytes(out[:8192])


def build_network_template(
    cluster: list,
    hash8: str,
) -> Optional[dict]:
    """由同一去重键的会话簇构建 nuclei network 模板。"""
    first = cluster[0]
    client0 = first["client_bytes"]
    server_bytes_list = [r["server_bytes"] for r in cluster]

    # SNI：优先 Go tls 字段，其次手解 ClientHello
    sni: Optional[str] = None
    tls_field = first.get("tls") or {}
    if tls_field.get("sni"):
        sni = str(tls_field["sni"])
    if not sni:
        sni = _parse_clienthello_sni(client0)

    matcher, matcher_source = _matcher(server_bytes_list)
    appdata = _first_tls_appdata(client0)
    ips = sorted({r["src_ip"] for r in cluster if r["src_ip"]})
    poc_id = f"poc-network-tls-{'sni' if sni else 'probe'}-{hash8}"

    net_block: dict = {"host": ["{{Hostname}}"]}
    if sni:
        net_block["tls"] = {"sni": [sni], "insecure": True}
    else:
        net_block["tls"] = {"insecure": True}
    if appdata:
        net_block["inputs"] = [{"data": input_expr(appdata)}]
    net_block["read-size"] = max(1024, min(max(len(r["server_bytes"]) for r in cluster), 65536))
    if matcher:
        net_block["matchers"] = [matcher]

    return {
        "id": poc_id,
        "info": {
            "name": f"EatAll absorbed tls probe (sni={sni or 'none'}, {matcher_source})",
            "author": "eatall-pipeline",
            "severity": "low",
            "description": (
                f"Captured by EatAll honeypot from {','.join(ips[:5])} "
                f"(sessions={len(cluster)}). SNI: {sni or 'none'}."
            ),
            "tags": "eatall,honeypot,tls,network",
        },
        "network": [net_block],
    }
