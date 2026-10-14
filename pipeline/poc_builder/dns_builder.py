"""DNS 模板重建（UDP）。

- qname 模式参数化：动态首标签 → {{FQDN}}；静态保留原样
- matcher：DSL 查 rcode（server_rcode）+ word 查 answer IP（server_answer_ips）
"""
from __future__ import annotations

from typing import Optional

from decoders.dns import server_answer_ips, server_rcode
from .emit import sanitize_segment
from .normalize import is_dynamic_token

# nuclei dns 模板支持的 type
_SUPPORTED_QTYPES = {"A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT", "ANY"}


def qname_pattern(qname: str) -> str:
    """qname → 模板 name 模式：动态首标签参数化。"""
    if not qname:
        return "{{FQDN}}"
    labels = qname.split(".")
    if len(labels) >= 2 and is_dynamic_token(labels[0]):
        return "{{FQDN}}"
    return qname


def build_dns_template(
    cluster: list,
    hash8: str,
) -> Optional[dict]:
    """由同一去重键的会话簇构建 nuclei dns 模板；qtype 不支持返回 None。"""
    first = cluster[0]
    parsed = first["parsed"] or {}
    queries = parsed.get("queries") or []
    if not queries:
        return None
    q = queries[0]
    qtype = str(q.get("qtype") or "")
    if qtype not in _SUPPORTED_QTYPES:
        return None

    name = qname_pattern(str(q.get("qname") or ""))
    ips = sorted({r["src_ip"] for r in cluster if r["src_ip"]})
    poc_id = f"poc-dns-{qtype.lower()}-{sanitize_segment(name.replace('.', '-'))}-{hash8}"

    # matcher：rcode 与 answer IP
    matchers: list[dict] = []
    rcode = None
    answers: list[str] = []
    for r in cluster:
        rc = server_rcode(r["server_bytes"])
        if rc is not None:
            rcode = rc
        answers.extend(server_answer_ips(r["server_bytes"]))
    if rcode is not None:
        matchers.append({"type": "dsl", "dsl": [f"rcode == {rcode}"]})
    answers = list(dict.fromkeys(answers))[:4]
    if answers:
        matchers.append({"type": "word", "words": answers})

    dns_block: dict = {"name": name, "type": qtype}
    if matchers:
        dns_block["matchers"] = matchers

    return {
        "id": poc_id,
        "info": {
            "name": f"EatAll absorbed dns query {qtype} {name}",
            "author": "eatall-pipeline",
            "severity": "low",
            "description": (
                f"Captured by EatAll honeypot from {','.join(ips[:5])} "
                f"(sessions={len(cluster)}). Query pattern: {name} ({qtype})."
            ),
            "tags": "eatall,honeypot,dns",
        },
        "dns": [dns_block],
    }
