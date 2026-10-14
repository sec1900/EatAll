"""POC 重建包：会话簇 → nuclei 模板 → 落盘 → 入库。

build_all(db, ...) 为顶层编排：
1. 按去重键聚类（http：归一化请求哈希；tcp：归一化首块字节；dns：qname 模式）
2. 各协议 builder 产出模板（matcher 取 ≥2 会话共现稳定串）
3. emit 原子落盘 → pocs 表 upsert（已存在 → hit_count+1，不重建文件）
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from db import DB, templates_dir
from . import dns_builder, http_builder, network_builder, tcp_builder
from .emit import EmitError, ValidateError, dump_yaml, emit
from .normalize import dns_req_hash, normalized_req_hash, tcp_req_hash

logger = logging.getLogger("eatall.build")

# proto_conf → 模板 type / builder
_TCP_PROTOS = ("ssh", "mysql", "redis", "ftp", "smb", "generic")


def _row_parsed(row) -> dict:
    try:
        return json.loads(row["parsed_json"] or "{}")
    except Exception:
        return {}


def _decode_blob(row, field: str) -> bytes:
    v = row[field]
    return bytes(v) if v is not None else b""


def _cluster_http(rows: list) -> tuple[dict[str, list], list]:
    """按归一化请求哈希聚类 HTTP 会话。

    返回 (clusters, invalid_sessions)：method 非合法 HTTP 动词的会话
    （二进制协议混入 http 端口被容错解析出伪 method）单独返回，由调用方
    转 tcp 模板重建——这类内容产 http 模板会被 nuclei 校验拒绝。
    """
    clusters: dict[str, list] = {}
    invalid: list = []
    for row in rows:
        parsed = _row_parsed(row)
        if not parsed.get("method") and not parsed.get("path"):
            continue
        method = str(parsed.get("method") or "GET")
        if not http_builder.is_valid_http_method(method):
            invalid.append(row)
            continue
        headers = parsed.get("headers") or {}
        body = base64.b64decode(parsed.get("body_b64") or "")
        try:
            body_text = body.decode("utf-8", "replace")
        except Exception:
            body_text = ""
        h = normalized_req_hash(
            method,
            str(parsed.get("path") or "/"),
            headers,
            body_text,
        )
        clusters.setdefault(h, []).append(row)
    return clusters, invalid


def _cluster_tcp(rows: list) -> dict[str, list]:
    """按归一化首块字节哈希聚类 TCP 会话。"""
    clusters: dict[str, list] = {}
    for row in rows:
        block = _decode_blob(row, "client_bytes")[:8192]
        if not block:
            continue
        h = tcp_req_hash(str(row["proto"]), block)
        clusters.setdefault(h, []).append(row)
    return clusters


def _cluster_dns(rows: list) -> dict[str, list]:
    clusters: dict[str, list] = {}
    for row in rows:
        parsed = _row_parsed(row)
        queries = parsed.get("queries") or []
        if not queries:
            continue
        q = queries[0]
        qname = str(q.get("qname") or "")
        qtype = str(q.get("qtype") or "")
        pattern = dns_builder.qname_pattern(qname)
        h = dns_req_hash(pattern, qtype)
        clusters.setdefault(h, []).append(row)
    return clusters


def _cluster(rows: list) -> list[tuple[str, str, dict[str, list]]]:
    """全部会话 → [(proto, type, clusters)]。

    type 映射：http 端口合法 HTTP → http 模板；http 端口伪 method（二进制
    协议混入）→ tcp 模板；tls-http 合法 HTTP → http 模板，伪 method →
    network 模板；ssh/mysql/... → tcp 模板；dns → dns 模板。
    """
    out: list[tuple[str, str, dict[str, list]]] = []

    for proto in ("http", "tls-http"):
        p_rows = [r for r in rows if r["proto"] == proto]
        if not p_rows:
            continue
        clusters, invalid = _cluster_http(p_rows)
        if clusters:
            out.append((proto, "http", clusters))
        if invalid:  # 伪 method → tcp/network 归一化首块重建
            if proto == "tls-http":
                out.append((proto, "network", _cluster_tcp(invalid)))
            else:
                out.append((proto, "tcp", _cluster_tcp(invalid)))

    for proto in _TCP_PROTOS:
        p_rows = [r for r in rows if r["proto"] == proto]
        if p_rows:
            out.append((proto, "tcp", _cluster_tcp(p_rows)))

    dns_rows = [r for r in rows if r["proto"] == "dns"]
    if dns_rows:
        out.append(("dns", "dns", _cluster_dns(dns_rows)))
    return out


def _confidence(cluster: list, has_vuln: bool) -> float:
    """confidence 规则：首次 0.4；≥2 独立源 0.7；漏洞特征词 +0.2。"""
    ips = {r["src_ip"] for r in cluster if r["src_ip"]}
    conf = 0.7 if len(ips) >= 2 else 0.4
    if has_vuln:
        conf += 0.2
    return min(1.0, round(conf, 3))


def _row_bag(r) -> dict:
    """sqlite 行 → builder 所需的统一字段包。"""
    return {
        "parsed": _row_parsed(r),
        "client_bytes": _decode_blob(r, "client_bytes"),
        "server_bytes": _decode_blob(r, "server_bytes"),
        "src_ip": r["src_ip"],
        "ts_start": r["ts_start"],
        "session_id": r["session_id"],
    }


def _build_and_emit(
    db: DB,
    ptype: str,
    proto: str,
    h: str,
    cluster: list,
    *,
    validate: bool,
    nuclei_bin: Optional[str],
    templates_out: Path,
) -> Optional[dict]:
    """单簇：构建模板 → 去重判断 → 落盘/入库。返回结果摘要或 None。"""
    rows_sorted = sorted(cluster, key=lambda r: r["ts_start"])
    first = rows_sorted[0]
    last = rows_sorted[-1]
    src_ip = str(first["src_ip"] or "")
    cluster_ips = list(dict.fromkeys(str(r["src_ip"] or "") for r in rows_sorted))
    hash8 = h[:8]
    bags = [_row_bag(r) for r in rows_sorted]

    if ptype == "http":
        template = http_builder.build_http_template(bags, hash8)
    elif ptype == "tcp":
        template = tcp_builder.build_tcp_template(proto, bags, hash8)
    elif ptype == "dns":
        template = dns_builder.build_dns_template(bags, hash8)
    elif ptype == "network":
        template = network_builder.build_network_template(bags, hash8)
    else:
        return None

    if template is None:
        return None

    existing = db.get_poc_by_hash(h)
    if existing is not None:
        # 已存在：仅更新命中计数 / 追加 src_ip / confidence+0.1，不重建文件
        db.upsert_poc(
            normalized_req_hash=h, proto=proto, ptype=ptype,
            src_ip=src_ip, src_ips=cluster_ips,
            first_seen=first["ts_start"], last_seen=last["ts_start"],
            source_session_id=str(first["session_id"] or ""),
        )
        # 模板文件丢失（用户删除）→ 重建
        if not os.path.exists(existing["template_path"] or ""):
            try:
                poc_id, path = emit(template, src_ip=src_ip,
                                    source_session_count=len(rows_sorted),
                                    out_dir=templates_out, validate=validate,
                                    nuclei_bin=nuclei_bin)
                db.upsert_poc(
                    normalized_req_hash=h, proto=proto, ptype=ptype,
                    src_ip=src_ip, src_ips=cluster_ips,
                    first_seen=first["ts_start"], last_seen=last["ts_start"],
                    source_session_id=str(first["session_id"] or ""),
                    template_path=path, template_yaml=_read_yaml(Path(path)),
                )
                logger.info("重建丢失的模板文件: %s", poc_id)
            except EmitError as exc:
                logger.error("重建模板失败 %s: %s", h[:8], exc)
        return {"hash": h, "id": str(existing["poc_id"]), "action": "updated"}

    # 新模板：先落盘后入库
    try:
        poc_id, path = emit(
            template,
            src_ip=src_ip,
            source_session_count=len(rows_sorted),
            out_dir=templates_out,
            validate=validate,
            nuclei_bin=nuclei_bin,
        )
    except ValidateError:
        raise  # nuclei 门禁失败：交给 build_all 记入 errors
    except EmitError as exc:
        logger.error("模板落盘失败 %s (%s): %s", h[:8], proto, exc)
        return None

    has_vuln = bool(
        http_builder.detect_vulns(str(template.get("info", {}).get("description", "")))
    ) if ptype == "http" else False
    conf = _confidence(rows_sorted, has_vuln)
    db.upsert_poc(
        normalized_req_hash=h, proto=proto, ptype=ptype,
        src_ip=src_ip, src_ips=cluster_ips,
        first_seen=first["ts_start"], last_seen=last["ts_start"],
        source_session_id=str(first["session_id"] or ""),
        template_path=path, template_yaml=_read_yaml(Path(path)), confidence=conf,
    )
    return {"hash": h, "id": poc_id, "action": "inserted"}


def _read_yaml(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def build_all(
    db: DB,
    *,
    validate: bool = False,
    nuclei_bin: Optional[str] = None,
    templates_out: Optional[Path] = None,
    since_rowid: Optional[int] = None,
) -> dict:
    """增量构建：聚类 → 模板 → 落盘/入库。返回统计摘要。

    since_rowid 指定后只处理入库顺序在其后的新会话（长驻循环每轮全量
    重建会把 hit_count 虚增——重复构建同一批会话不应算重复命中）。
    返回 summary，调用方用 summary['max_rowid_processed'] 推进水位。
    """
    templates_out = templates_out or templates_dir()
    t0 = time.time()
    rows = db.get_sessions(since_rowid=since_rowid)
    summary = {
        "sessions_scanned": len(rows),
        "templates_emitted": 0,
        "pocs_inserted": 0,
        "pocs_updated": 0,
        "skipped": 0,
        "elapsed_ms": 0,
        "errors": [],
        "max_rowid_processed": 0,
    }
    if not rows:
        summary["elapsed_ms"] = int((time.time() - t0) * 1000)
        return summary
    summary["max_rowid_processed"] = rows[-1]["rowid"]

    for proto, ptype, clusters in _cluster(rows):
        for h, cluster in sorted(clusters.items(), key=lambda kv: min(r["ts_start"] for r in kv[1])):
            if not cluster:
                continue
            try:
                result = _build_and_emit(
                    db, ptype, proto, h, cluster,
                    validate=validate, nuclei_bin=nuclei_bin, templates_out=templates_out,
                )
            except ValidateError as exc:
                summary["errors"].append(str(exc))
                logger.error("模板未通过 nuclei 校验: %s", exc)
                continue
            except Exception as exc:
                summary["errors"].append(f"{proto}/{h[:8]}: {exc!r}")
                logger.exception("构建失败 %s/%s", proto, h[:8])
                continue
            if result is None:
                summary["skipped"] += 1
            elif result["action"] == "inserted":
                summary["templates_emitted"] += 1
                summary["pocs_inserted"] += 1
            else:
                summary["pocs_updated"] += 1

    summary["elapsed_ms"] = int((time.time() - t0) * 1000)
    return summary
