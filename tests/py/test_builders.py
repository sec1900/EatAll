"""builder + emit 单测：模板结构 / 去重 / 原子写。"""
import json
import os

import pytest
import yaml

from db import DB
from poc_builder import build_all
from poc_builder.http_builder import build_http_template, detect_vulns, severity_for, vendor_for
from poc_builder.normalize import normalized_req_hash
from poc_builder.tcp_builder import build_tcp_template
from poc_builder.emit import dump_yaml, emit, _ID_RE
from ingest import run_once
from fingerprint import FlowAggregator
from conftest import make_session, write_sessions


def _bag(parsed, client, server, src="1.2.3.4", ts=1785662000000, sid="s1"):
    return {
        "parsed": parsed, "client_bytes": client, "server_bytes": server,
        "src_ip": src, "ts_start": ts, "session_id": sid,
    }


# ---------- http_builder ----------

def test_http_builder_basic():
    parsed = {
        "method": "POST", "path": "/index.php?id=1' AND sleep(3)-- -",
        "headers": {"User-Agent": "sqlmap/1.8", "Host": "t", "Content-Type": "application/x-www-form-urlencoded"},
        "body_b64": b"", "req_count": 1,
    }
    server = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<html>ThinkPHP Error</html>"
    h = normalized_req_hash("POST", "/index.php?id=1' AND sleep(3)-- -",
                            parsed["headers"], "")
    cluster = [
        _bag(parsed, b"POST /index.php HTTP/1.1\r\n\r\n", server),
        _bag(parsed, b"POST /index.php HTTP/1.1\r\n\r\n", server, src="2.2.2.2"),
    ]
    tpl = build_http_template(cluster, h[:8])
    assert tpl["id"] == f"poc-http-php-probe-{h[:8]}" or tpl["id"].startswith("poc-http-")
    assert _ID_RE.match(tpl["id"])
    block = tpl["http"][0]
    assert block["method"] == "POST"
    # 相对路径必须拼 {{BaseURL}}，否则 nuclei 无法执行（带 query 的相对路径解析失败）
    assert block["path"] == ["{{BaseURL}}/index.php?id=1' AND sleep(3)-- -"]
    # UA/Host 剔除
    assert "User-Agent" not in block.get("headers", {})
    assert "Host" not in block.get("headers", {})
    assert block["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    # matcher word 来自两会话稳定响应
    words = block["matchers"][0]["words"]
    assert any("ThinkPHP" in w for w in words)


def test_http_builder_severity_vuln_words():
    parsed = {"method": "GET", "path": "/struts2-showcase/index.action",
              "headers": {}, "body_b64": b""}
    server = b"HTTP/1.1 200 OK\r\n\r\nStruts Showcase"
    tpl = build_http_template([_bag(parsed, b"", server)], "abc12345")
    assert tpl["info"]["severity"] == "high"
    assert "struts2" in tpl["info"]["tags"]
    assert tpl["id"].startswith("poc-http-struts2-")

    parsed2 = {"method": "GET", "path": "/index.php?id=1 union select 1,2,3-- -",
               "headers": {}, "body_b64": b""}
    tpl2 = build_http_template([_bag(parsed2, b"", server)], "abc12345")
    assert tpl2["info"]["severity"] == "critical"


def test_http_builder_query_and_body_parameterize():
    parsed = {
        "method": "GET",
        "path": "/x.php?sid=550e8400-e29b-41d4-a716-446655440000&a=1",
        "headers": {}, "body_b64": b"",
    }
    server = b"HTTP/1.1 200 OK\r\n\r\nok"
    tpl = build_http_template([_bag(parsed, b"", server)], "abc12345")
    path_tpl = tpl["http"][0]["path"][0]
    assert "{{randstr}}" in path_tpl
    assert "a=1" in path_tpl

    # body 动态值
    import base64 as _b64
    parsed2 = {
        "method": "POST", "path": "/l", "headers": {"Content-Type": "text/plain"},
        "body_b64": _b64.b64encode(b"PHPSESSID=cdd08c95af809a78&x=1").decode(),
    }
    tpl2 = build_http_template([_bag(parsed2, b"", server)], "abc12345")
    assert "{{randstr}}" in tpl2["http"][0]["body"]
    assert "x=1" in tpl2["http"][0]["body"]


def test_http_builder_status_fallback_matcher():
    parsed = {"method": "GET", "path": "/bin", "headers": {}, "body_b64": b""}
    server = b"HTTP/1.1 404 Not Found\r\n\r\n"  # 无可打印响应
    tpl = build_http_template([_bag(parsed, b"", server)], "abc12345")
    matchers = tpl["http"][0]["matchers"]
    assert matchers[0]["type"] == "status"
    assert matchers[0]["status"] == [404]


def test_detect_vulns_and_mapping():
    hits = detect_vulns("/x.php?id=1' and sleep(3)")
    assert "sleep(" in hits
    assert severity_for(hits) == "critical"
    assert severity_for(["thinkphp"]) == "high"
    assert severity_for([]) == "low"
    assert vendor_for("/struts2-showcase/index.action") == "struts2"
    assert vendor_for("/actuator/env") == "actuator"
    assert vendor_for("/random") == "generic"


# ---------- tcp_builder ----------

def test_tcp_builder_ssh():
    server = b"SSH-2.0-OpenSSH_7.4\r\n\x00\x00\x00\xd0\x08\x00\x00\x00\x00"
    cluster = [
        _bag({}, b"SSH-2.0-OpenSSH_8.9\r\n", server),
        _bag({}, b"SSH-2.0-OpenSSH_8.9\r\n", server, src="2.2.2.2"),
    ]
    tpl = build_tcp_template("ssh", cluster, "abc12345")
    assert tpl["id"].startswith("poc-tcp-ssh-")
    block = tpl["tcp"][0]
    assert block["inputs"][0]["data"] == "SSH-2.0-OpenSSH_8.9\r\n"  # 可打印原样
    # binary matcher hex 包含服务端稳定字节
    matcher = block["matchers"][0]
    assert matcher["type"] == "binary"
    hexstr = matcher["binary"][0]
    assert "5353482d322e302d4f70656e5353485f372e34" in hexstr  # "SSH-2.0-OpenSSH_7.4"
    assert block["read-size"] >= 1024


def test_tcp_builder_binary_input():
    cluster = [_bag({}, b"\x01\x02\x03\x04\x05", b"RESP-BANNER-XXXX")]
    tpl = build_tcp_template("generic", cluster, "abc12345")
    data = tpl["tcp"][0]["inputs"][0]["data"]
    assert data.startswith("{{hex_decode('0102030405")


# ---------- network_builder ----------

def _tls_clienthello(sni):
    """构造带 SNI 的 TLS ClientHello record（RFC 8446 布局）。"""
    # server_name 扩展：type(2) + ext_len(2) + [list_len(2) + name_type(1) + name_len(2) + name]
    inner = (len(sni) + 3).to_bytes(2, "big") + b"\x00" + len(sni).to_bytes(2, "big") + sni.encode()
    ext = b"\x00\x00" + len(inner).to_bytes(2, "big") + inner
    body = (
        b"\x03\x03" + os.urandom(32) + b"\x00"  # version + random + session_id_len=0
        + (4).to_bytes(2, "big") + b"\x13\x01\x13\x02"  # cipher_suites (len=4)
        + b"\x01\x00"  # compression: len=1, null
        + len(ext).to_bytes(2, "big") + ext
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def test_network_builder_tls():
    from poc_builder.network_builder import build_network_template
    client = _tls_clienthello("vpn.example.com") + b"\x17\x03\x03\x00\x05hello"
    server = b"\x16\x03\x03\x00\x2a" + os.urandom(38) + b"TLS-BANNER-STABLE"
    cluster = [_bag({}, client, server), _bag({}, client, server, src="2.2.2.2")]
    tpl = build_network_template(cluster, "abc12345")
    assert tpl is not None
    assert tpl["id"].startswith("poc-network-tls-")
    block = tpl["network"][0]
    assert block["tls"]["sni"] == ["vpn.example.com"]
    assert block["tls"]["insecure"] is True
    # 首块 TLS appdata（解密后的 HTTP 请求）作为 inputs
    assert block["inputs"][0]["data"] == "hello"
    # 服务端稳定字节 binary matcher
    matcher = block["matchers"][0]
    assert matcher["type"] == "binary"
    assert "544c532d42414e4e45522d535441424c45" in matcher["binary"][0]  # TLS-BANNER-STABLE


def test_network_builder_no_sni():
    from poc_builder.network_builder import build_network_template
    client = b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00"  # 畸形/无 SNI
    server = b"RESPONSE-BANNER-XXXX"
    tpl = build_network_template([_bag({}, client, server)], "abc12345")
    assert tpl is not None
    assert tpl["network"][0]["tls"].get("sni") is None  # 无 SNI 则缺省
    assert tpl["network"][0]["tls"].get("insecure") is True


# ---------- emit ----------

def test_emit_roundtrip_and_quoting(tmp_home):
    tpl = {
        "id": "poc-http-php-probe-abc12345",
        "info": {"name": "x", "author": "eatall-pipeline", "severity": "low",
                 "description": "d", "tags": "eatall"},
        "http": [{"method": "POST", "path": ["{{BaseURL}}/a.php?x={{randstr}}"],
                  "headers": {"X-T": "{{randstr}}"}, "body": "redirect:${%23a%3D{{randstr}}}"}],
    }
    text = dump_yaml(tpl)
    loaded = yaml.safe_load(text)
    assert loaded["http"][0]["path"][0] == "{{BaseURL}}/a.php?x={{randstr}}"
    assert loaded["http"][0]["body"] == "redirect:${%23a%3D{{randstr}}}"

    out = tmp_home / "out" / "templates"
    poc_id, path = emit(tpl, src_ip="9.9.9.9", source_session_count=1, out_dir=out)
    assert poc_id == tpl["id"]
    content = open(path, encoding="utf-8").read()
    assert content.startswith("# generated by EatAll")
    assert "# src_ip: 9.9.9.9" in content
    assert "# generated_at: " in content
    assert "poc-http-php-probe-abc12345" in content
    # 无临时文件残留
    assert not [f for f in os.listdir(out) if f.startswith(".")]


def test_emit_atomic_replace(tmp_home):
    out = tmp_home / "out" / "templates"
    tpl = {"id": "poc-tcp-ssh-probe-abc12345",
           "info": {"name": "x", "author": "a", "severity": "low", "description": "d", "tags": "t"},
           "tcp": [{"host": ["{{Hostname}}"], "inputs": [{"data": "x"}], "read-size": 1024}]}
    emit(tpl, src_ip="1.1.1.1", source_session_count=1, out_dir=out)
    emit(tpl, src_ip="1.1.1.1", source_session_count=2, out_dir=out)  # 覆盖写
    final = out / "poc-tcp-ssh-probe-abc12345.yaml"
    assert final.exists()
    content = final.read_text(encoding="utf-8")
    assert "# source_sessions: 2" in content


def test_emit_rejects_bad_id(tmp_home):
    import pytest
    from poc_builder.emit import EmitError
    with pytest.raises(EmitError):
        emit({"id": "bad id!!"}, src_ip="1.1.1.1", source_session_count=1,
             out_dir=tmp_home / "out")


# ---------- 全链路（ingest → build → 去重） ----------

def _attack_sessions(prefix="att"):
    s = []
    for i in range(2):
        client = b"GET /index.php?id=1' AND sleep(3)-- - HTTP/1.1\r\nUser-Agent: sqlmap/1.8\r\nHost: t\r\n\r\n"
        server = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<html><title>ThinkPHP</title></html>"
        s.append(make_session(
            client_bytes=client, server_bytes=server,
            parsed={
                "method": "GET", "path": "/index.php?id=1' AND sleep(3)-- -",
                "headers": {"User-Agent": "sqlmap/1.8", "Host": "t"},
                "body_b64": "", "req_count": 1,
            },
            src_ip=f"10.0.0.{i+1}", session_id=f"{prefix}{i}",
            ts_start=1785662000000 + i * 1000,
        ))
    return s


def test_build_all_insert_and_dedup(tmp_home):
    write_sessions(tmp_home, _attack_sessions())
    db = DB()
    agg = FlowAggregator(db)
    run_once(db, agg)
    summary = build_all(db)
    assert summary["pocs_inserted"] == 1
    assert summary["templates_emitted"] == 1
    assert summary["sessions_scanned"] == 2
    pocs = db.get_pocs()
    assert len(pocs) == 1
    row = pocs[0]
    assert row["hit_count"] == 1
    assert row["confidence"] == pytest.approx(0.9)  # ≥2 独立源 0.7 + 漏洞词 0.2
    assert row["status"] == "unverified"
    assert json.loads(row["src_ips"]) == ["10.0.0.1", "10.0.0.2"]
    tpl_path = row["template_path"]
    assert os.path.exists(tpl_path)

    # 同一攻击再扫（新会话 id，相同归一化内容）→ 去重：hit_count 增加，不新增模板文件
    write_sessions(tmp_home, _attack_sessions(prefix="att2"))
    run_once(db, agg)
    summary2 = build_all(db)
    assert summary2["pocs_inserted"] == 0
    assert summary2["pocs_updated"] == 1
    row2 = db.get_poc_by_hash(row["normalized_req_hash"])
    assert row2["hit_count"] == 2  # 首次 1 + 二次扫描 1（按去重键计命中）
    files = list((tmp_home / "out" / "templates").glob("poc-*.yaml"))
    assert len(files) == 1

    # 模板文件为合法 YAML
    with open(tpl_path, encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh)
    assert loaded["id"].startswith("poc-http-")
    assert loaded["http"][0]["method"] == "GET"
    db.close()


def test_build_incremental_watermark(tmp_home):
    """增量构建：重复 build 不虚增 hit_count（长驻循环语义）。"""
    write_sessions(tmp_home, _attack_sessions())
    db = DB()
    agg = FlowAggregator(db)
    run_once(db, agg)
    s1 = build_all(db)  # 全量第一轮
    assert s1["pocs_inserted"] == 1
    assert s1["max_rowid_processed"] > 0
    # 无新会话 → 增量构建 sessions_scanned=0
    s2 = build_all(db, since_rowid=s1["max_rowid_processed"])
    assert s2["sessions_scanned"] == 0
    assert s2["pocs_updated"] == 0
    # 新会话（第二次攻击，ts_start 故意复用旧值模拟迟到完成）→ 只处理新会话，hit_count+1
    write_sessions(tmp_home, _attack_sessions(prefix="att3"))
    run_once(db, agg)
    s3 = build_all(db, since_rowid=s1["max_rowid_processed"])
    assert s3["sessions_scanned"] == 2
    assert s3["pocs_updated"] == 1
    row = db.get_poc_by_hash(db.get_pocs()[0]["normalized_req_hash"])
    assert row["hit_count"] == 2
    # 同一水位再跑一次 → 不再更新（水位推进过）
    s4 = build_all(db, since_rowid=s3["max_rowid_processed"])
    assert s4["sessions_scanned"] == 0
    row = db.get_poc_by_hash(row["normalized_req_hash"])
    assert row["hit_count"] == 2
    db.close()


def test_build_all_multi_proto(tmp_home):
    """http + ssh + generic 三类会话 → 三类模板。"""
    ssh_client = b"SSH-2.0-OpenSSH_8.9\r\n"
    ssh_server = b"SSH-2.0-OpenSSH_7.4\r\nstatic-kexinit-bytes-here"
    sessions = [
        make_session(client_bytes=b"GET / HTTP/1.1\r\n\r\n", server_bytes=b"HTTP/1.1 200 OK\r\n\r\nhi",
                     parsed={"method": "GET", "path": "/", "headers": {}, "body_b64": ""},
                     src_ip="3.3.3.3"),
        make_session(proto_conf="ssh", dst_port=8022,
                     client_bytes=ssh_client, server_bytes=ssh_server, parsed=None,
                     src_ip="3.3.3.3"),
        make_session(proto_conf="generic", dst_port=7001,
                     client_bytes=b"hello\r\n", server_bytes=b"welcome-banner\r\n", parsed=None,
                     src_ip="3.3.3.3"),
    ]
    write_sessions(tmp_home, sessions)
    db = DB()
    agg = FlowAggregator(db)
    run_once(db, agg)
    summary = build_all(db)
    assert summary["pocs_inserted"] == 3
    protos = {r["proto"] for r in db.get_pocs()}
    assert {"http", "ssh", "generic"} == protos
    files = sorted((tmp_home / "out" / "templates").glob("poc-*.yaml"))
    assert len(files) == 3
    assert any(f.name.startswith("poc-tcp-ssh-") for f in files)
    db.close()
