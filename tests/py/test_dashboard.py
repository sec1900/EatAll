"""dashboard 服务端测试：API 路由 + 数据形状 + 安全（路径穿越防护）。"""
import json
import os
import threading
import urllib.request
import urllib.error

import pytest

from db import DB
from dashboard.server import Api, Handler, serve

from conftest import make_session, write_sessions


@pytest.fixture()
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("EATALL_HOME", str(tmp_path))
    (tmp_path / "data" / "sessions").mkdir(parents=True)
    write_sessions(tmp_path, [
        make_session(session_id="s1", src_ip="1.2.3.4", ts_start=1_000_000_000_000,
                     proto_conf="http",
                     client_bytes=b"GET /index.php?a=1 HTTP/1.1\r\n\r\n",
                     server_bytes=b"HTTP/1.1 200 OK\r\n\r\n<html>ThinkPHP</html>"),
        make_session(session_id="s2", src_ip="5.6.7.8", ts_start=1_000_000_000_100,
                     proto_conf="ssh", dst_port=8022),
    ])
    d = DB()
    from ingest import run_once
    from fingerprint import FlowAggregator
    run_once(d, FlowAggregator(d))  # JSONL → DB
    d.insert_flow(flow_id="f1", src_ip="1.2.3.4", ts_start=1, ts_end=2,
                  ports_hit=[8080], conn_count=1, tool_guess="sqlmap",
                  tool_conf=0.9, behaviors=["sql_injection"])
    d.upsert_poc(
        normalized_req_hash="h1", proto="http", ptype="http", src_ip="1.2.3.4",
        first_seen=1, last_seen=2, source_session_id="s1",
        template_path="out/templates/poc-http-php-probe-abcdef12.yaml",
        template_yaml=(
            'id: poc-http-php-probe-abcdef12\ninfo:\n  name: "test poc"\n'
            "  author: x\n  severity: critical\n  tags: php,rce\n"
            "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/index.php'\n"
        ),
    )
    return d


@pytest.fixture()
def httpd(db):
    Handler.api = Api(db)
    from http.server import ThreadingHTTPServer
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()


def _get(port, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def test_overview(httpd):
    status, body = _get(httpd, "/api/overview")
    assert status == 200
    d = json.loads(body)
    assert d["session_total"] == 2
    assert d["poc_count"] == 1
    assert d["scan_count"] == 0
    assert d["lib_hash"] == ""
    assert len(d["recent"]) == 2
    assert {p["proto"] for p in d["protocols"]} == {"http", "ssh"}
    assert d["top_srcs"][0]["src_ip"] == "1.2.3.4"


def test_sessions_paginated_filter(httpd):
    status, body = _get(httpd, "/api/sessions?proto=http")
    d = json.loads(body)
    assert d["total"] == 1
    assert d["items"][0]["session_id"] == "s1"
    assert "client_bytes" not in d["items"][0]  # 列表不携带大字段


def test_session_detail_bytes(httpd):
    status, body = _get(httpd, "/api/sessions/s1")
    d = json.loads(body)
    assert d["parsed"]["method"] == "GET"
    assert "GET /index.php" in d["client"]["ascii"]
    assert "47 45 54" in d["client"]["hex"]  # "GET"
    assert d["client"]["len"] > 0
    # 未知 id → 404
    status, _ = _get(httpd, "/api/sessions/nope")
    assert status == 404


def test_flows(httpd):
    status, body = _get(httpd, "/api/flows")
    d = json.loads(body)
    assert d["items"][0]["tool_guess"] == "sqlmap"
    assert d["items"][0]["behaviors"] == ["sql_injection"]


def test_pocs_list_and_yaml(httpd):
    status, body = _get(httpd, "/api/pocs")
    d = json.loads(body)
    assert d["total"] == 1
    p = d["items"][0]
    assert p["filename"] == "poc-http-php-probe-abcdef12.yaml"
    assert p["severity"] == "critical"
    assert p["name"] == "test poc"
    status, body = _get(httpd, "/api/pocs/poc-http-php-probe-abcdef12.yaml")
    assert "{{BaseURL}}" in json.loads(body)["yaml"]
    # 路径穿越防护：不存在的文件名 → 404（且不读文件系统）
    status, _ = _get(httpd, "/api/pocs/..%2F..%2Fetc%2Fpasswd")
    assert status == 404


def test_scans_and_lib_empty(httpd):
    status, body = _get(httpd, "/api/scans")
    assert json.loads(body)["items"] == []
    status, body = _get(httpd, "/api/lib")
    assert json.loads(body)["items"] == []


def test_index_served(httpd):
    status, body = _get(httpd, "/")
    assert status == 200
    assert "EatAll" in body
    status, body = _get(httpd, "/app.js")
    assert status == 200 and "renderOverview" in body


def test_ports_matrix(httpd):
    status, body = _get(httpd, "/api/ports")
    d = json.loads(body)
    ports = {p["dst_port"]: p for p in d["items"]}
    assert ports[8080]["proto"] == "http"
    assert ports[8080]["n"] >= 1
    assert ports[8022]["proto"] == "ssh"


def test_port_detail(httpd):
    status, body = _get(httpd, "/api/ports/8080")
    d = json.loads(body)
    assert d["dst_port"] == 8080
    assert d["proto"] == "http"
    assert d["session_count"] >= 1
    assert d["sessions"][0]["parsed"]["method"] == "GET"
    # 关联 POC（该端口会话触发的模板）
    assert any(p["file"] == "poc-http-php-probe-abcdef12.yaml" for p in d["pocs"])
    # 不存在的端口 → 空结果不 500
    status, body = _get(httpd, "/api/ports/65535")
    assert status in (200, 404)


def test_scan_detail_ports_and_nonhttp(tmp_path, monkeypatch, httpd):
    """scan 事件写入后，详情带端口明细 + 非 HTTP POC 标记。"""
    import sqlite3
    from pathlib import Path
    # 用独立连接写 scan_ports（模拟 scans 模块输出）
    home = Path(os.environ["EATALL_HOME"])
    conn = sqlite3.connect(str(home / "data" / "eatall.db"))
    conn.execute(
        """INSERT INTO scans (scan_id, src_ip, tool_guess, ts_start, ts_end, conn_count,
           session_ids, poc_ids, new_pocs, removed_pocs, poc_count, new_count, removed_count, ports_hit)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("scan-test-1", "1.2.3.4", "nuclei", 100, 200, 3,
         '["s1"]', '["poc-http-php-probe-abcdef12.yaml","poc-tcp-x-123.yaml"]',
         '[]', '[]', 2, 0, 0, "[8080]"),
    )
    conn.execute(
        """INSERT INTO scan_ports (scan_id, dst_port, proto, banner, conn_count, attacks, sample)
           VALUES (?,?,?,?,?,?,?)""",
        ("scan-test-1", 8080, "http", "nginx/1.18.0", 3,
         '["poc_attempt"]', '{"path": "/index.php?id=1"}'),
    )
    conn.commit()
    conn.close()

    status, body = _get(httpd, "/api/scans/scan-test-1")
    d = json.loads(body)
    assert d["ports_hit"] == [8080]
    assert d["ports"][0]["attacks"] == ["poc_attempt"]
    assert d["ports"][0]["sample"]["path"] == "/index.php?id=1"
    assert d["poc_ids_nonhttp"][0]["file"] == "poc-tcp-x-123.yaml"
