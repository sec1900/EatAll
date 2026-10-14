"""指纹规则 + 流聚合单测。"""
import base64

from fingerprint import (
    FlowAggregator,
    fingerprint_session,
    ssh_kex_fingerprint,
)
from conftest import make_session


def _http_sess(ua, path="/", ts=1785662000000, src="1.2.3.4", dport=8080):
    return make_session(
        parsed={"method": "GET", "path": path, "headers": {"User-Agent": ua}, "body_b64": ""},
        src_ip=src, dst_port=dport, ts_start=ts, ts_end=ts + 10,
        client_bytes=f"GET {path} HTTP/1.1\r\nUser-Agent: {ua}\r\n\r\n".encode(),
    )


def test_http_ua_rules():
    assert fingerprint_session(_http_sess("sqlmap/1.8#stable"), {"headers": {"User-Agent": "sqlmap/1.8#stable"}})[0] == "sqlmap"
    assert fingerprint_session(_http_sess("nuclei"), {"headers": {"User-Agent": "nuclei"}})[0] == "nuclei"
    ua = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
    assert fingerprint_session(_http_sess(ua), {"headers": {"User-Agent": ua}})[0] == "nmap"
    assert fingerprint_session(_http_sess("zgrab/0.x"), {"headers": {"User-Agent": "zgrab/0.x"}})[0] == "zgrab"
    assert fingerprint_session(_http_sess("WPScan v3.8"), {"headers": {"User-Agent": "WPScan v3.8"}})[0] == "wpscan"
    assert fingerprint_session(_http_sess("python-requests/2.31"), {"headers": {"User-Agent": "python-requests/2.31"}})[0] == "python-requests"
    assert fingerprint_session(_http_sess("Go-http-client/1.1"), {"headers": {"User-Agent": "Go-http-client/1.1"}})[0] == "go-http-client"
    # 无 UA 不误判
    assert fingerprint_session(_http_sess(""), {"headers": {}})[0] is None


def test_ssh_kex_rules():
    openssh = {"kex_algorithms": ["curve25519-sha256", "ext-info-c", "kex-strict-c-v00@openssh.com"], "enc_c2s": ["chacha20-poly1305@openssh.com"]}
    paramiko = {"kex_algorithms": ["curve25519-sha256", "diffie-hellman-group1-sha1", "ext-info-c"], "enc_c2s": ["chacha20-poly1305@openssh.com"]}
    go = {"kex_algorithms": ["curve25519-sha256@libssh.org", "ecdh-sha2-nistp256"], "enc_c2s": ["aes128-ctr", "aes192-ctr"]}
    tools = {t for t, _, _ in ssh_kex_fingerprint(openssh)}
    assert "openssh" in tools
    tools = {t for t, _, _ in ssh_kex_fingerprint(paramiko)}
    assert "paramiko" in tools
    tools = {t for t, _, _ in ssh_kex_fingerprint(go)}
    assert "go-xcrypto" in tools
    assert ssh_kex_fingerprint({}) == []


def test_flow_port_scan():
    db = None
    agg = FlowAggregator(db)  # 不落库（db=None 时仅内存聚合）
    from fingerprint import Flow
    flow = Flow("1.2.3.4", 1785662000000)
    for i in range(7):
        flow.add(_http_sess("nuclei", dport=8000 + i, ts=1785662000000 + i * 1000), {"headers": {"User-Agent": "nuclei"}})
    behaviors = flow.behaviors()
    assert "port_scan" in behaviors
    tool, conf = flow.tool_guess()
    assert tool == "nuclei"


def test_flow_sql_injection_behavior():
    from fingerprint import Flow
    flow = Flow("5.6.7.8", 1785662000000)
    s = make_session(
        client_bytes=b"GET /index.php?id=1' AND sleep(3)-- - HTTP/1.1\r\n\r\n",
        src_ip="5.6.7.8",
    )
    flow.add(s, {"method": "GET"})
    assert "sql_injection" in flow.behaviors()


def test_flow_window_split():
    """超过 60s 窗口 → 新 flow。"""
    agg = FlowAggregator(None, now_fn=lambda: 1785662999999)
    s1 = make_session(src_ip="9.9.9.9", ts_start=1785662000000)
    s2 = make_session(src_ip="9.9.9.9", ts_start=1785662000000 + 61_000)
    f1 = agg.add(s1, {})
    f2 = agg.add(s2, {})
    assert f1 != f2
    # idle 关闭
    n = agg.close_idle()
    assert n >= 1
    assert agg.close_all() >= 0


def test_flow_aggregator_persists(tmp_home, db):
    from ingest import run_once
    from conftest import write_sessions
    sess = [
        make_session(src_ip="2.2.2.2", dst_port=8000, ts_start=1785662000000),
        make_session(src_ip="2.2.2.2", dst_port=8001, ts_start=1785662000500),
    ]
    write_sessions(tmp_home, sess)
    agg = FlowAggregator(db)
    run_once(db, agg)
    agg.close_all()
    assert db.flow_count() == 1
    rows = db.conn.execute("SELECT * FROM flows").fetchall()
    assert sorted(json_loads(rows[0]["ports_hit"])) == [8000, 8001]
    assert rows[0]["conn_count"] == 2


def json_loads(s):
    import json
    return json.loads(s)
