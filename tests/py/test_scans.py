"""scans.py 版本控制单测：事件分割、tool 归属、diff 三集合、幂等、库快照。"""
import json
import os

import pytest

from db import DB
from scans import (
    EPISODE_GAP_SEC,
    _assign_tool,
    _episode_poc_ids,
    _lib_hash,
    _poc_index,
    compute_scans,
    detect_episodes,
)

HOUR = 3600_000


def _db(tmp_path, monkeypatch):
    monkeypatch.setenv("EATALL_HOME", str(tmp_path))
    return DB()


def _add_session(db, sid, ip, ts, proto="http", dst_port=8080):
    db.insert_session(
        session_id=sid, ts_start=ts, ts_end=ts + 100, src_ip=ip, src_port=5000,
        dst_ip="127.0.0.1", dst_port=dst_port, transport="tcp", proto=proto,
        banner="", client_bytes=b"GET / HTTP/1.1\r\n\r\n", server_bytes=b"HTTP/1.1 200 OK\r\n\r\n",
        parse_status="ok", parsed_json="{}", close_reason="client_closed", flow_id="",
    )


def _add_poc(db, fname, sids):
    db.upsert_poc(
        normalized_req_hash=fname, proto="http", ptype="http", src_ip="1.1.1.1",
        first_seen=1, last_seen=2, source_session_id=sids[0],
        template_path=f"out/templates/{fname}", template_yaml=f"id: {fname}\n",
        source_session_ids=sids,
    )


# ---------- detect_episodes ----------

def test_episode_split_on_gap():
    s = [
        ("s1", "1.1.1.1", 1000), ("s2", "1.1.1.1", 5000),        # 同一事件
        ("s3", "1.1.1.1", 5000 + 120_000 + 1),                  # 距上会话超 gap → 新事件
        ("s4", "2.2.2.2", 1000),                                # 不同 IP
    ]
    eps = detect_episodes(s, EPISODE_GAP_SEC * 1000)
    assert len(eps) == 3
    by_ip = {(e["src_ip"], e["ts_start"]): e for e in eps}
    e1 = by_ip[("1.1.1.1", 1000)]
    assert e1["conn_count"] == 2 and e1["ts_end"] == 5000
    e2 = by_ip[("1.1.1.1", 5000 + 120_000 + 1)]
    assert e2["conn_count"] == 1
    e4 = by_ip[("2.2.2.2", 1000)]
    assert e4["conn_count"] == 1


def test_episode_gap_boundary_inside():
    # 间隔恰好等于 gap 属于同一事件（> 才分割）
    s = [("s1", "1.1.1.1", 0), ("s2", "1.1.1.1", EPISODE_GAP_SEC * 1000)]
    eps = detect_episodes(s, EPISODE_GAP_SEC * 1000)
    assert len(eps) == 1 and eps[0]["conn_count"] == 2


# ---------- tool 归属 ----------

def test_assign_tool(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _add_session(db, "s1", "1.1.1.1", 1000)
    db.insert_flow(flow_id="f1", src_ip="1.1.1.1", ts_start=0, ts_end=1000,
                   ports_hit=[8080], conn_count=1, tool_guess="nuclei", tool_conf=0.8,
                   behaviors=[])
    db.insert_flow(flow_id="f2", src_ip="1.1.1.1", ts_start=500, ts_end=2000,
                   ports_hit=[8080], conn_count=1, tool_guess="sqlmap", tool_conf=0.9,
                   behaviors=[])
    ep = {"src_ip": "1.1.1.1", "ts_start": 1000, "ts_end": 1000}
    assert _assign_tool(db, ep) == "sqlmap"  # conf 最高
    assert _assign_tool(db, {"src_ip": "9.9.9.9", "ts_start": 0, "ts_end": 1}) == ""


# ---------- POC 集 ----------

def test_poc_index_and_episode_pocs(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    _add_poc(db, "poc-a.yaml", ["s1", "s2"])
    _add_poc(db, "poc-b.yaml", ["s2"])
    _add_poc(db, "poc-c.yaml", ["s9"])
    idx = _poc_index(db)
    ep = {"session_ids": ["s1", "s2"]}
    assert _episode_poc_ids(idx, ep) == ["poc-a.yaml", "poc-b.yaml"]


# ---------- compute_scans（端到端 diff） ----------

def test_compute_scans_diff_rounds(tmp_path, monkeypatch):
    """两轮扫描：第二轮引入新 POC → new_pocs 正确；第二轮移除 → removed 正确。"""
    db = _db(tmp_path, monkeypatch)
    now = 1_000_000_000_000
    gap = EPISODE_GAP_SEC * 1000

    # 第一轮：s1-s3（now-5gap），捕获 poc-a/poc-b
    _add_session(db, "s1", "1.1.1.1", now - 5 * gap)
    _add_session(db, "s2", "1.1.1.1", now - 5 * gap + 1000)
    _add_session(db, "s3", "1.1.1.1", now - 5 * gap + 2000)
    _add_poc(db, "poc-a.yaml", ["s1"])
    _add_poc(db, "poc-b.yaml", ["s2", "s3"])
    db.insert_flow(flow_id="f1", src_ip="1.1.1.1", ts_start=now - 5 * gap,
                   ts_end=now - 5 * gap + 2000, ports_hit=[8080], conn_count=3,
                   tool_guess="nuclei", tool_conf=0.8, behaviors=[])

    # 第二轮：s4-s5（now-3gap，两轮间隔 > gap），poc-a 仍捕获 + 新 poc-c
    _add_session(db, "s4", "1.1.1.1", now - 3 * gap)
    _add_session(db, "s5", "1.1.1.1", now - 3 * gap + 1000)
    # 生产行为：每次命中调一次 upsert，逐个追加 session id
    db.upsert_poc(normalized_req_hash="poc-a.yaml", proto="http", ptype="http",
                  src_ip="1.1.1.1", first_seen=1, last_seen=2,
                  source_session_id="s4")
    _add_poc(db, "poc-c.yaml", ["s5"])
    db.insert_flow(flow_id="f2", src_ip="1.1.1.1", ts_start=now - 3 * gap,
                   ts_end=now - 3 * gap + 1000, ports_hit=[8080], conn_count=2,
                   tool_guess="nuclei", tool_conf=0.8, behaviors=[])

    summary = compute_scans(db, now_ms=now)
    assert summary["scans_written"] == 2
    scans = db.list_scans_for_src("1.1.1.1")
    assert len(scans) == 2
    first, second = scans[0], scans[1]
    assert set(json.loads(first["poc_ids"])) == {"poc-a.yaml", "poc-b.yaml"}
    assert json.loads(second["new_pocs"]) == ["poc-c.yaml"]  # 升级新增
    assert set(json.loads(second["removed_pocs"])) == {"poc-b.yaml"}  # 本轮未发
    assert second["new_count"] == 1 and second["removed_count"] == 1
    assert second["poc_count"] == 2

    # 幂等：重跑不重复插入
    summary2 = compute_scans(db, now_ms=now + 1000)
    assert len(db.list_scans_for_src("1.1.1.1")) == 2


def test_compute_scans_tool_split(tmp_path, monkeypatch):
    """同 IP 不同工具 → 独立事件序列，互不混淆。"""
    db = _db(tmp_path, monkeypatch)
    now = 1_000_000_000_000
    gap = EPISODE_GAP_SEC * 1000
    _add_session(db, "s1", "1.1.1.1", now - 5 * gap)
    _add_session(db, "s2", "1.1.1.1", now - 3 * gap)
    _add_poc(db, "poc-a.yaml", ["s1"])
    _add_poc(db, "poc-b.yaml", ["s2"])
    db.insert_flow(flow_id="f1", src_ip="1.1.1.1", ts_start=now - 5 * gap,
                   ts_end=now - 5 * gap + 100, ports_hit=[8080], conn_count=1,
                   tool_guess="nuclei", tool_conf=0.8, behaviors=[])
    db.insert_flow(flow_id="f2", src_ip="1.1.1.1", ts_start=now - 3 * gap,
                   ts_end=now - 3 * gap + 100, ports_hit=[8080], conn_count=1,
                   tool_guess="sqlmap", tool_conf=0.9, behaviors=[])
    summary = compute_scans(db, now_ms=now)
    assert summary["scans_written"] == 2
    scans = db.list_scans_for_src("1.1.1.1")
    tools = sorted(s["tool_guess"] for s in scans)
    assert tools == ["nuclei", "sqlmap"]
    # 各自 new_count = 1（无历史）
    assert all(s["new_count"] == 1 for s in scans)


# ---------- 端口聚合与攻击分类 ----------

def _mk_sess_row(proto, port, client_len=100, parsed=None, banner="b1", sid="sx"):
    return {
        "session_id": sid, "src_ip": "1.1.1.1", "ts_start": 1, "dst_port": port,
        "proto": proto, "banner": banner, "client_len": client_len,
        "parsed_json": json.dumps(parsed or {}),
    }


def test_classify_mysql_brute():
    from scans import _classify_port
    sess = [_mk_sess_row("mysql", 3306, parsed={"login": {"username": u}}) for u in ("root", "admin", "test", "user")]
    assert _classify_port("mysql", sess) == ["mysql_brute"]
    assert _classify_port("mysql", sess[:1]) == ["probe"]


def test_classify_redis_unauthorized():
    from scans import _classify_port
    sess = [_mk_sess_row("redis", 6379, parsed={"commands": [["INFO"]]})]
    assert _classify_port("redis", sess) == ["unauthorized_probe"]
    sess2 = [_mk_sess_row("redis", 6379, parsed={"commands": [["PING"]]})]
    assert _classify_port("redis", sess2) == ["probe"]


def test_classify_ftp_brute_and_ssh():
    from scans import _classify_port
    ftp = [_mk_sess_row("ftp", 21, parsed={"commands": [{"cmd": "USER", "arg": f"u{i}"}]}) for i in range(3)]
    assert _classify_port("ftp", ftp) == ["ftp_brute"]
    ssh = [_mk_sess_row("ssh", 22, client_len=50) for _ in range(5)]
    assert _classify_port("ssh", ssh) == ["ssh_brute_probe"]
    assert _classify_port("ssh", ssh[:2]) == ["probe"]


def test_classify_generic_port_probe():
    from scans import _classify_port
    short = [_mk_sess_row("generic", 7001, client_len=4) for _ in range(3)]
    assert _classify_port("generic", short) == ["port_probe"]
    long = [_mk_sess_row("generic", 7001, client_len=200) for _ in range(3)]
    assert _classify_port("generic", long) == ["probe"]


def test_classify_http_poc_attempt():
    from scans import _classify_port
    sess = [_mk_sess_row("http", 8080, parsed={"method": "POST", "path": "/index.php?id=1' AND sleep(3)-- -"})]
    assert _classify_port("http", sess) == ["poc_attempt"]
    sess2 = [_mk_sess_row("http", 8080, parsed={"method": "GET", "path": "/"})]
    assert _classify_port("http", sess2) == ["probe"]


def test_compute_scans_writes_ports(tmp_path, monkeypatch):
    """事件 → ports_hit + scan_ports 明细正确写入。"""
    db = _db(tmp_path, monkeypatch)
    now = 1_000_000_000_000
    gap = EPISODE_GAP_SEC * 1000
    _add_session(db, "s1", "1.1.1.1", now - 5 * gap, proto="http", dst_port=8080)
    for i, user in enumerate(("root", "admin", "test")):
        _add_session(db, f"s{i+2}", "1.1.1.1", now - 5 * gap + 1000 + i,
                     proto="mysql", dst_port=3306)
    # 更新 parsed：mysql 爆破（3 个不同用户名）+ http POC 特征
    for i, user in enumerate(("root", "admin", "test")):
        db.conn.execute("UPDATE sessions SET parsed_json = ? WHERE session_id = ?",
                        (json.dumps({"login": {"username": user}}), f"s{i+2}"))
    db.conn.execute("UPDATE sessions SET parsed_json = ? WHERE session_id = 's1'",
                    (json.dumps({"method": "POST", "path": "/index.php?x=1 AND sleep(3)"}),))
    db.conn.commit()

    summary = compute_scans(db, now_ms=now)
    assert summary["scans_written"] == 1
    assert summary["ports_written"] == 2
    scans = db.list_scans_for_src("1.1.1.1")
    assert json.loads(scans[0]["ports_hit"]) == [3306, 8080]
    ports = db.get_scan_ports(scans[0]["scan_id"])
    by_port = {p["dst_port"]: p for p in ports}
    assert "mysql_brute" in json.loads(by_port[3306]["attacks"]) or \
           json.loads(by_port[3306]["attacks"]) == ["mysql_brute"]
    assert json.loads(by_port[3306]["sample"])["username"] == "root"
    assert "poc_attempt" in json.loads(by_port[8080]["attacks"])
    assert json.loads(by_port[8080]["sample"])["path"].startswith("/index.php")


# ---------- 库快照 ----------

def test_lib_snapshot_per_scan(tmp_path, monkeypatch):
    """版本快照语义：每个新闭合扫描事件记一条（扫一次记一个版本），
    无新扫描不落快照（库持续吸收不再刷版本线）；快照关联扫描事件。"""
    db = _db(tmp_path, monkeypatch)
    now = 1_000_000_000_000
    gap = EPISODE_GAP_SEC * 1000

    # 第一轮扫描（闭合事件）：捕获 poc-a → 落 1 条快照，关联 scan_id
    _add_session(db, "s1", "1.1.1.1", now - 5 * gap)
    _add_poc(db, "poc-a.yaml", ["s1"])
    summary = compute_scans(db, now_ms=now)
    assert summary["poc_count"] == 1 and summary["lib_hash"]
    snaps = db.list_lib_snapshots()
    assert len(snaps) == 1
    s0 = snaps[0]
    assert s0["scan_id"] == f"scan-1.1.1.1-{now - 5 * gap}"
    assert s0["src_ip"] == "1.1.1.1" and s0["poc_count"] == 1

    # 幂等重跑 + 库内容变化（同一扫描补录 poc-b）→ 无新扫描不落新快照
    _add_poc(db, "poc-b.yaml", ["s1"])
    compute_scans(db, now_ms=now + 1000)
    assert len(db.list_lib_snapshots()) == 1

    # 第二轮扫描（闭合）→ 落第 2 条快照（版本 = 扫描次数，与 hash 是否变化无关）
    _add_session(db, "s2", "1.1.1.1", now - 3 * gap)
    compute_scans(db, now_ms=now + 2000)
    snaps = db.list_lib_snapshots()
    assert len(snaps) == 2
    assert snaps[0]["scan_id"] != s0["scan_id"]
    assert snaps[0]["poc_count"] == 2
