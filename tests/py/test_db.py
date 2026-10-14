"""SQLite 三表单测：结构 / 去重 UNIQUE / confidence 演进。"""
import json


def test_schema_tables(db):
    tables = {
        r[0]
        for r in db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert {"sessions", "flows", "pocs"} <= tables


def test_sessions_idempotent_insert(db):
    ok = db.insert_session(
        session_id="k1", ts_start=1, ts_end=2, src_ip="1.1.1.1", src_port=100,
        dst_ip="2.2.2.2", dst_port=8080, transport="tcp", proto="http",
        banner="nginx", client_bytes=b"a", server_bytes=b"b", parse_status="ok",
        parsed_json="{}", close_reason="x", flow_id="f1",
    )
    assert ok is True
    ok2 = db.insert_session(
        session_id="k1", ts_start=1, ts_end=2, src_ip="1.1.1.1", src_port=100,
        dst_ip="2.2.2.2", dst_port=8080, transport="tcp", proto="http",
        banner="nginx", client_bytes=b"a", server_bytes=b"b", parse_status="ok",
        parsed_json="{}", close_reason="x", flow_id="f1",
    )
    assert ok2 is False  # OR IGNORE
    assert db.session_count() == 1


def test_pocs_upsert_dedup_and_confidence(db):
    status, row = db.upsert_poc(
        normalized_req_hash="h1", proto="http", ptype="http",
        src_ip="1.1.1.1", first_seen=1, last_seen=1, source_session_id="s1",
        template_path="out/templates/a.yaml", template_yaml="yaml", confidence=0.4,
    )
    assert status == "inserted"
    assert row["confidence"] == 0.4
    assert row["hit_count"] == 1
    assert row["status"] == "unverified"

    # 重复命中：hit_count+1、confidence+0.1、src_ip 追加
    status, row = db.upsert_poc(
        normalized_req_hash="h1", proto="http", ptype="http",
        src_ip="2.2.2.2", first_seen=1, last_seen=2, source_session_id="s2",
    )
    assert status == "updated"
    assert row["hit_count"] == 2
    assert row["confidence"] == 0.5
    assert json.loads(row["src_ips"]) == ["1.1.1.1", "2.2.2.2"]

    # UNIQUE 约束本身生效（直接 SQL 冲突）
    import pytest, sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        db.conn.execute(
            "INSERT INTO pocs (normalized_req_hash, proto, type) VALUES ('h1','http','http')"
        )
        db.conn.commit()


def test_pocs_confidence_cap(db):
    db.upsert_poc(
        normalized_req_hash="h9", proto="tcp", ptype="tcp", src_ip="1.1.1.1",
        first_seen=1, last_seen=1, source_session_id="s", confidence=0.95,
    )
    for _ in range(5):
        db.upsert_poc(
            normalized_req_hash="h9", proto="tcp", ptype="tcp", src_ip="1.1.1.1",
            first_seen=1, last_seen=1, source_session_id="s",
        )
    row = db.get_poc_by_hash("h9")
    assert row["confidence"] <= 1.0


def test_flow_insert(db):
    db.insert_flow(
        flow_id="f1", src_ip="1.1.1.1", ts_start=1, ts_end=2,
        ports_hit=[8000, 8022], conn_count=2, tool_guess="nuclei",
        tool_conf=0.8, behaviors=["port_scan"],
    )
    db.insert_flow(
        flow_id="f1", src_ip="1.1.1.1", ts_start=1, ts_end=2,
        ports_hit=[8000, 8022], conn_count=2, tool_guess="nuclei",
        tool_conf=0.8, behaviors=["port_scan"],
    )  # OR IGNORE
    assert db.flow_count() == 1
