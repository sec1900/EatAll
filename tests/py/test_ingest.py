"""ingest 单测：断点续传 / 单行容错 / 幂等。"""
import json

from db import DB, state_path
from fingerprint import FlowAggregator
from ingest import IngestState, run_once
from conftest import make_session, write_sessions


def _sessions(n=3, **over):
    out = []
    for i in range(n):
        s = make_session(
            client_bytes=f"GET /p{i} HTTP/1.1\r\nHost: t\r\n\r\n".encode(),
            server_bytes=f"HTTP/1.1 200 OK\r\n\r\npage{i}".encode(),
            ts_start=1785662000000 + i * 1000,
            **over,
        )
        out.append(s)
    return out


def test_ingest_basic(tmp_home, db):
    write_sessions(tmp_home, _sessions(3))
    agg = FlowAggregator(db)
    state = IngestState()
    n = run_once(db, agg, state)
    assert n == 3
    assert db.session_count() == 3
    # offset 已持久化
    saved = json.loads(state_path().read_text(encoding="utf-8"))
    assert saved["version"] == 1
    assert saved["offsets"]["sessions-20260802-09.jsonl"] > 0


def test_ingest_corrupt_line_and_partial_tail(tmp_home, db):
    path = write_sessions(tmp_home, _sessions(2))
    # 追加一行损坏 JSON（带 \n）+ 一行未完成（无 \n，模拟 Go 半行写入）
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"schema":1,"broken":\n')
        fh.write('{"schema":1,"ts_start":1785663000000,"partial":true,')
    agg = FlowAggregator(db)
    state = IngestState()
    n = run_once(db, agg, state)
    assert n == 2  # 仅两行完整有效行被消费
    assert db.session_count() == 2
    # 错误日志有 1 条损坏行记录
    err_log = tmp_home / "data" / "logs" / "ingest_errors.log"
    assert err_log.exists()
    assert "broken" in err_log.read_text(encoding="utf-8")
    # 半行未被消费：offset 停在最后完整行（损坏行之后、半行之前）
    saved = json.loads(state_path().read_text(encoding="utf-8"))
    offset = saved["offsets"]["sessions-20260802-09.jsonl"]
    raw = path.read_bytes()
    assert raw[offset - 1 : offset] == b"\n"
    assert raw[offset:].startswith(b'{"schema":1,"ts_start":1785663000000,"partial"')
    # 补全半行后下一轮消费
    with path.open("a", encoding="utf-8") as fh:
        fh.write('"x":1}\n')
    n2 = run_once(db, agg, state)
    assert n2 == 1
    assert db.session_count() == 3


def test_ingest_no_duplicate_second_run(tmp_home, db):
    write_sessions(tmp_home, _sessions(3))
    agg = FlowAggregator(db)
    state = IngestState()
    assert run_once(db, agg, state) == 3
    assert run_once(db, agg, state) == 0  # 无新行
    assert db.session_count() == 3


def test_ingest_crash_restart_resume(tmp_home, db):
    """kill 模拟：丢弃内存状态，从磁盘 state 恢复 → 不丢行不重读。"""
    write_sessions(tmp_home, _sessions(2))
    agg = FlowAggregator(db)
    state = IngestState()
    run_once(db, agg, state)
    # 模拟进程被杀：新 DB / 新聚合器 / 新状态对象（从磁盘加载）
    db.close()
    db2 = DB()
    agg2 = FlowAggregator(db2)
    state2 = IngestState()
    n = run_once(db2, agg2, state2)
    assert n == 0  # 没有重读
    assert db2.session_count() == 2
    db2.close()


def test_ingest_hour_rotation_new_file(tmp_home, db):
    write_sessions(tmp_home, _sessions(2), fname="sessions-20260802-09.jsonl")
    write_sessions(tmp_home, _sessions(1), fname="sessions-20260802-10.jsonl")
    agg = FlowAggregator(db)
    state = IngestState()
    assert run_once(db, agg, state) == 3
    saved = json.loads(state_path().read_text(encoding="utf-8"))
    assert "sessions-20260802-10.jsonl" in saved["offsets"]


def test_ingest_state_corrupt_reset(tmp_home, db):
    write_sessions(tmp_home, _sessions(2))
    state_path().write_text("{corrupt!!!", encoding="utf-8")
    agg = FlowAggregator(db)
    state = IngestState()
    n = run_once(db, agg, state)
    assert n == 2  # 状态损坏 → 从头 ingest（入库幂等吸收）
    assert db.session_count() == 2


def test_ingest_session_id_empty(tmp_home, db):
    """Go 侧 session_id 为空的兼容：确定性主键，幂等。"""
    s = make_session(session_id="")
    write_sessions(tmp_home, [s])
    agg = FlowAggregator(db)
    state = IngestState()
    run_once(db, agg, state)
    write_sessions(tmp_home, [s])  # 同内容再次出现
    state2 = IngestState()
    # 重置 offset 模拟重读场景
    state2.data["offsets"] = {}
    run_once(db, agg, state2)
    assert db.session_count() == 1  # 幂等


def test_flows_written(tmp_home, db):
    write_sessions(tmp_home, _sessions(3))
    agg = FlowAggregator(db)
    run_once(db, agg)
    agg.close_all()
    assert db.flow_count() == 1


def test_ingest_ignore_loopback(tmp_home, db, monkeypatch):
    """EATALL_IGNORE_LOOPBACK=1 时回环流量跳过入库，外网正常入库。"""
    import importlib
    import ingest as ingest_mod

    write_sessions(
        tmp_home,
        _sessions(2, src_ip="127.0.0.1") + _sessions(1, src_ip="192.168.1.5"),
    )
    monkeypatch.setenv("EATALL_IGNORE_LOOPBACK", "1")
    ingest_mod = importlib.reload(ingest_mod)
    state = IngestState()
    n = ingest_mod.run_once(db, FlowAggregator(db), state)
    assert n == 3  # 行都消费（跳过也算），offset 正常推进
    assert db.session_count() == 1  # 仅外网入库
    # 恢复默认（回环保留），避免影响后续用例
    monkeypatch.setenv("EATALL_IGNORE_LOOPBACK", "0")
    importlib.reload(ingest_mod)
