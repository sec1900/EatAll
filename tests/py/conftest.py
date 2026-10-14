"""pytest 公共设施：路径注入、临时 EATALL_HOME、会话构造器。"""
from __future__ import annotations

import base64
import json
import os
import sys
import uuid
from pathlib import Path

import pytest

# 把 pipeline/ 加入 sys.path（main.py 以脚本方式运行时 sys.path[0] 即该目录）
TESTS_PY = Path(__file__).resolve().parent
PIPELINE = TESTS_PY.parents[1] / "pipeline"
if str(PIPELINE) not in sys.path:
    sys.path.insert(0, str(PIPELINE))

from db import DB, state_path  # noqa: E402


@pytest.fixture()
def tmp_home(tmp_path, monkeypatch):
    """EATALL_HOME 指向临时目录：DB/状态/日志全部隔离。"""
    monkeypatch.setenv("EATALL_HOME", str(tmp_path))
    (tmp_path / "data" / "sessions").mkdir(parents=True)
    (tmp_path / "data" / "logs").mkdir(parents=True)
    return tmp_path


@pytest.fixture()
def db(tmp_home):
    db = DB()
    yield db
    db.close()


def make_session(**over):
    """构造一条与 Go JSONL 同构的会话 dict。"""
    client = over.pop("client_bytes", b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
    server = over.pop("server_bytes", b"HTTP/1.1 200 OK\r\n\r\nok")
    parsed = over.pop("parsed", None)
    if parsed is None and over.get("proto_conf", "http") in ("http", "tls-http"):
        parsed = {"method": "GET", "path": "/", "headers": {"Host": "t"}, "body_b64": ""}
    base = {
        "schema": 1,
        "session_id": uuid.uuid4().hex,
        "ts_start": 1785662000000,
        "ts_end": 1785662000100,
        "src_ip": "127.0.0.1",
        "src_port": 54321,
        "dst_ip": "127.0.0.1",
        "dst_port": 8080,
        "transport": "tcp",
        "proto_conf": "http",
        "client_bytes_b64": base64.b64encode(client).decode(),
        "server_bytes_b64": base64.b64encode(server).decode(),
        "client_len": len(client),
        "server_len": len(server),
        "duration_ms": 100,
        "banner": "",
        "parse_status": "ok",
        "parsed": parsed,
        "close_reason": "client_closed",
        "tls": {},
    }
    base.update(over)
    return base


def write_sessions(tmp_home, sessions: list[dict], fname: str = "sessions-20260802-09.jsonl"):
    """把会话 dict 列表写入 data/sessions/（每次追加，模拟 Go writer）。"""
    p = tmp_home / "data" / "sessions" / fname
    with p.open("a", encoding="utf-8") as fh:
        for s in sessions:
            fh.write(json.dumps(s) + "\n")
    return p


@pytest.fixture()
def sess_factory():
    return make_session


@pytest.fixture()
def writer(tmp_home):
    return lambda sessions, fname="sessions-20260802-09.jsonl": write_sessions(
        tmp_home, sessions, fname
    )
