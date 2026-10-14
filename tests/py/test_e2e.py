"""端到端：合成会话 → ingest → build → 合法 YAML（可选 nuclei 校验）。"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from db import DB
from fingerprint import FlowAggregator
from ingest import run_once
from poc_builder import build_all
from conftest import make_session, write_sessions


def _nuclei_bin():
    env = os.environ.get("NUCLEI_BIN")
    if env:
        return env
    cand = Path(__file__).resolve().parents[2] / "bin" / "nuclei.exe"
    return str(cand) if cand.exists() else None


def _synthetic_attack():
    """模拟 sqlmap 攻击 + ssh 扫描 + dns 探测。"""
    sessions = []
    for i, ip in enumerate(("10.1.1.1", "10.1.1.2")):
        client = b"GET /index.php?id=1' AND sleep(3)-- - HTTP/1.1\r\nUser-Agent: sqlmap/1.8#stable\r\nHost: t\r\n\r\n"
        server = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<html><title>ThinkPHP</title></html>"
        sessions.append(make_session(
            client_bytes=client, server_bytes=server,
            parsed={"method": "GET", "path": "/index.php?id=1' AND sleep(3)-- -",
                    "headers": {"User-Agent": "sqlmap/1.8#stable", "Host": "t"},
                    "body_b64": "", "req_count": 1},
            src_ip=ip, ts_start=1785662000000 + i * 2000,
        ))
    sessions.append(make_session(
        proto_conf="ssh", dst_port=8022, src_ip="10.1.1.3",
        client_bytes=b"SSH-2.0-OpenSSH_8.9\r\n",
        server_bytes=b"SSH-2.0-OpenSSH_7.4\r\n\x00\x00\x00\xd0\x08\x00\x00\x00\x00",
        parsed=None, parse_status="ok",
    ))
    return sessions


def test_e2e_synthetic_pipeline(tmp_home):
    write_sessions(tmp_home, _synthetic_attack())
    db = DB()
    agg = FlowAggregator(db)
    run_once(db, agg)
    summary = build_all(db)
    assert summary["pocs_inserted"] == 2
    assert summary["errors"] == []

    templates = sorted((tmp_home / "out" / "templates").glob("poc-*.yaml"))
    assert len(templates) == 2

    # 全部模板可被 yaml 解析，且含 info.id / 动态值引号
    for t in templates:
        loaded = yaml.safe_load(t.read_text(encoding="utf-8"))
        assert loaded["id"] == t.stem
        assert loaded["info"]["author"] == "eatall-pipeline"
        assert loaded["info"]["severity"] in ("critical", "high", "low")

    # sqlmap 请求模板 severity=critical（sleep(）
    http_tpl = [t for t in templates if "poc-http-" in t.name][0]
    loaded = yaml.safe_load(http_tpl.read_text(encoding="utf-8"))
    assert loaded["info"]["severity"] == "critical"

    # flows 已落库且带指纹/行为
    agg.close_all()
    assert db.flow_count() >= 2
    db.close()


@pytest.mark.skipif(not _nuclei_bin(), reason="nuclei 未安装")
def test_e2e_nuclei_validate(tmp_home):
    """真实 nuclei -validate 门禁（安装则执行）。"""
    write_sessions(tmp_home, _synthetic_attack())
    db = DB()
    agg = FlowAggregator(db)
    run_once(db, agg)
    nuclei = _nuclei_bin()
    summary = build_all(db, validate=True, nuclei_bin=nuclei)
    assert summary["errors"] == []
    assert summary["pocs_inserted"] == 2
    # 兜底：对 out/templates 整目录再验证一遍
    proc = subprocess.run(
        [nuclei, "-validate", "-t", str(tmp_home / "out" / "templates")],
        capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, proc.stdout[-800:] + proc.stderr[-800:]
    db.close()
