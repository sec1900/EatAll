"""ingest：轮询 data/sessions/，offset 断点续传，单行容错。

设计要点：
- 只消费完整行（以 \\n 结尾）：Go 侧 64KB bufio 缓冲可能导致文件尾部存在
  半行，半行留给下一轮 poll 重读——崩溃重启不丢行不重读
- 单行 JSON/解码失败 → data/logs/ingest_errors.log，不中断
- offset 持久化到 data/.ingest_state.json（tmp+rename 原子写）
- 会话入库幂等：session_id 由内容确定性生成，重复 ingest 走 OR IGNORE
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from db import DB, logs_dir, sessions_dir, state_path
from decoders import decode_session
from fingerprint import FlowAggregator

# 回环流量（本机自测 curl/脚本）不入库：生产部署（漏扫在独立 IP）时设 1，
# 避免本机验证噪音污染统计；默认关 = 保留 127.0.0.1 测试通道
IGNORE_LOOPBACK = os.environ.get("EATALL_IGNORE_LOOPBACK", "0") == "1"


def _is_loopback(ip: str) -> bool:
    return ip == "::1" or ip == "127.0.0.1" or ip.startswith("127.")

STATE_VERSION = 1
POLL_INTERVAL_SEC = 2.0
# 错误日志轮转阈值
ERROR_LOG_MAX_BYTES = 5 * 1024 * 1024

logger = logging.getLogger("eatall.ingest")


class IngestState:
    """offset 断点续传状态。"""

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else state_path()
        self.data: dict = {"version": STATE_VERSION, "offsets": {}, "last_poll_ms": 0}
        self.load()

    def load(self) -> None:
        try:
            if self.path.exists():
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if raw.get("version") == STATE_VERSION:
                    self.data = raw
        except Exception as exc:
            # 状态文件损坏：从头开始（入库幂等，重复行被 OR IGNORE 吸收）
            logger.warning("ingest state 损坏，重置: %s", exc)

    def save(self) -> None:
        self.data["last_poll_ms"] = int(time.time() * 1000)
        tmp = self.path.with_name(self.path.name + f".tmp{os.getpid()}")
        try:
            tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
            os.replace(tmp, self.path)
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def offset_for(self, fname: str) -> int:
        return int(self.data.get("offsets", {}).get(fname, 0))

    def mark(self, fname: str, offset: int) -> None:
        self.data.setdefault("offsets", {})[fname] = offset

    def prune(self, keep_sec: float = 86400.0) -> None:
        """清理已不存在文件的 offset 记录（防状态文件无限增长）。"""
        now = time.time()
        stale = []
        for fname in self.data.get("offsets", {}):
            if not (sessions_dir() / fname).exists():
                # 保留 24h 防止轮转间隙误删
                if now - os.path.getmtime(state_path()) > keep_sec:
                    stale.append(fname)
        for fname in stale:
            self.data["offsets"].pop(fname, None)

    # ---------- build 增量水位 ----------

    def build_since_rowid(self) -> int:
        """上次 build 已处理的最大会话 rowid（增量构建水位，入库顺序）。"""
        return int(self.data.get("last_build_rowid", 0))

    def build_mark_rowid(self, rowid: int) -> None:
        """推进 build 水位（≥ 传入值）。"""
        self.data["last_build_rowid"] = max(
            int(self.data.get("last_build_rowid", 0)), int(rowid)
        )


def session_key(session: dict) -> str:
    """会话主键：Go 侧 session_id 为空时由内容确定性生成（保证幂等）。"""
    sid = session.get("session_id")
    if sid:
        return str(sid)
    raw = "|".join(
        str(session.get(k, ""))
        for k in ("ts_start", "src_ip", "src_port", "dst_port", "proto_conf", "client_len", "server_len")
    )
    return "auto-" + hashlib.sha256(raw.encode()).hexdigest()[:24]


def _rotate_error_log(path: Path) -> None:
    try:
        if path.exists() and path.stat().st_size > ERROR_LOG_MAX_BYTES:
            os.replace(path, path.with_name(path.name + ".1"))
    except OSError:
        pass


def _log_error(fname: str, offset: int, line: str, exc: Exception) -> None:
    logs_dir().mkdir(parents=True, exist_ok=True)
    path = logs_dir() / "ingest_errors.log"
    _rotate_error_log(path)
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(
                f"[{int(time.time()*1000)}] {fname} offset~{offset} "
                f"error={exc!r}\nline={line[:500]}\n\n"
            )
    except OSError:
        logger.error("无法写入 ingest_errors.log: %s", exc)


def _ingest_one(db: DB, agg: FlowAggregator, fname: str, offset: int, line: str) -> None:
    """处理单行：解码 → 流聚合 → 入库。任何异常向上抛（由调用方记错误日志）。"""
    session = json.loads(line)
    if not isinstance(session, dict):
        raise ValueError("JSON line is not an object")

    parsed, status = decode_session(session)

    key = session_key(session)
    ts_start = int(session.get("ts_start") or 0)
    ts_end = session.get("ts_end")
    ts_end = int(ts_end) if ts_end is not None else ts_start
    src_ip = str(session.get("src_ip") or "")
    if IGNORE_LOOPBACK and _is_loopback(src_ip):
        return  # 回环测试流量跳过（行仍按已读推进，不落库、不聚合）
    src_port = session.get("src_port")
    dst_port = session.get("dst_port")
    proto = str(session.get("proto_conf") or "generic")

    client = base64.b64decode(session.get("client_bytes_b64") or "")
    server = base64.b64decode(session.get("server_bytes_b64") or "")

    flow_id = agg.add(session, parsed)

    db.insert_session(
        session_id=key,
        ts_start=ts_start,
        ts_end=ts_end,
        src_ip=src_ip,
        src_port=int(src_port) if src_port is not None else None,
        dst_ip=session.get("dst_ip"),
        dst_port=int(dst_port) if dst_port is not None else None,
        transport=str(session.get("transport") or ""),
        proto=proto,
        banner=str(session.get("banner") or ""),
        client_bytes=client,
        server_bytes=server,
        parse_status=status,
        parsed_json=json.dumps(parsed, ensure_ascii=False),
        close_reason=str(session.get("close_reason") or ""),
        flow_id=flow_id,
    )


def run_once(db: DB, agg: FlowAggregator, state: Optional[IngestState] = None) -> int:
    """单轮轮询：处理所有 session 文件的完整行，保存 offset 状态。

    返回新处理的行数。
    """
    state = state or IngestState()
    sessions_dir().mkdir(parents=True, exist_ok=True)
    files = sorted(sessions_dir().glob("sessions-*.jsonl"))
    processed = 0

    for path in files:
        fname = path.name
        offset = state.offset_for(fname)
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size < offset:
            logger.warning("%s 变短（轮转/截断）: offset %d -> 0", fname, offset)
            offset = 0
        if size == offset:
            continue
        with path.open("rb") as fh:
            fh.seek(offset)
            raw = fh.read()
        last_nl = raw.rfind(b"\n")
        if last_nl < 0:
            continue  # 尚无完整行（半行写入），下轮重读
        complete = raw[: last_nl + 1]
        if not complete:
            continue

        line_offset = offset
        for line in complete.split(b"\n"):
            if not line:
                line_offset += 1
                continue
            try:
                _ingest_one(db, agg, fname, line_offset, line)
                processed += 1
            except Exception as exc:
                _log_error(fname, line_offset, line.decode("utf-8", "replace"), exc)
            line_offset += len(line) + 1

        state.mark(fname, offset + len(complete))

    state.prune()
    state.save()
    return processed


def ingest_loop(
    db: DB,
    agg: FlowAggregator,
    interval: float = POLL_INTERVAL_SEC,
    once: bool = False,
    stop_event: Optional[object] = None,
) -> int:
    """长驻轮询循环；once=True 时只跑一轮。返回处理的总行数。"""
    total = 0
    while True:
        n = run_once(db, agg)
        total += n
        if once:
            break
        if stop_event is not None and stop_event.is_set():
            break
        time.sleep(interval)
    return total
