"""EatAll 分析管道入口。

长驻编排：
- run（默认）：ingest 2s 轮询 + 每轮 build + 周期扫描事件计算，崩溃可断点续传
- ingest：仅轮询入库
- fingerprint：ingest 一次 + 关闭 idle 流 → flows 表
- build：ingest 一次 + 关闭全部流 + 全量重建模板
- scan：扫描事件检测 + 相邻 diff + 库快照（版本控制）
- dashboard：展示界面（默认 0.0.0.0:9090，局域网可访问）

用法：
    python pipeline/main.py run --validate
    python pipeline/main.py build --once
    python pipeline/main.py ingest --once
    python pipeline/main.py scan
    python pipeline/main.py dashboard --port 9090
"""
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

from db import DB, data_root, logs_dir
from fingerprint import FlowAggregator
from ingest import IngestState, POLL_INTERVAL_SEC, ingest_loop, run_once
from poc_builder import build_all
from scans import compute_scans

# 每 N 轮 run 循环执行一次 build
BUILD_EVERY = 1
# 每 N 轮 run 循环执行一次扫描事件计算（版本控制）
SCANS_EVERY = 15

logger = logging.getLogger("eatall.main")


def _setup_logging() -> None:
    logs_dir().mkdir(parents=True, exist_ok=True)
    # Windows GBK 控制台下强制 UTF-8，避免中文日志乱码
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    root = logging.getLogger("eatall")
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    fh = logging.FileHandler(logs_dir() / "pipeline.log", encoding="utf-8")
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    root.addHandler(fh)
    root.addHandler(ch)


def _nuclei_bin() -> str | None:
    """nuclei 可执行文件：环境变量优先，其次 repo bin/。"""
    env = os.environ.get("NUCLEI_BIN")
    if env:
        return env
    cand = data_root() / "bin" / ("nuclei.exe" if os.name == "nt" else "nuclei")
    return str(cand) if cand.exists() else None


def _run_daemon(args) -> int:
    """长驻循环：ingest 2s 轮询 + 周期性 build + 周期扫描事件计算。
    SIGINT/SIGTERM 优雅退出。"""
    stop = threading.Event()

    def _signal_handler(signum, frame):
        logger.info("收到信号 %s，优雅退出…", signum)
        stop.set()

    signal.signal(signal.SIGINT, _signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _signal_handler)

    db = DB()
    state = IngestState()
    agg = FlowAggregator(db)
    nuclei = _nuclei_bin() if args.validate else None

    try:
        cycle = 0
        while not stop.is_set():
            n = run_once(db, agg, state)
            agg.close_idle()
            if n:
                logger.info("本轮 ingest %d 行", n)
            if cycle % BUILD_EVERY == 0:
                # 增量构建：只处理水位之后的新会话（全量重建会虚增 hit_count）
                summary = build_all(
                    db, validate=args.validate, nuclei_bin=nuclei,
                    since_rowid=state.build_since_rowid(),
                )
                if summary["max_rowid_processed"]:
                    state.build_mark_rowid(summary["max_rowid_processed"])
                    state.save()
                if summary["pocs_inserted"] or summary["pocs_updated"]:
                    logger.info(
                        "build: emitted=%d inserted=%d updated=%d skipped=%d errors=%d (%.0fms)",
                        summary["templates_emitted"], summary["pocs_inserted"],
                        summary["pocs_updated"], summary["skipped"],
                        len(summary["errors"]), summary["elapsed_ms"],
                    )
                # 版本控制：扫描事件检测 + 相邻 diff + 库快照（节流）
                if cycle % SCANS_EVERY == 0:
                    s = compute_scans(db)
                    if s["scans_written"]:
                        logger.info(
                            "scans: episodes=%d written=%d pocs=%d lib=%s",
                            s["episodes"], s["scans_written"], s["poc_count"], s["lib_hash"],
                        )
            cycle += 1
            stop.wait(args.interval)
    finally:
        agg.close_all()
        state.save()
        db.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EatAll 分析管道")
    parser.add_argument(
        "command", nargs="?", default="run",
        choices=["run", "ingest", "fingerprint", "build", "scan", "dashboard"],
        help="子命令（默认 run）",
    )
    parser.add_argument("--once", action="store_true", help="只执行一轮（调试/CI）")
    parser.add_argument("--interval", type=float, default=POLL_INTERVAL_SEC,
                        help="轮询间隔秒（默认 2）")
    parser.add_argument("--validate", action="store_true",
                        help="模板落盘后跑 nuclei -validate 门禁")
    parser.add_argument("--host", default="0.0.0.0", help="dashboard 绑定地址（默认 0.0.0.0）")
    parser.add_argument("--port", type=int, default=9090, help="dashboard 端口（默认 9090）")
    args = parser.parse_args(argv)

    _setup_logging()

    if args.command == "run" and not args.once:
        return _run_daemon(args)

    db = DB()
    state = IngestState()
    agg = FlowAggregator(db)
    try:
        if args.command == "dashboard":
            from dashboard.server import serve
            serve(host=args.host, port=args.port, db=db)
            return 0
        if args.command == "scan":
            # 版本控制：扫描事件 diff + 库快照（不需要 ingest/build）
            summary = compute_scans(db)
            logger.info(
                "scan 完成: episodes=%d scans_written=%d pocs=%d lib=%s",
                summary["episodes"], summary["scans_written"],
                summary["poc_count"], summary["lib_hash"],
            )
            return 0
        n = ingest_loop(db, agg, interval=args.interval, once=True)
        logger.info("ingest 完成，处理 %d 行", n)
        if args.command == "fingerprint":
            agg.close_all()
            logger.info("fingerprint 完成：flows=%d", db.flow_count())
            return 0
        if args.command == "build" or (args.command == "run" and args.once):
            agg.close_all()
            summary = build_all(db, validate=args.validate,
                                nuclei_bin=_nuclei_bin() if args.validate else None,
                                since_rowid=state.build_since_rowid())
            if summary["max_rowid_processed"]:
                state.build_mark_rowid(summary["max_rowid_processed"])
                state.save()
            logger.info(
                "build 完成: sessions=%d emitted=%d inserted=%d updated=%d skipped=%d errors=%d (%.0fms)",
                summary["sessions_scanned"], summary["templates_emitted"],
                summary["pocs_inserted"], summary["pocs_updated"],
                summary["skipped"], len(summary["errors"]), summary["elapsed_ms"],
            )
            for err in summary["errors"][:10]:
                logger.error("build error: %s", err)
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
