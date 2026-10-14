#!/usr/bin/env python3
"""历史数据重解析：把 proto=generic 但实际是 HTTP 请求的会话重解析为 http。

背景：generic→HTTP 识别是修复后加的，此前的扫描（如 7001 端口的 WebLogic
wls-wsat 反序列化攻击）被当 generic 记录（parsed 丢失）。原始字节在
client_bytes 里，用解码器离线重解析并更新 sessions 表，
然后重跑 build 即可重建这些 POC。

用法: python scripts/reparse-http.py [--dry-run]
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "pipeline"))

from db import DB  # noqa: E402
from decoders.http import HTTPDecoder  # noqa: E402

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ",
                b"PATCH ", b"TRACE ", b"PROPFIND ", b"M-SEARCH ")


def main() -> None:
    dry = "--dry-run" in sys.argv
    db = DB()
    rows = db.conn.execute(
        "SELECT session_id, client_bytes FROM sessions WHERE proto = 'generic'"
    ).fetchall()

    dec = HTTPDecoder()
    fixed = 0
    for r in rows:
        cb = r["client_bytes"] or b""
        if not cb.startswith(HTTP_METHODS):
            continue
        try:
            parsed = dec.deep_parse(cb, b"")
        except Exception:
            continue
        if not parsed:
            continue
        parsed_json = json.dumps(parsed, ensure_ascii=False)
        if dry:
            print(f"[dry] {r['session_id'][:12]} -> http: "
                  f"{parsed.get('method')} {parsed.get('path', '')[:60]}")
        else:
            db.conn.execute(
                "UPDATE sessions SET proto = 'http', parsed_json = ? WHERE session_id = ?",
                (parsed_json, r["session_id"]),
            )
        fixed += 1

    if not dry:
        db.conn.commit()
    print(f"{'[dry-run] ' if dry else ''}重解析 {fixed} 条 generic→http 会话")


if __name__ == "__main__":
    main()
