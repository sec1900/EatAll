#!/usr/bin/env python3
"""用吸收的 POC 库对指定目标发起攻击（反向输出）。

⚠️ 仅限你拥有或已获授权的目标（自有资产 / 渗透测试授权范围）。
未授权攻击他人资产违法——请自行确认目标授权。

用法:
    python scripts/attack.py -t http://127.0.0.1:8081                # 全部模板
    python scripts/attack.py -t http://192.168.x.x -e rce            # 仅 RCE 类
    python scripts/attack.py -t http://x -e sql_injection -v weblogic # 组合筛选
    python scripts/attack.py -t http://x -l targets.txt -n 200       # 批量+限量
    python scripts/attack.py -t http://x --dry-run                   # 只列将使用的模板

攻击目标前请确认：目标属于你 / 你有书面授权。本工具仅整合自捕获的 POC。
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline"))
from classify import classify  # noqa: E402

TEMPLATES = ROOT / "out" / "templates"
NUCLEI = ROOT / "bin" / ("nuclei.exe" if sys.platform == "win32" else "nuclei")

# 模板 → 来源端口映射（pocs.source_session_ids → sessions.dst_port）
_PORT_CACHE: dict[str, set[int]] | None = None


def _port_map() -> dict[str, set[int]]:
    """模板文件名 → 捕获来源端口集合。"""
    global _PORT_CACHE
    if _PORT_CACHE is not None:
        return _PORT_CACHE
    import json
    import sqlite3
    _PORT_CACHE = {}
    db_path = ROOT / "data" / "eatall.db"
    if not db_path.exists():
        return _PORT_CACHE
    conn = sqlite3.connect(str(db_path))
    try:
        pocs = conn.execute(
            "SELECT template_path, source_session_ids FROM pocs"
        ).fetchall()
        for path, sids_json in pocs:
            fname = Path(path or "").name  # 兼容 / 与 \ 分隔
            if not fname:
                continue
            try:
                sids = json.loads(sids_json or "[]")
            except json.JSONDecodeError:
                continue
            if not sids:
                continue
            ports = set()
            for i in range(0, len(sids), 800):
                chunk = sids[i:i + 800]
                rows = conn.execute(
                    f"SELECT DISTINCT dst_port FROM sessions WHERE session_id IN ({','.join('?' * len(chunk))})",
                    chunk,
                ).fetchall()
                ports.update(r[0] for r in rows if r[0])
            _PORT_CACHE[fname] = ports
    finally:
        conn.close()
    return _PORT_CACHE


def pick_templates(exploit: str | None, vendor: str | None,
                   from_port: int | None, limit: int) -> list[Path]:
    """按利用类型 + 厂商 + 来源端口筛选模板。"""
    port_map = _port_map()
    picked = []
    for f in sorted(TEMPLATES.glob("poc-*.yaml")):
        if vendor and vendor not in f.name:
            continue
        if from_port:
            ports = port_map.get(f.name, set())
            if from_port not in ports:
                continue
        if exploit:
            kind = classify(f.read_text(encoding="utf-8", errors="replace"))["kind"]
            if kind != exploit:
                continue
        picked.append(f)
        if len(picked) >= limit:
            break
    return picked


def main() -> int:
    parser = argparse.ArgumentParser(description="用吸收的 POC 库攻击目标（授权范围内）")
    parser.add_argument("-t", "--target", help="目标 URL 或 IP")
    parser.add_argument("-l", "--targets-file", help="批量目标文件")
    parser.add_argument("-e", "--exploit", choices=[
        "rce", "sql_injection", "deserialization", "expression", "traversal",
        "xss", "ssrf", "brute", "obfuscation", "unknown", "probe"],
        help="仅打指定利用类型")
    parser.add_argument("-v", "--vendor", help="仅打指定厂商（文件名含关键词，如 weblogic/tomcat/struts2）")
    parser.add_argument("-p", "--from-port", type=int,
                        help="仅打从该来源端口吸收的 POC（如 7001 = 从 WebLogic 7001 捕获的模板）")
    parser.add_argument("-n", "--limit", type=int, default=200, help="模板数量上限")
    parser.add_argument("--dry-run", action="store_true", help="只列出将使用的模板不执行")
    args = parser.parse_args()

    if not args.target and not args.targets_file:
        parser.error("需要 -t 目标或 -l 批量目标文件")

    picked = pick_templates(args.exploit, args.vendor, args.from_port, args.limit)
    print(f"选择模板: {len(picked)} 个（筛选: exploit={args.exploit or '全部'} "
          f"vendor={args.vendor or '全部'} from_port={args.from_port or '全部'}）")
    if not picked:
        print("无匹配模板")
        return 1
    if args.dry_run:
        for f in picked[:30]:
            print(f"  {f.name}")
        if len(picked) > 30:
            print(f"  ... 共 {len(picked)} 个")
        return 0

    # 复制到临时目录（只包含选中模板）
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td) / "pocs"
        tdir.mkdir()
        for f in picked:
            shutil.copy2(f, tdir / f.name)
        cmd = [str(NUCLEI), "-t", str(tdir), "-o", str(ROOT / "data" / "attack_result.txt")]
        if args.target:
            cmd += ["-u", args.target]
        if args.targets_file:
            cmd += ["-l", args.targets_file]
        print("执行: " + " ".join(cmd))
        r = subprocess.run(cmd)
        print(f"\nnuclei 退出码: {r.returncode}")
        result = ROOT / "data" / "attack_result.txt"
        if result.exists():
            lines = result.read_text(encoding="utf-8", errors="replace").strip().splitlines()
            print(f"命中结果: {len(lines)} 条（data/attack_result.txt）")
            for line in lines[:20]:
                print(f"  {line[:150]}")
        return r.returncode


if __name__ == "__main__":
    main()
