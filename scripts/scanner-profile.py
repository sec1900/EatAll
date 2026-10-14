#!/usr/bin/env python3
"""扫描器行为画像：从捕获流量逆向对方扫描机制。

分析维度：
1. 时间线还原（阶段划分：端口探测→服务识别→POC→验证）
2. 并发度与节奏（每秒连接数、轮次间隔）
3. 连接深度（每端口连接数 → 深测判定）
4. 验证机制推断（payload 后是否跟进二次请求 = 响应驱动）
5. 带外验证检测（DNS/HTTP 回调域名）
6. POC 库特征（同路径 payload 变体数）
"""
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "pipeline"))
from db import DB

SRC = "192.168.166.120"
T0 = 1785677750000  # 22:25:50 起


def main() -> None:
    db = DB()
    rows = db.conn.execute(
        """SELECT ts_start, dst_port, proto, parsed_json, length(client_bytes) clen
           FROM sessions WHERE src_ip=? AND ts_start >= ? ORDER BY ts_start""",
        (SRC, T0),
    ).fetchall()
    print(f"样本: {len(rows)} 条会话（{time.strftime('%H:%M', time.localtime(rows[0]['ts_start']/1000))} 起）\n")

    # ---- 1. 时间线：按 30s 窗口聚合连接数，还原阶段 ----
    windows = Counter()
    for r in rows:
        windows[r['ts_start'] // 30000] += 1
    print("=== 1. 扫描节奏（30s 窗口连接数）===")
    seq = sorted(windows.items())
    for w, n in seq[:8]:
        print(f"  {time.strftime('%H:%M:%S', time.localtime(w*30000/1000))}: {n} 连接")
    print(f"  ... 共 {len(seq)} 个窗口，峰值 {max(windows.values())}/30s")

    # ---- 2. 连接深度分布 ----
    depth = Counter()
    for r in rows:
        depth[r['dst_port']] += 1
    d1 = sum(1 for v in depth.values() if v == 1)
    d2 = sum(1 for v in depth.values() if 2 <= v <= 3)
    d4 = sum(1 for v in depth.values() if v >= 4)
    print(f"\n=== 2. 端口连接深度 ===\n  1次: {d1} 端口 | 2-3次: {d2} | 4+次(深测): {d4}")

    # ---- 3. 验证机制：同一路径 2 次以上请求（响应驱动 = 二次确认）----
    path_repeat = Counter()
    path_ports = defaultdict(set)
    for r in rows:
        p = json.loads(r['parsed_json'] or '{}')
        path = f"{p.get('method','')} {p.get('path','')}"
        if path.strip():
            path_repeat[path] += 1
            path_ports[path].add(r['dst_port'])
    multi = {k: v for k, v in path_repeat.items() if v >= 2 and len(path_ports[k]) == 1}
    print(f"\n=== 3. 验证机制 ===\n  同一路径在同端口重复请求(响应驱动二次确认): {len(multi)} 个路径")
    for k, v in sorted(multi.items(), key=lambda x: -x[1])[:5]:
        print(f"    ×{v}  {k[:60]}")

    # ---- 4. 带外验证检测 ----
    print("\n=== 4. 带外验证（DNS 回调）===")
    dns_rows = db.conn.execute(
        """SELECT parsed_json FROM sessions WHERE src_ip=? AND ts_start >= ? AND proto='dns'""",
        (SRC, T0),
    ).fetchall()
    oob_domains = set()
    suspicious = ["dnslog", "ceye", "oast", "burpcollaborator", "interactsh",
                  "dnslog.cn", "eye.io", "bugscan", "tu4.org", "1u.ms", "dnsbin"]
    for r in dns_rows:
        p = json.loads(r['parsed_json'] or '{}')
        for q in p.get('queries', []):
            qn = q.get('qname', '')
            for s in suspicious:
                if s in qn.lower():
                    oob_domains.add(qn)
    print(f"  带外域名命中: {len(oob_domains)} 个")
    for d in list(oob_domains)[:8]:
        print(f"    {d}")
    if not oob_domains:
        print("  未发现 dnslog/ceye 类域名（对方验证机制可能非带外型）")

    # ---- 5. POC 变体 ----
    print("\n=== 5. POC 库特征 ===")
    # 攻击路径变体数（同 base path 不同 payload）
    base = Counter()
    for r in rows:
        p = json.loads(r['parsed_json'] or '{}')
        path = p.get('path', '')
        if path:
            base[path.split('?')[0]] += 1
    top = sorted(base.items(), key=lambda x: -x[1])[:8]
    for path, n in top:
        print(f"    ×{n:3d}  {path[:55]}")


if __name__ == "__main__":
    main()
