#!/usr/bin/env python3
"""自研漏扫：吸收的 POC 库 → 完整扫描编排。

流程: 端口探测 → 服务识别 → POC 自动匹配 → nuclei 执行 → 汇总报告

⚠️ 仅限你拥有或已获授权的目标。未授权扫描/攻击他人资产违法。

用法:
    python scripts/scanner.py -t 192.168.1.100                  # 全端口自动
    python scripts/scanner.py -t 192.168.1.100 -p 21,22,80,443  # 指定端口
    python scripts/scanner.py -t http://目标.com -e rce          # 仅 RCE
    python scripts/scanner.py -l targets.txt                     # 批量目标
    python scripts/scanner.py -t 192.168.1.100 -n 300            # 限制 POC 数
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline"))
sys.path.insert(0, str(ROOT / "scripts"))
from classify import classify  # noqa: E402
from attack import _port_map  # noqa: E402

NUCLEI = ROOT / "bin" / ("nuclei.exe" if sys.platform == "win32" else "nuclei")
TEMPLATES = ROOT / "out" / "templates"

# 常见端口 → 服务名（POC 匹配辅助）
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 873: "rsync",
    1080: "socks", 1433: "mssql", 2181: "zookeeper", 2222: "ssh",
    2375: "docker", 3000: "grafana", 3128: "squid", 3306: "mysql",
    4848: "glassfish", 5060: "sip", 5432: "postgres", 5900: "vnc",
    6379: "redis", 7001: "weblogic", 7002: "weblogic", 7003: "weblogic",
    7547: "tr069", 8000: "http", 8008: "http", 8009: "ajp", 8080: "http",
    8081: "http", 8082: "nginx", 8083: "apache", 8085: "tomcat",
    8086: "tomcat", 8087: "weblogic", 8088: "jboss", 8089: "iis",
    8443: "https", 8888: "http", 8983: "solr", 9000: "http", 9090: "http",
    9200: "elasticsearch", 9418: "git", 10250: "kubelet", 11211: "memcached",
    27017: "mongodb", 49152: "rpc",
}


def port_scan(host: str, ports: list[int] | None, timeout: float = 1.0) -> list[int]:
    """TCP connect 端口快扫（并发 200）。"""
    if ports is None:
        ports = sorted(COMMON_SERVICES.keys()) + list(range(1, 1024))
        ports = sorted(set(p for p in ports if p <= 65535))
    open_ports = []

    def probe(p: int) -> int | None:
        try:
            s = socket.create_connection((host, p), timeout=timeout)
            s.close()
            return p
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
        for result in ex.map(probe, ports):
            if result:
                open_ports.append(result)
    return sorted(open_ports)


def service_probe(host: str, port: int, timeout: float = 2.0) -> str:
    """轻量服务识别：HTTP 探测优先，回退端口号推断。"""
    svc = COMMON_SERVICES.get(port, "unknown")
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        if svc in ("http", "https", "tomcat", "nginx", "apache", "weblogic", "jboss",
                   "iis", "solr", "elasticsearch", "grafana", "docker", "kubelet"):
            s.sendall(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
            try:
                resp = s.recv(512).decode("utf-8", "replace").lower()
            except Exception:
                resp = ""
            if "server:" in resp:
                for line in resp.split("\r\n"):
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()[:40]
        elif svc == "ssh":
            s.sendall(b"SSH-2.0-probe\r\n")
            try:
                banner = s.recv(100).decode("utf-8", "replace").strip()
                if banner.startswith("SSH-"):
                    return banner[:40]
            except Exception:
                pass
        elif svc in ("ftp", "smtp", "pop3", "imap", "telnet", "rsync", "mysql"):
            try:
                banner = s.recv(100).decode("utf-8", "replace").strip()
                if banner:
                    return banner[:40]
            except Exception:
                pass
        s.close()
    except Exception:
        pass
    return svc


def nmap_deep_scan(host: str, ports: list[int]) -> dict | None:
    """nmap -sV 深度服务识别（识别服务+版本，POC 匹配更精准）。"""
    nmap = shutil.which("nmap")
    if not nmap:
        print("      nmap 不可用，回退轻量识别")
        return None
    port_list = ",".join(str(p) for p in ports)
    try:
        r = subprocess.run(
            [nmap, "-sV", "-p", port_list, host],
            capture_output=True, text=True, timeout=180,
        )
    except Exception as e:
        print(f"      nmap 失败: {e}")
        return None
    services = {}
    for line in r.stdout.splitlines():
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", line.strip())
        if m:
            ver = m.group(3).strip() or m.group(2)
            services[int(m.group(1))] = f"{m.group(2)} {ver}"[:40]
    return services or None


def match_templates(open_ports: list[int], exploit: str | None) -> list[Path]:
    """POC 匹配：来源端口命中 + 可选利用类型过滤。"""
    port_map = _port_map()
    picked = []
    for f in sorted(TEMPLATES.glob("poc-*.yaml")):
        ports = port_map.get(f.name, set())
        if open_ports and not (ports & set(open_ports)):
            continue
        if exploit:
            kind = classify(f.read_text(encoding="utf-8", errors="replace"))["kind"]
            if kind != exploit:
                continue
        picked.append(f)
    return picked


def build_targets(host: str, open_ports: list[int]) -> list[str]:
    """构造扫描目标 URL 列表（HTTP 类端口）。"""
    urls = []
    for p in open_ports:
        svc = COMMON_SERVICES.get(p, "")
        if svc in ("http", "https", "tomcat", "nginx", "apache", "weblogic", "jboss",
                   "iis", "solr", "elasticsearch", "grafana", "docker", "kubelet",
                   "http", "squid", "glassfish", "prometheus", "tr069") or svc == "unknown":
            scheme = "https" if p in (443, 8443) else "http"
            urls.append(f"{scheme}://{host}:{p}")
    return urls


def run_scan(targets: list[str], templates: list[Path], limit: int) -> str:
    """nuclei 批量执行，返回结果文件路径。"""
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td) / "pocs"
        tdir.mkdir()
        for f in templates[:limit]:
            shutil.copy2(f, tdir / f.name)
        result_file = ROOT / "data" / "scan_result.txt"
        cmd = [str(NUCLEI), "-t", str(tdir), "-o", str(result_file), "-silent", "-nc"]
        cmd += ["-u", targets[0]] if len(targets) == 1 else ["-l", str(_write_targets(targets))]
        subprocess.run(cmd)
        return str(result_file)


def _write_targets(targets: list[str]) -> Path:
    p = ROOT / "data" / "scan_targets.tmp"
    p.write_text("\n".join(targets), encoding="utf-8")
    return p


def parse_result(result_file: str) -> tuple[list[str], Counter, dict]:
    """解析 nuclei 结果：命中行 / 严重级 / 模板 id 集合。"""
    lines = Path(result_file).read_text(encoding="utf-8", errors="replace").splitlines()
    sev = Counter()
    template_ids = defaultdict(int)
    for l in lines:
        try:
            parts = l.split("]")
            if len(parts) >= 3:
                sev[parts[2].strip()] += 1
                tid = parts[0].strip("[").strip()
                template_ids[tid] += 1
        except Exception:
            pass
    return lines, sev, template_ids


def backfill_verified(template_ids: dict) -> int:
    """结果回注：命中目标的 POC 标记 verified（置信度提到 1.0）。"""
    import sqlite3
    db_path = ROOT / "data" / "eatall.db"
    if not db_path.exists():
        return 0
    conn = sqlite3.connect(str(db_path))
    updated = 0
    try:
        for tid, hits in template_ids.items():
            row = conn.execute(
                "SELECT poc_id FROM pocs WHERE template_path LIKE ?",
                (f"%{tid}%",),
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE pocs SET status='verified', confidence=1.0 WHERE poc_id=?",
                    (row[0],),
                )
                updated += 1
        conn.commit()
    finally:
        conn.close()
    return updated


def html_report(result_file: str, services: dict, target: str) -> Path:
    """生成 HTML 漏洞报告。"""
    lines, sev, _ = parse_result(result_file)
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_hits = sorted(
        lines,
        key=lambda l: sev_rank.get((l.split("]")[2].strip() if len(l.split("]")) > 2 else "info"), 9),
    )
    rows = "".join(
        f"<tr><td>{h.split(']')[0].strip('[') if ']' in h else h[:40]}</td>"
        f"<td><span class='sev {h.split(']')[2].strip() if len(h.split(']'))>2 else ''}'>{h.split(']')[2].strip() if len(h.split(']'))>2 else '-'}</span></td>"
        f"<td>{h.split(']')[-1].strip() if ']' in h else ''}</td></tr>"
        for h in sorted_hits[:200]
    )
    svc_rows = "".join(f"<tr><td>{p}</td><td>{s}</td></tr>" for p, s in sorted(services.items()))
    html = f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>EatAll 扫描报告 - {target}</title>
<style>body{{font-family:system-ui;background:#0f1419;color:#dbe4ee;padding:20px}}
h1{{color:#4cc2ff}} table{{border-collapse:collapse;width:100%;font-size:13px}}
td,th{{border:1px solid #2e3844;padding:6px 10px;text-align:left}}
.sev{{padding:1px 8px;border-radius:8px;font-size:11px}}
.critical{{background:#5a1d1d;color:#ff9d9d}} .high{{background:#5a3b12;color:#ffd166}}
.medium{{background:#3b4a5a;color:#9ecbff}} .low{{background:#2a3a2a;color:#8fd48f}}
.info{{background:#2e3844;color:#8b98a8}}</style></head><body>
<h1>EatAll 扫描报告</h1>
<p>目标: {target} · 时间: {time.strftime('%Y-%m-%d %H:%M:%S')} · 命中: {len(lines)} 条 · 严重级: {dict(sev) or '无'}</p>
<h2>服务识别</h2><table><tr><th>端口</th><th>服务</th></tr>{svc_rows or '<tr><td colspan="2">无</td></tr>'}</table>
<h2>漏洞命中（前 200）</h2><table><tr><th>模板</th><th>级别</th><th>目标</th></tr>{rows or '<tr><td colspan="3">无命中</td></tr>'}</table>
</body></html>"""
    out = ROOT / "data" / f"scan_report_{int(time.time())}.html"
    out.write_text(html, encoding="utf-8")
    return out


def report(result_file: str, services: dict, target: str, backfill: bool = False) -> None:
    lines, sev, tids = parse_result(result_file)
    if backfill and tids:
        n = backfill_verified(tids)
        print(f"回注: {n} 个命中 POC 标记 verified（置信度 1.0）")
    print("\n" + "=" * 50)
    print(f"扫描完成: {len(lines)} 条命中")
    print(f"严重级: {dict(sev) or '无'}")
    print("\n服务识别:")
    for p, s in sorted(services.items()):
        print(f"  {p}: {s}")
    print("\n命中明细（前 20）:")
    for h in lines[:20]:
        print(f"  {h[:140]}")
    html = html_report(result_file, services, target)
    print(f"\n完整结果: {result_file}")
    print(f"HTML 报告: {html}")


def main() -> int:
    parser = argparse.ArgumentParser(description="自研漏扫（吸收的 POC 库）")
    parser.add_argument("-t", "--target", help="目标 IP 或 URL")
    parser.add_argument("-l", "--targets-file", help="批量目标文件")
    parser.add_argument("-p", "--ports", help="端口列表（逗号分隔），默认常见端口")
    parser.add_argument("-e", "--exploit", help="仅打指定利用类型")
    parser.add_argument("-n", "--limit", type=int, default=300, help="POC 数量上限")
    parser.add_argument("--backfill", action="store_true",
                        help="命中目标的 POC 回注为 verified（置信度 1.0）")
    parser.add_argument("--nmap", action="store_true",
                        help="用 nmap -sV 深度服务识别（更精准的版本指纹 → POC 匹配）")
    args = parser.parse_args()

    target = args.target
    if not target and args.targets_file:
        target = Path(args.targets_file).read_text().strip().splitlines()[0]
    if not target:
        parser.error("需要 -t 目标或 -l 批量目标文件")
    host = urlparse(target if "://" in target else f"http://{target}").hostname

    t0 = time.time()
    print(f"[1/4] 端口扫描 {host} ...")
    ports = [int(p) for p in args.ports.split(",")] if args.ports else None
    open_ports = port_scan(host, ports)
    print(f"      开放端口: {open_ports}（{len(open_ports)} 个）")

    print("[2/4] 服务识别 ...")
    services = {}
    if args.nmap:
        services = nmap_deep_scan(host, open_ports) or {}
    if not services:
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            for p, s in zip(open_ports, ex.map(lambda p: service_probe(host, p), open_ports)):
                services[p] = s

    print("[3/4] POC 匹配 ...")
    templates = match_templates(open_ports, args.exploit)
    print(f"      匹配 {len(templates)} 个 POC（来源端口命中）")

    urls = build_targets(host, open_ports)
    print(f"[4/4] 执行扫描（{len(urls)} 个 URL，POC 上限 {args.limit}）...")
    result_file = run_scan(urls, templates, args.limit)

    report(result_file, services, target, backfill=args.backfill)
    print(f"总耗时: {time.time() - t0:.0f}s")
    return 0


if __name__ == "__main__":
    main()
