#!/usr/bin/env python3
"""目标克隆机制：把给定网站/主机的外观克隆到蜜罐，伪装成"对方"。

用途：克隆一个真实目标（你拥有/已授权的）的页面、Server 头、路径、表单 →
      蜜罐变得和对方一样 → 漏扫扫克隆体 = 扫真实目标 → 吸收针对该目标的 POC。

⚠️ 克隆前请确认目标属于你或已获授权。爬取动作会向目标发起请求。

用法:
    python scripts/clone.py -u http://192.168.1.50:8080 -p 18888 -n myapp
    # -u 目标  -p 蜜罐伪装端口  -n 克隆名（默认 myapp）
    # 生成后重启代理生效: 重启 eatal-proxy
"""
from __future__ import annotations

import argparse
import html
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlparse

ROOT = Path(__file__).resolve().parent.parent
BANNERS = ROOT / "config" / "banners.yaml"

MAX_PATHS = 40          # 最多克隆路径数
COMMON_PATHS = ["/login", "/login.php", "/admin/", "/admin", "/index.php",
                "/index.html", "/robots.txt", "/favicon.ico", "/api/", "/config",
                "/user/login", "/wp-login.php", "/console/", "/static/", "/css/",
                "/js/", "/images/", "/uploads/"]


def fetch(url: str, timeout: float = 6.0) -> tuple[int, dict, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; eatal-clone)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(512 * 1024).decode("utf-8", "replace")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        body = e.read(512 * 1024).decode("utf-8", "replace")
        return e.code, dict(e.headers), body
    except Exception as e:
        return 0, {}, str(e)


def extract_links(body: str, base: str) -> list[str]:
    """提取同源相对路径（去 query/hash，去重限数）。"""
    base_host = urlparse(base).netloc
    paths = []
    for m in re.finditer(r'href=["\']([^"\']+)["\']', body, re.I):
        u = urljoin(base, m.group(1))
        p = urlparse(u)
        if p.netloc and p.netloc != base_host:
            continue  # 外链跳过
        path = p.path or "/"
        if path not in paths and not path.endswith((".css", ".js", ".png", ".jpg",
                                                     ".gif", ".ico", ".svg", ".woff")):
            paths.append(path)
    return paths[:MAX_PATHS]


def extract_forms(body: str) -> list[dict]:
    forms = []
    for m in re.finditer(r'<form[^>]*>', body, re.I):
        attrs = m.group(0)
        action = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
        method = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', body[m.end():m.end() + 2000], re.I)
        forms.append({
            "action": action.group(1) if action else "",
            "method": (method.group(1) if method else "get").lower(),
            "inputs": list(dict.fromkeys(inputs))[:8],
        })
    return forms


def yaml_literal(s: str, indent: str) -> str:
    """YAML 字面量块（多行安全）。"""
    s = s.replace("\\", "\\\\")
    lines = s.splitlines() or [""]
    out = [indent + "body: |"]
    for line in lines[:60]:  # 页面截断 60 行
        out.append(indent + "  " + line)
    return "\n".join(out)


def generate_clone(name: str, target: str, pages: dict) -> str:
    """生成 banners.yaml 克隆配置块。"""
    server_hdr = pages.get("server", "nginx")
    yaml_out = [f"  # ===== 克隆自 {target}（{time.strftime('%Y-%m-%d %H:%M')}）=====",
                f"  clone_{name}:",
                f"    proto: http",
                f"    server_header: \"{server_hdr[:60]}\""]
    for path, (status, body) in pages["pages"].items():
        yaml_out.append(f"    responses:")
        yaml_out.append(f"      \"{path}\":")
        yaml_out.append(f"        status: {status if status else 200}")
        if pages["forms"].get(path):
            yaml_out.append(f"        form: true")
        yaml_out.append(yaml_literal(body or f"<html><body>{path}</body></html>", "        "))
        break  # 只完整写第一个；其余简写
    # 其余路径简写（相同响应体避免配置膨胀）
    rest = [p for p in pages["pages"] if p != "/"]
    if rest:
        yaml_out.append(f"      \"{rest[0]}\":")
        yaml_out.append(f"        status: 200")
        if pages["forms"].get(rest[0]):
            yaml_out.append(f"        form: true")
        yaml_out.append(yaml_literal(body or f"<html><body>{rest[0]}</body></html>", "        "))
    # fallback
    yaml_out.append("    fallback:")
    yaml_out.append(f"      status: 404")
    yaml_out.append(yaml_literal(f"<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>", "      "))
    return "\n".join(yaml_out)


def main() -> int:
    parser = argparse.ArgumentParser(description="克隆目标网站到蜜罐（伪装成对方）")
    parser.add_argument("-u", "--url", required=True, help="目标 URL")
    parser.add_argument("-p", "--port", type=int, default=18888, help="蜜罐伪装端口")
    parser.add_argument("-n", "--name", default="myapp", help="克隆名")
    parser.add_argument("--dry-run", action="store_true", help="只展示将生成的配置")
    args = parser.parse_args()

    target = args.url.rstrip("/")
    print(f"[1/3] 爬取目标 {target} ...")
    pages: dict[str, tuple[int, str]] = {}
    forms: dict[str, list] = {}

    # 首页
    status, headers, body = fetch(target)
    server = headers.get("Server", "")
    print(f"      首页: HTTP {status} · Server: {server or '无'} · {len(body)}B")
    pages["/"] = (status, body)
    forms["/"] = extract_forms(body)

    # 首页链接 + 常见路径
    links = extract_links(body, target)
    print(f"      发现 {len(links)} 个同源路径")
    to_probe = list(dict.fromkeys(links + COMMON_PATHS))[:MAX_PATHS]
    for i, p in enumerate(to_probe):
        if p in pages or p == "/":
            continue
        url = urljoin(target + "/", p.lstrip("/"))
        st, _, b = fetch(url)
        if st and st < 500 and b:
            pages[p] = (st, b)
            fm = extract_forms(b)
            if fm:
                forms[p] = fm
        print(f"      {i+1}/{len(to_probe)} {p} -> {st}")

    print(f"[2/3] 生成克隆配置（{len(pages)} 个路径）...")
    cfg = generate_clone(args.name, target, {"pages": pages, "forms": forms, "server": server})

    if args.dry_run:
        print(cfg[:800])
        return 0

    # 追加到 banners.yaml（在 ports: 前插入 named 段 + 端口映射）
    text = BANNERS.read_text(encoding="utf-8")
    if f"  clone_{args.name}:" in text:
        print(f"克隆 {args.name} 已存在，覆盖")
        text = re.sub(rf"  # ===== 克隆自.*?clone_{args.name}:.*?(?=\n  [a-z_0-9]+:|\nports:|\Z)",
                      "", text, flags=re.S)
    port_line = f'  "{args.port}":  {{ use: clone_{args.name} }}\n'
    text = text.replace("ports:\n", "ports:\n" + port_line, 1)
    # named 段插入到 ports: 之前
    marker = "ports:\n"
    idx = text.index(marker)
    named_block = cfg + "\n\n"
    text = text[:idx] + named_block + text[idx:]
    BANNERS.write_text(text, encoding="utf-8")
    print(f"已写入 banners.yaml：克隆 {args.name} → 端口 {args.port}")

    # 自动把端口加进监听配置（config.broad.yaml / config.yaml 均追加）
    added = []
    for cfg_file in (ROOT / "config" / "config.broad.yaml", ROOT / "config" / "config.yaml"):
        if not cfg_file.exists():
            continue
        s = cfg_file.read_text(encoding="utf-8")
        port_entry = f'  - "{args.port}"'
        if port_entry not in s:
            s = s.replace('  - "49152"', f'{port_entry}     # 克隆目标 {args.name}\n  - "49152"', 1) \
                 if '49152' in s else s + f'{port_entry}     # 克隆目标 {args.name}\n'
            cfg_file.write_text(s, encoding="utf-8")
            added.append(cfg_file.name)
    if added:
        print(f"已自动加入监听端口: {', '.join(added)}（无需手动改配置）")

    print(f"[3/3] 完成。重启代理生效: 停止 eatal-proxy 后重新启动")
    print(f"      然后漏扫扫 http://<本机IP>:{args.port} —— 会像扫真实目标一样打它")
    return 0


if __name__ == "__main__":
    main()
