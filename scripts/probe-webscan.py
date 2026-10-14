#!/usr/bin/env python3
"""E2E 网站漏扫模拟：爬虫跟随链接 → 表单提交 → 参数 fuzz → XSS → SQLi。
模拟 AWVS/Xray 类网站漏扫的探测思路，验证蜜罐诱饵 + webscan 归纳。"""
import re
import socket
import time
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8081"


def req(path: str, method="GET", data=None, headers=None):
    url = BASE + path
    req_obj = urllib.request.Request(url, method=method, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req_obj, timeout=5) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def links_of(html: str):
    return re.findall(r'<a href="(/[^"]*)"', html)


def main():
    t0 = time.time()
    # 1. 爬虫：首页 → 跟随链接（发现阶段）
    _, home = req("/")
    found = links_of(home)
    print(f"首页发现 {len(found)} 个链接")
    for p in found[:6]:
        req(p)
    # 2. 表单发现 + 提交（POST 参数组合）
    _, login = req("/login.php")
    if "<form" in login:
        print("发现登录表单，提交参数组合")
        req("/login.php", method="POST",
            data=urllib.parse.urlencode({"username": "admin", "password": "123456"}).encode())
        req("/login.php", method="POST",
            data=urllib.parse.urlencode({"username": "admin' or 1=1-- ", "password": "x"}).encode())
    # 3. 参数 fuzz（常见注入点参数名）
    for param in ("id", "q", "name", "file", "url"):
        req(f"/index.php?{param}=1")
        req(f"/index.php?{param}=1'")
    # 4. XSS payload 变体（反射点确认后发变体）
    for payload in ("<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                    "javascript:alert(document.cookie)"):
        req("/search.php?q=" + urllib.parse.quote(payload))
    # 5. SQLi payload 变体
    for payload in ("1' AND sleep(3)-- -", "1' UNION SELECT 1,2,3-- -",
                    "1' OR '1'='1", "1' AND 1=1-- -"):
        req("/index.php?id=" + urllib.parse.quote(payload))
    # 6. 路径遍历
    req("/download.php?f=../../../../etc/passwd")
    req("/download.php?f=..%2f..%2f..%2fetc%2fpasswd")
    print(f"网站漏扫模拟完成：{time.time() - t0:.1f}s，共 {9 + len(found[:6])} 个请求")


if __name__ == "__main__":
    main()
