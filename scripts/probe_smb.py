#!/usr/bin/env python3
"""提取 nmap 的 SMBProgNeg 探针，发给本机蜜罐，dump 响应字节（M3 SMB 调试用）"""
import re
import socket

probes = r"C:\Program Files (x86)\Nmap\nmap-service-probes"
txt = open(probes, encoding="latin-1").read()
m = re.search(r"Probe TCP SMBProgNeg q\|(.*?)\|", txt, re.S)
if not m:
    print("SMBProgNeg probe not found")
    raise SystemExit(1)

q = m.group(1)
out = bytearray()
i = 0
while i < len(q):
    c = q[i]
    if c == "\\" and i + 1 < len(q):
        nxt = q[i + 1]
        if nxt in "\\|":
            out.append(ord(nxt))
            i += 2
            continue
        if nxt == "x" and i + 3 < len(q):
            out.append(int(q[i + 2 : i + 4], 16))
            i += 4
            continue
        if nxt == "0":
            out.append(0)
            i += 2
            continue
    out.append(ord(c))
    i += 1

print("probe len:", len(out))
s = socket.create_connection(("127.0.0.1", 8445), timeout=3)
s.sendall(bytes(out))
resp = b""
s.settimeout(2)
try:
    while True:
        c = s.recv(65536)
        if not c:
            break
        resp += c
except socket.timeout:
    pass
s.close()
print("response:", len(resp), "bytes")
print("resp hex:", resp.hex(" "))

# 结构解析
if len(resp) >= 40 and resp[4:8] == b"\xffSMB" and resp[8] == 0x72:
    hdr = resp[4:36]
    wc = resp[36]
    print(f"SMB1 response: wc={wc} dialect={int.from_bytes(resp[37:39],'little')}")
