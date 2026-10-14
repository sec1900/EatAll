#!/usr/bin/env python3
"""E2E 攻击模拟：对蜜罐发起多协议探测/爆破，验证端口视角与攻击分类。"""
import socket
import struct
import time

HOST = "127.0.0.1"


def tcp(port, data: bytes, wait=0.3) -> bytes:
    s = socket.create_connection((HOST, port), timeout=3)
    s.settimeout(2)
    try:
        if data:
            s.sendall(data)
        time.sleep(wait)
        out = b""
        try:
            while True:
                c = s.recv(65536)
                if not c:
                    break
                out += c
        except socket.timeout:
            pass
        return out
    finally:
        s.close()


def mysql_greeting(port) -> bytes:
    s = socket.create_connection((HOST, port), timeout=3)
    s.settimeout(2)
    g = s.recv(4096)
    s.close()
    return g


def mysql_handshake(port, username: bytes, plugin: bytes = b"caching_sha2_password"):
    """发 MySQL 41 握手响应包（带 4B 头）。"""
    caps = 0x00000200 | 0x00008000 | 0x00080000 | 0x00000008
    body = struct.pack("<I", caps) + struct.pack("<I", 16777216) + b"\x21" + b"\x00" * 23
    body += username + b"\x00"
    body += b"\x00"  # auth response len 0
    body += b"\x00"  # no database
    body += plugin + b"\x00"
    pkt = struct.pack("<I", len(body))[:3] + b"\x01" + body  # seq=1
    tcp(port, pkt)


def main():
    t0 = time.time()
    print("== MySQL 爆破（4 个用户名）==")
    for u in (b"root", b"admin", b"test", b"postgres"):
        mysql_greeting(33061)
        mysql_handshake(33061, u)

    print("== Redis 未授权探测 ==")
    for cmd in (b"*1\r\n$4\r\nINFO\r\n", b"*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$3\r\ndir\r\n", b"*1\r\n$4\r\nKEYS\r\n"):
        tcp(63791, cmd)

    print("== FTP 爆破（4 组 USER/PASS）==")
    for user, pwd in (("admin", "123456"), ("root", "root"), ("test", "test123"), ("oracle", "oracle")):
        tcp(8021, f"USER {user}\r\n".encode())
        tcp(8021, f"PASS {pwd}\r\n".encode())

    print("== SSH 批量连接（6 次）==")
    for _ in range(6):
        s = socket.create_connection((HOST, 8022), timeout=3)
        s.sendall(b"SSH-2.0-OpenSSH_8.9\r\n")
        s.close()

    print("== HTTP SQLi ==")
    tcp(8081, b"GET /index.php?id=1%27%20AND%20sleep(3)--%20- HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")

    print(f"done in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
