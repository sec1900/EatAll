"""normalize.py 单测：动态值识别 / LCS 稳定字节 / 去重哈希 / 二进制归一化。"""
import base64
import os

from poc_builder.normalize import (
    dns_req_hash,
    is_dynamic_token,
    longest_common_substring,
    normalize_binary,
    normalize_text,
    normalized_req_hash,
    printable_words,
    stable_bytes_over_sessions,
    tcp_req_hash,
)


def test_is_dynamic_token():
    # UUID
    assert is_dynamic_token("550e8400-e29b-41d4-a716-446655440000")
    # 13 位时间戳
    assert is_dynamic_token("1785662000123")
    # 10 位秒级时间戳
    assert is_dynamic_token("1785662000")
    # 24+ hex
    assert is_dynamic_token("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
    # 16 hex 不足 24 → 不判动态
    assert not is_dynamic_token("cdd08c95af809a78")
    # session cookie
    assert is_dynamic_token("PHPSESSID=cdd08c95af809a78")
    # 高熵串（≥29 个不同字符才能超过 4.5 bits/byte）
    assert is_dynamic_token("x9q2k7v4m1z8p3w6t5r0s7n2abcdefgh")
    # 普通值
    assert not is_dynamic_token("admin")
    assert not is_dynamic_token("1")
    assert not is_dynamic_token("index.php")


def test_normalize_text():
    text = "/x?sid=550e8400-e29b-41d4-a716-446655440000&ts=1785662000123&id=1"
    out = normalize_text(text)
    assert "{dyn}" in out
    assert "550e8400" not in out
    assert "1785662000123" not in out
    assert "id=1" in out  # 静态值保留
    # 稳定文本原样
    assert normalize_text("GET /index.php HTTP/1.1") == "GET /index.php HTTP/1.1"


def test_normalized_req_hash():
    headers = {"User-Agent": "curl/8.13.0", "Host": "127.0.0.1:8080", "Accept": "*/*"}
    h1 = normalized_req_hash("GET", "/index.php?a=1", headers, "x=1")
    h2 = normalized_req_hash("GET", "/index.php?a=1", headers, "x=1")
    assert h1 == h2
    # UA/Host 剔除 → 不同 UA 同哈希
    h3 = normalized_req_hash(
        "GET", "/index.php?a=1", {"User-Agent": "sqlmap/1.8", "Accept": "*/*"}, "x=1"
    )
    assert h1 == h3
    # 动态 token 归一化 → 不同 cookie 同哈希
    h4 = normalized_req_hash(
        "GET", "/index.php?a=1", {"User-Agent": "x"},
        "PHPSESSID=cdd08c95af809a78",
    )
    h5 = normalized_req_hash(
        "GET", "/index.php?a=1", {"User-Agent": "x"},
        "PHPSESSID=11111111aaaaaaaa",
    )
    assert h4 == h5
    # 不同路径 → 不同哈希
    assert h1 != normalized_req_hash("GET", "/other.php?a=1", headers, "x=1")
    # 头顺序无关
    h6 = normalized_req_hash("GET", "/index.php?a=1", {"Accept": "*/*", "X-B": "1", "X-A": "2"}, "x=1")
    h7 = normalized_req_hash("GET", "/index.php?a=1", {"X-A": "2", "X-B": "1", "Accept": "*/*"}, "x=1")
    assert h6 == h7


def test_longest_common_substring():
    a = b"hello world stable-marker-1234 foo"
    b = b"xx stable-marker-1234 yy"
    lcs = longest_common_substring(a, b)
    assert b"stable-marker-1234" in lcs  # 公共子串含两侧空格
    assert len(lcs) == len(b" stable-marker-1234 ")
    # 无公共 → 空
    assert longest_common_substring(b"aaaa", b"bbbb") == b""
    # 单字节退化
    assert longest_common_substring(b"a", b"a") == b""


def test_longest_common_substring_repeated():
    # 重复字符边界：全 a
    assert longest_common_substring(b"a" * 50, b"a" * 40) == b"a" * 40


def test_stable_bytes_over_sessions():
    marker = b"BANNER-7.4-STABLE-MARKER-"
    s1 = marker + b"XXXXXX-more-data"
    s2 = marker + b"YYYYYY-other"
    s3 = b"prefix-" + marker + b"ZZZZZZ"
    stable = stable_bytes_over_sessions([s1, s2, s3])
    assert stable == marker
    assert len(stable) >= 16  # ≥16B 才作为模板输入
    # 少于两会话 → 空
    assert stable_bytes_over_sessions([s1]) == b""
    # 无稳定 → 空
    assert stable_bytes_over_sessions([b"abcdef", b"uvwxyz"]) == b""
    # 稳定串不足 16B → 空
    assert stable_bytes_over_sessions([b"shared-abc-de", b"shared-abc-de"]) == b""


def test_normalize_binary():
    # SSH kexinit 风格：静态头 + 16B 随机 cookie
    cookie = os.urandom(16)
    block = b"\x00\x00\x00\xbc\x05\x14" + cookie + b"\x00" * 10
    norm = normalize_binary(block)
    assert b"{dyn}" in norm
    assert cookie not in norm
    # 两次调用一致（同一随机块）
    assert normalize_binary(block) == norm
    # 全静态 → 原样
    assert normalize_binary(b"SSH-2.0-OpenSSH_7.4") == b"SSH-2.0-OpenSSH_7.4"


def test_tcp_and_dns_hashes():
    h1 = tcp_req_hash("ssh", b"SSH-2.0-OpenSSH_8.9\r\n")
    assert h1 == tcp_req_hash("ssh", b"SSH-2.0-OpenSSH_8.9\r\n")
    assert h1 != tcp_req_hash("ssh", b"SSH-2.0-OpenSSH_7.4\r\n")
    # 随机 cookie 不影响哈希
    a = tcp_req_hash("ssh", b"\x14" + os.urandom(16) + b"\x00" * 8)
    b = tcp_req_hash("ssh", b"\x14" + os.urandom(16) + b"\x00" * 8)
    assert a == b
    assert dns_req_hash("vpn.example.com", "A") == dns_req_hash("vpn.example.com", "A")
    assert dns_req_hash("vpn.example.com", "A") != dns_req_hash("vpn.example.com", "AAAA")


def test_printable_words():
    data = b"garbage\x01\x02Banner-Stable-Word\xffHello-World"
    words = printable_words(data)
    assert "Banner-Stable-Word" in words
    assert "Hello-World" in words
    assert len(words) <= 3
    # 全二进制 → 空
    assert printable_words(b"\x00\x01\x02\x03\x04\x05\x06") == []
