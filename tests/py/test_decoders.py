"""解码器单测：Go parsed 复用 + 原始字节深解析（畸形容错）。"""
import base64
import os

from decoders import decode_session
from decoders.dns import server_answer_ips, server_rcode
from decoders.http import HTTPDecoder, server_status
from decoders.ssh import SSHDecoder
from conftest import make_session


# ---------- HTTP ----------

def _http_session(client_bytes, server_bytes=b"HTTP/1.1 200 OK\r\n\r\nok", **over):
    return make_session(
        client_bytes=client_bytes, server_bytes=server_bytes,
        parse_status="failed", parsed=None, **over,
    )


def test_http_reuse_go_parsed():
    parsed = {"method": "POST", "path": "/x?a=1", "headers": {"User-Agent": "nuclei"}, "body_b64": ""}
    s = make_session(parsed=parsed, parse_status="ok")
    out, status = decode_session(s)
    assert out is parsed and status == "ok"


def test_http_malformed_garbage_method():
    raw = b"GARBAGE{ / HTTP/1.1\r\nHost: x\r\n\r\n"
    out, status = decode_session(_http_session(raw))
    assert out["method"] == "GARBAGE{"
    assert out["path"] == "/"
    assert out["http_version"] == "HTTP/1.1"
    assert out["headers"] == {"Host": "x"}
    assert status == "ok"  # 深解析成功


def test_http_bare_cr_line_endings():
    raw = b"GET /a HTTP/1.1\rX-T: 1\r\r"
    out, _ = decode_session(_http_session(raw))
    assert out["headers"].get("X-T") == "1"
    assert out["path"] == "/a"


def test_http_no_version():
    raw = b"GET /nover HTTP/1.0\nHost: y\n\n"
    out, _ = decode_session(_http_session(raw))
    assert out["path"] == "/nover"
    assert out["http_version"] == "HTTP/1.0"


def test_http_chunked_body():
    raw = b"POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    out, _ = decode_session(_http_session(raw))
    assert base64.b64decode(out["body_b64"]) == b"hello"
    assert out["body_truncated"] is False


def test_http_content_length_body():
    raw = b"POST /l HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd"
    out, _ = decode_session(_http_session(raw))
    assert base64.b64decode(out["body_b64"]) == b"abcd"


def test_http_empty_client():
    s = make_session(client_bytes=b"", parse_status="failed", parsed=None)
    out, status = decode_session(s)
    assert status == "failed"


def test_server_status():
    assert server_status(b"HTTP/1.1 404 Not Found\r\n") == 404
    assert server_status(b"garbage") is None
    assert server_status(b"") is None


# ---------- SSH ----------

def _ssh_kexinit_packet(kex, host, enc, mac, comp):
    def ss(s):
        b = s.encode()
        return len(b).to_bytes(4, "big") + b

    payload = b"\x14" + os.urandom(16)
    for lst in (kex, host, enc, enc, mac, mac, comp, comp):
        payload += ss(",".join(lst))
    payload += b"\x00" + b"\x00\x00\x00\x00"
    pad = 4
    pkt = len(payload) + 1 + pad
    return pkt.to_bytes(4, "big") + bytes([pad]) + payload + b"\x00" * pad


OPENSSH_KEX = ["curve25519-sha256", "ecdh-sha2-nistp256", "ext-info-c", "kex-strict-c-v00@openssh.com"]
PARAMIKO_KEX = ["curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group1-sha1", "ext-info-c"]
GO_KEX = ["curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha1"]
GO_ENC = ["aes128-ctr", "aes192-ctr", "chacha20-poly1305@openssh.com"]
HOST_ALGS = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512"]
MACS = ["hmac-sha2-256", "umac-64-etm@openssh.com"]
COMPS = ["none", "zlib@openssh.com"]


def _ssh_session(kex, enc=None):
    ver = b"SSH-2.0-OpenSSH_for_Windows_9.5\r\n"
    kexinit = _ssh_kexinit_packet(kex, HOST_ALGS, enc or ["chacha20-poly1305@openssh.com"], MACS, COMPS)
    return make_session(
        client_bytes=ver + kexinit, parse_status="failed", parsed=None, proto_conf="ssh",
        client_len=len(ver + kexinit), dst_port=8022,
    )


def test_ssh_deep_parse():
    s = _ssh_session(OPENSSH_KEX)
    out, status = decode_session(s)
    assert out["client_id"] == "OpenSSH_for_Windows_9.5"
    assert out["proto_version"] == "2.0"
    kex = out["kexinit"]
    assert kex["kex_algorithms"][0] == "curve25519-sha256"
    assert "kex-strict-c-v00@openssh.com" in kex["kex_algorithms"]
    assert status == "ok"


def test_ssh_version_only():
    s = make_session(client_bytes=b"SSH-2.0-libssh-0.9.6\r\n", parse_status="failed", parsed=None, proto_conf="ssh")
    out, _ = decode_session(s)
    assert out["client_id"] == "libssh-0.9.6"
    assert "kexinit" not in out


def test_ssh_no_version_line():
    s = make_session(client_bytes=b"\x00\x01\x02\x03", parse_status="failed", parsed=None, proto_conf="ssh")
    out, status = decode_session(s)
    assert status == "failed"


# ---------- MySQL ----------

def _mysql_hr(username="root", database="mysql", auth=b"\x01\x02\x03\x04\x05"):
    caps = 0x00080000 | 0x00000008  # lenenc auth + connect with db
    p = caps.to_bytes(4, "little") + (0x00FFFFFF).to_bytes(4, "little") + b"\x21" + b"\x00" * 23
    p += username.encode() + b"\x00" + bytes([len(auth)]) + auth
    p += database.encode() + b"\x00"
    return (len(p)).to_bytes(3, "little") + b"\x01" + p


def test_mysql_deep_parse():
    s = make_session(client_bytes=_mysql_hr(), parse_status="failed", parsed=None, proto_conf="mysql")
    out, status = decode_session(s)
    assert out["login"]["username"] == "root"
    assert out["login"]["database"] == "mysql"
    assert status == "ok"


def test_mysql_short_packet():
    s = make_session(client_bytes=b"\x01\x02\x03", parse_status="failed", parsed=None, proto_conf="mysql")
    _, status = decode_session(s)
    assert status == "failed"


# ---------- Redis ----------

def test_redis_resp_and_inline():
    resp = b"*2\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n"
    inline = b"INFO\r\n"
    s = make_session(client_bytes=resp + inline, parse_status="failed", parsed=None, proto_conf="redis")
    out, _ = decode_session(s)
    assert ["CONFIG", "GET"] in out["commands"]
    assert ["INFO"] in out["commands"]


# ---------- FTP ----------

def test_ftp_commands():
    s = make_session(client_bytes=b"USER admin\r\nPASS admin123\r\n", parse_status="failed", parsed=None, proto_conf="ftp")
    out, _ = decode_session(s)
    assert out["commands"] == [{"cmd": "USER", "arg": "admin"}, {"cmd": "PASS", "arg": "admin123"}]


# ---------- DNS ----------

def _dns_query(qname, qtype=1):
    header = (0x1234).to_bytes(2, "big") + (0x0100).to_bytes(2, "big") + (1).to_bytes(2, "big") + b"\x00" * 6
    name = b"".join(bytes([len(l)]) + l.encode() for l in qname.split(".")) + b"\x00"
    return header + name + qtype.to_bytes(2, "big") + b"\x00\x01"


def _dns_response(qname, ip="172.16.0.10", rcode=0):
    flags = 0x8180 | rcode
    header = (0x1234).to_bytes(2, "big") + flags.to_bytes(2, "big") + (1).to_bytes(2, "big") + (1).to_bytes(2, "big") + b"\x00" * 4
    name = b"".join(bytes([len(l)]) + l.encode() for l in qname.split(".")) + b"\x00"
    question = name + (1).to_bytes(2, "big") + (1).to_bytes(2, "big")  # qtype + qclass
    answer = b"\xc0\x0c" + (1).to_bytes(2, "big") + (1).to_bytes(2, "big") + (300).to_bytes(4, "big") + (4).to_bytes(2, "big") + bytes(int(x) for x in ip.split("."))
    return header + question + answer


def test_dns_deep_parse():
    s = make_session(client_bytes=_dns_query("vpn.example.com"), parse_status="failed", parsed=None, proto_conf="dns", transport="udp")
    out, status = decode_session(s)
    assert out["queries"][0]["qname"] == "vpn.example.com"
    assert out["queries"][0]["qtype"] == "A"
    assert status == "ok"


def test_dns_server_rcode_and_answer():
    resp = _dns_response("vpn.example.com", ip="172.16.0.10", rcode=0)
    assert server_rcode(resp) == 0
    assert server_answer_ips(resp) == ["172.16.0.10"]
    assert server_rcode(b"short") is None


# ---------- generic ----------

def test_generic_passthrough():
    s = make_session(client_bytes=b"\x00\x01\x02", parse_status="failed", parsed=None, proto_conf="generic")
    out, status = decode_session(s)
    assert out == {} and status == "failed"
    s2 = make_session(parse_status="ok", parsed={}, proto_conf="generic")
    out2, status2 = decode_session(s2)
    assert status2 == "ok"
