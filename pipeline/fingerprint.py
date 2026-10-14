"""扫描器指纹规则表 + 流聚合（同 src_ip 60s 滑动窗口）。

证据优先级：parsed 字段 > 原始字节 > 行为。
- HTTP UA 正则：sqlmap / nuclei / Nmap Scripting Engine / zgrab / acunetix /
  WPScan / Nikto / python-requests / Go-http-client（低置信）
- SSH kexinit 算法组合：paramiko / OpenSSH / libssh / Go x/crypto
- 行为：60s 内 >5 端口 → port_scan；union select / sleep( / ' or 1=1 →
  sql_injection；握手后极短时间发完整 payload → automated
"""
from __future__ import annotations

import base64
import hashlib
import re
import time
from typing import Optional

from decoders import get_header

# ---------- HTTP User-Agent 规则 ----------
# (tool, regex, confidence)；匹配优先级按列表顺序（先精确后宽松）
HTTP_UA_RULES: list[tuple[str, re.Pattern, float]] = [
    ("sqlmap", re.compile(r"sqlmap/", re.I), 0.9),
    ("nuclei", re.compile(r"nuclei", re.I), 0.8),
    ("nmap", re.compile(r"Nmap Scripting Engine", re.I), 0.9),
    ("zgrab", re.compile(r"zgrab", re.I), 0.85),
    ("acunetix", re.compile(r"acunetix", re.I), 0.9),
    ("wpscan", re.compile(r"wpscan", re.I), 0.9),
    ("nikto", re.compile(r"nikto", re.I), 0.9),
    ("python-requests", re.compile(r"python-requests", re.I), 0.6),
    ("go-http-client", re.compile(r"Go-http-client", re.I), 0.3),
    ("curl", re.compile(r"curl/", re.I), 0.2),
]

# ---------- SSH kexinit 算法组合规则 ----------
# OpenSSH 9.x：ext-info-c + kex-strict-c-v00@openssh.com
# paramiko 3.x：ext-info-c 有、kex-strict 无，且保留 diffie-hellman-group1-sha1
# Go x/crypto：kex 首选 curve25519-sha256@libssh.org，enc 首选 aes128-ctr
def ssh_kex_fingerprint(kex: Optional[dict]) -> list[tuple[str, float, str]]:
    if not kex:
        return []
    kex_algs = kex.get("kex_algorithms") or []
    enc_c2s = kex.get("enc_c2s") or []
    host_algs = kex.get("host_key_algorithms") or []
    out: list[tuple[str, float, str]] = []

    if "kex-strict-c-v00@openssh.com" in kex_algs:
        out.append(("openssh", 0.85, "kex-strict-c-v00@openssh.com present"))
    elif "ext-info-c" in kex_algs and "diffie-hellman-group1-sha1" in kex_algs:
        out.append(("paramiko", 0.8, "ext-info-c w/o kex-strict + group1-sha1"))
    elif "diffie-hellman-group1-sha1" in kex_algs:
        out.append(("paramiko", 0.7, "group1-sha1 present"))

    if kex_algs and kex_algs[0] == "curve25519-sha256@libssh.org":
        if enc_c2s and enc_c2s[0] == "aes128-ctr":
            out.append(("go-xcrypto", 0.85, "kex[0]=curve25519-sha256@libssh.org + aes128-ctr first"))
        else:
            out.append(("libssh", 0.6, "kex[0]=curve25519-sha256@libssh.org"))
    elif enc_c2s and enc_c2s[0] == "chacha20-poly1305@openssh.com" and not out:
        out.append(("openssh", 0.5, "chacha20-poly1305 first"))

    if host_algs and host_algs[0].startswith("ssh-ed25519-cert-v01@"):
        # 证书算法在前的特征：OpenSSH 系
        pass
    return out

# ---------- SSH client_id 兜底 ----------
SSH_CLIENT_ID_RULES: list[tuple[str, str, float]] = [
    ("paramiko", "paramiko", 0.95),
    ("libssh", "libssh", 0.9),
    ("dropbear", "dropbear", 0.9),
    ("putty", "putty", 0.85),
    ("mobaxterm", "mobaxterm", 0.7),
    ("xshell", "xshell", 0.7),
    ("go-xcrypto", "golang", 0.6),
    ("openssh", "openssh", 0.4),  # client_id 仅弱证据
]

# ---------- 行为规则 ----------
# SQL 注入特征（对原始字节做正则）
SQLI_RE = re.compile(
    rb"union[\s+]+select|sleep\s*\(|['\"]\s*or\s+1\s*=\s*1|information_schema|benchmark\s*\(",
    re.I,
)
# 目录爆破特征：大量 404 探测（同一路径前缀下不同后缀）
_DIRBRUTE_MIN_REQS = 5

# 流聚合窗口：60s
FLOW_WINDOW_MS = 60_000
# 端口扫描阈值：窗口内 >5 端口
PORT_SCAN_THRESHOLD = 5


def _best(candidates: list[tuple[str, float, str]]) -> tuple[Optional[str], Optional[float], str]:
    """取置信度最高者；(tool, conf, evidence)。"""
    if not candidates:
        return None, None, ""
    tool, conf, evidence = max(candidates, key=lambda c: c[1])
    return tool, conf, evidence


def fingerprint_session(session: dict, decoded: dict) -> tuple[Optional[str], Optional[float], str]:
    """单会话指纹 → (tool, confidence, evidence)。证据优先级：parsed > 原始字节。"""
    proto = session.get("proto_conf") or "generic"
    candidates: list[tuple[str, float, str]] = []

    if proto in ("http", "tls-http"):
        ua = get_header(decoded.get("headers"), "User-Agent")
        for tool, rx, conf in HTTP_UA_RULES:
            if rx.search(ua):
                candidates.append((tool, conf, f"UA={ua[:80]}"))
                break  # 只取 UA 中最先命中且置信度最高的一条
    elif proto == "ssh":
        kex = decoded.get("kexinit") or {}
        candidates.extend(ssh_kex_fingerprint(kex))
        cid = str(decoded.get("client_id") or "").lower()
        for tool, needle, conf in SSH_CLIENT_ID_RULES:
            if needle in cid:
                candidates.append((tool, conf, f"client_id={cid[:60]}"))
                break

    return _best(candidates)


# ---------- 流聚合 ----------

class Flow:
    """同 src_ip 滑动窗口聚合。"""

    __slots__ = ("ip", "ts_start", "ts_end", "ports", "sessions")

    def __init__(self, ip: str, ts_start: int):
        self.ip = ip
        self.ts_start = ts_start
        self.ts_end = ts_start
        self.ports: set[int] = set()
        self.sessions: list[dict] = []  # 原始 session dict（行为检测用）

    @property
    def flow_id(self) -> str:
        return "flow-" + hashlib.sha256(f"{self.ip}|{self.ts_start}".encode()).hexdigest()[:16]

    def add(self, session: dict, decoded: dict) -> None:
        self.ts_end = max(self.ts_end, session.get("ts_end") or session.get("ts_start") or 0)
        dport = session.get("dst_port")
        if dport:
            self.ports.add(int(dport))
        self.sessions.append((session, decoded))

    def behaviors(self) -> list[str]:
        """行为规则评估（在 flow 关闭时调用）。"""
        out: list[str] = []
        if len(self.ports) > PORT_SCAN_THRESHOLD:
            out.append("port_scan")
        client_all = b"".join(
            base64.b64decode(s.get("client_bytes_b64") or "") for s, _ in self.sessions
        )
        if SQLI_RE.search(client_all):
            out.append("sql_injection")
        # automated：握手后 1s 内发完整 payload（http 一次成包 / ssh 版本行+kexinit 同批）
        for s, d in self.sessions:
            dur = s.get("duration_ms") or 0
            proto = s.get("proto_conf")
            if proto == "http" and dur < 1000 and s.get("client_len", 0) > 0:
                out.append("automated")
                break
            if proto == "ssh" and dur < 3000 and d.get("kexinit"):
                out.append("automated")
                break
        # dir_brute：同 ip 同端口大量 HTTP 探测
        http_sessions = [s for s, _ in self.sessions if s.get("proto_conf") in ("http", "tls-http")]
        if len(http_sessions) >= _DIRBRUTE_MIN_REQS:
            out.append("dir_brute")
        return out

    def tool_guess(self) -> tuple[Optional[str], Optional[float]]:
        """聚合流内所有会话指纹，取全局最高置信。"""
        cands: list[tuple[str, float, str]] = []
        for s, d in self.sessions:
            t, c, _ = fingerprint_session(s, d)
            if t:
                cands.append((t, c or 0.0, ""))
        tool, conf, _ = _best(cands)
        return tool, conf


class FlowAggregator:
    """src_ip → Flow 聚合器。窗口 60s，idle 超窗自动落库。"""

    def __init__(self, db, window_ms: int = FLOW_WINDOW_MS, now_fn=None):
        self.db = db
        self.window_ms = window_ms
        self._flows: dict[str, Flow] = {}
        self._now = now_fn or (lambda: int(time.time() * 1000))

    def add(self, session: dict, decoded: dict) -> str:
        """加入会话，返回所属 flow_id（必要时关闭旧 flow）。"""
        ip = session.get("src_ip") or "unknown"
        now = int(session.get("ts_start") or self._now())
        flow = self._flows.get(ip)
        if flow is None or now - flow.ts_end > self.window_ms:
            if flow is not None:
                self._close(flow)
            flow = Flow(ip, now)
            self._flows[ip] = flow
        flow.add(session, decoded)
        return flow.flow_id

    def close_idle(self) -> int:
        """关闭 idle 超过窗口的 flow，返回关闭数。"""
        now = self._now()
        closed = 0
        for ip, flow in list(self._flows.items()):
            if now - flow.ts_end > self.window_ms:
                self._close(flow)
                del self._flows[ip]
                closed += 1
        return closed

    def close_all(self) -> int:
        n = len(self._flows)
        for flow in list(self._flows.values()):
            self._close(flow)
        self._flows.clear()
        return n

    def _close(self, flow: Flow) -> None:
        behaviors = flow.behaviors()
        tool, conf = flow.tool_guess()
        if self.db is None:
            return  # 纯内存聚合（单测场景）
        self.db.insert_flow(
            flow_id=flow.flow_id,
            src_ip=flow.ip,
            ts_start=flow.ts_start,
            ts_end=flow.ts_end,
            ports_hit=sorted(flow.ports),
            conn_count=len(flow.sessions),
            tool_guess=tool,
            tool_conf=conf,
            behaviors=behaviors,
        )
