# 会话 JSONL Schema（v1）—— Go 捕获代理与 Python 分析管道的解耦契约

- 文件：`data/sessions/sessions-YYYYMMDD-HH.jsonl`（UTC 小时轮转），每行一个 JSON 对象
- 代理每 ~1s flush 一次；ingest 需支持断点续传（崩溃重启不丢行不重读）
- 时间：unix ms UTC

## 顶层字段（顺序即输出顺序）

```json
{
  "schema": 1,
  "session_id": "b0c55c15-7bb7-461b-a7c3-b25952b5ea3f",
  "ts_start": 1785662490010,
  "ts_end": 1785662505014,
  "src_ip": "127.0.0.1",
  "src_port": 28993,
  "dst_ip": "127.0.0.1",
  "dst_port": 8022,
  "transport": "tcp",
  "proto_conf": "ssh",
  "client_bytes_b64": "...",
  "server_bytes_b64": "...",
  "client_len": 1000,
  "server_len": 213,
  "duration_ms": 15004,
  "banner": "SSH-2.0-OpenSSH_7.4",
  "parse_status": "ok",
  "parsed": { },
  "close_reason": "idle_timeout",
  "tls": {}
}
```

### close_reason 取值
`client_closed` | `idle_timeout` | `max_bytes` | `max_http_reqs` | `client_requested_close` | `rate_limited` | `bad_version_line` | `udp_window_end` | `error` | `closed`

### parse_status 取值
`ok` | `partial` | `failed`（尽力而为，失败不影响原始字节记录）

## parsed 各协议结构

### http（proto_conf=http）
```json
{
  "method": "GET",
  "path": "/struts2-showcase/index.action",
  "http_version": "HTTP/1.1",
  "headers": {"Host": "127.0.0.1:8080", "User-Agent": "curl/8.13.0"},
  "body_b64": "",
  "body_truncated": false,
  "req_count": 1
}
```
注：`path` 含 query；headers 保真（原始大小写）；一次连接多个请求时只详述首个，req_count 记总数。

### ssh（proto_conf=ssh）
```json
{
  "client_id": "OpenSSH_for_Windows_9.5",
  "proto_version": "2.0",
  "kexinit": {
    "kex_algorithms": ["curve25519-sha256", "ext-info-c", "kex-strict-c-v00@openssh.com"],
    "host_key_algorithms": ["ssh-ed25519", ...],
    "enc_c2s": ["chacha20-poly1305@openssh.com", "aes128-ctr", ...],
    "enc_s2c": [...],
    "mac_c2s": ["hmac-sha2-256", ...],
    "mac_s2c": [...],
    "compression_c2s": ["none", "zlib@openssh.com"],
    "compression_s2c": ["none", "zlib@openssh.com"],
    "first_packet_follows": false
  }
}
```
指纹要点：`kex_algorithms` 中 `ext-info-c`、`kex-strict-c-v00@openssh.com` 是 OpenSSH 9.x 特征；paramiko/libssh/Go x/crypto 各自的算法顺序不同（详见 M2 指纹规则）。

### mysql（M3 实现）
```json
{ "login": {"username": "root", "auth_plugin": "caching_sha2_password", "database": "mysql"}, "packet_count": 3 }
```

### redis（M3 实现）
```json
{ "commands": [["INFO"], ["CONFIG", "GET", "dir"]], "responses_sent": 2 }
```

### ftp（M3 实现）
```json
{ "commands": [{"cmd": "USER", "arg": "admin"}, {"cmd": "PASS", "arg": "admin123"}] }
```

### smb（M3 实现）
```json
{ "dialects": [2, 3.1.1], "client_guid": "xxxx", "response_sent": true }
```

### dns（M3 实现，transport=udp）
```json
{ "queries": [{"qname": "vpn.example.com", "qtype": "A"}], "replies_sent": 1 }
```

### generic（兜底）
```json
{}
```

## tls 字段（tls-http 端口，M3 实现）
```json
{ "sni": "example.com", "cipher_suites": ["0x1301", "0x1302"], "tls_version": "1.3" }
```

## 备注
- base64 仅作 JSONL 传输格式；Python 侧解码后存 SQLite BLOB
- 解码失败的行由 ingest 记入 `data/logs/ingest_errors.log`，不中断
