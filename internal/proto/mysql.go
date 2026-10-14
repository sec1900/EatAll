package proto

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strings"
)

// MySQL handler：伪造 server greeting（版本/插件自洽）→ 解析客户端 41 握手包
// （username/database 是爆破字典情报）→ 按配置回 ERR 或 OK 进入命令阶段

// MySQL capability flags（仅用到的小集合）
const (
	capClientConnectWithDB = 0x00000008
	capClientProtocol41    = 0x00000200
	capClientSecureConn    = 0x00008000
	capClientPluginAuth    = 0x00080000
)

// HandlePostgres 半伪装：发认证请求包 → 收用户名/密码 → 回认证失败。
// 目的是捕获弱口令爆破字典 + 让漏扫确认"存在 PostgreSQL 服务"。
// 协议：启动包(8B 长度+协议号) → 认证请求 R(0x52) → 密码消息 p(0x70) → E(0x45) 错误
func HandlePostgres(conn net.Conn, ctx *ConnCtx) {
	sc := Wrap(conn, ctx)
	defer sc.Close()
	SetSessionDeadline(sc, ctx.Limits)
	SetIdle(sc, ctx.Limits)
	ctx.Builder.Banner = "PostgreSQL 9.5.4"

	r := bufio.NewReaderSize(sc, 16<<10)
	// 读启动包（长度 4 + 协议号 4 + 参数）
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(r, hdr); err != nil {
		ctx.Builder.CloseReason = closeReasonFor(err)
		return
	}
	startLen := int(hdr[0])<<24 | int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if startLen > 8 && startLen < 1<<20 {
		rest := make([]byte, startLen-8)
		if _, err := io.ReadFull(r, rest); err != nil {
			ctx.Builder.CloseReason = closeReasonFor(err)
			return
		}
		// 从启动包提取 user 参数
		var user string
		parts := bytes.Split(rest, []byte{0})
		for i, p := range parts {
			if i+1 < len(parts) && string(p) == "user" {
				user = string(parts[i+1])
				break
			}
		}
		if user != "" {
			ctx.Builder.Parsed = map[string]interface{}{"login": map[string]interface{}{"username": user}}
		} else {
			ctx.Builder.Parsed = map[string]interface{}{}
		}
	} else {
		ctx.Builder.Parsed = map[string]interface{}{}
	}
	// 认证请求：md5 (R 0 0 0 12 00 00 00 03 ssssssss)
	authReq := []byte{'R', 0, 0, 0, 12, 0, 0, 0, 3, 's', 's', 's', 's', 's', 's', 's', 's'}
	if _, err := sc.Write(authReq); err != nil {
		ctx.Builder.CloseReason = "error"
		return
	}
	// 读密码消息（p + 密码 + \0）
	msg := make([]byte, 5)
	if _, err := io.ReadFull(r, msg); err != nil {
		ctx.Builder.CloseReason = closeReasonFor(err)
		return
	}
	if msg[0] == 'p' {
		plen := int(msg[1])<<24 | int(msg[2])<<16 | int(msg[3])<<8 | int(msg[4])
		if plen > 1 && plen < 4096 {
			pw := make([]byte, plen-1)
			if _, err := io.ReadFull(r, pw); err != nil {
				ctx.Builder.CloseReason = closeReasonFor(err)
				return
			}
			ctx.Builder.Parsed["password_md5"] = string(pw)[:32]
		}
	}
	// 认证失败
	errMsg := []byte{'E', 0, 0, 0, 62, 'S', 'F', 'A', 'T', 'A', 'L', 0,
		'V', '2', '8', 'P', '0', '1', 0, 'C', '2', '8', 'P', '0', '1', 0,
		'M', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', ' ', 'a', 'u', 't', 'h', 'e', 'n', 't', 'i', 'c', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ' ', 'f', 'o', 'r', ' ', 'u', 's', 'e', 'r', ' ', '"', 'x', '"', 0, 0}
	// 修正长度
	errLen := len(errMsg) - 1
	errMsg[1] = byte(errLen >> 24)
	errMsg[2] = byte(errLen >> 16)
	errMsg[3] = byte(errLen >> 8)
	errMsg[4] = byte(errLen)
	if _, err := sc.Write(errMsg); err != nil {
		ctx.Builder.CloseReason = "error"
		return
	}
	ctx.Builder.CloseReason = "auth_denied"
	ctx.Builder.ParseStatus = "ok"
}

// HandleMySQL 处理 MySQL 连接
func HandleMySQL(conn net.Conn, ctx *ConnCtx) {
	sc := Wrap(conn, ctx)
	defer sc.Close()
	SetSessionDeadline(sc, ctx.Limits)
	SetIdle(sc, ctx.Limits)

	version := ctx.PortCfg.ServerVersion
	if version == "" {
		version = "8.0.26"
	}
	plugin := ctx.PortCfg.AuthPlugin
	if plugin == "" {
		if strings.HasPrefix(version, "8.") {
			plugin = "caching_sha2_password"
		} else {
			plugin = "mysql_native_password"
		}
	}
	ctx.Builder.Banner = "MySQL " + version

	greeting := buildGreeting(version, plugin)
	if _, err := sc.Write(greeting); err != nil {
		ctx.Builder.CloseReason = "error"
		return
	}

	parsed := map[string]interface{}{}
	packetCount := 0

	// 读握手响应（seq=1）
	pkt, err := readMysqlPacket(sc)
	if err != nil {
		ctx.Builder.CloseReason = closeReasonFor(err)
		ctx.Builder.ParseStatus = "partial"
		ctx.Builder.Parsed = parsed
		return
	}
	packetCount++
	if len(pkt) == 0 || pkt[0] == 0xFF {
		// 客户端直接报错（如 SSL 协商失败被拒后客户端发 ERR）
		ctx.Builder.ParseStatus = "partial"
	}

	if login, ok := parseHandshakeResponse(pkt); ok {
		parsed["login"] = login
	}

	// 回应策略
	switch ctx.PortCfg.AuthReply {
	case "ok":
		if _, err := sc.Write(mysqlOK(2)); err != nil {
			ctx.Builder.CloseReason = "error"
			return
		}
		ctx.Builder.ParseStatus = "ok"
		// 命令阶段：读 COM_* 并记录
		var cmds []string
		for {
			SetIdle(sc, ctx.Limits)
			p, err := readMysqlPacket(sc)
			if err != nil {
				if ctx.Builder.CloseReason == "" {
					ctx.Builder.CloseReason = closeReasonFor(err)
				}
				break
			}
			packetCount++
			if len(p) == 0 {
				continue
			}
			switch p[0] {
			case 0x01: // COM_QUIT
				cmds = append(cmds, "QUIT")
				ctx.Builder.CloseReason = "client_closed"
				goto done
			case 0x03: // COM_QUERY
				cmds = append(cmds, "QUERY "+truncateStr(string(p[1:]), 256))
				if _, err := sc.Write(mysqlErr(2+byte(packetCount%250), 1054, "42S22", "Unknown column 'x' in 'field list'")); err != nil {
					ctx.Builder.CloseReason = "error"
					goto done
				}
			case 0x0e: // COM_PING
				cmds = append(cmds, "PING")
				if _, err := sc.Write(mysqlOK(2 + byte(packetCount%250))); err != nil {
					ctx.Builder.CloseReason = "error"
					goto done
				}
			case 0x02: // COM_INIT_DB
				cmds = append(cmds, "INIT_DB "+truncateStr(string(p[1:]), 128))
				if _, err := sc.Write(mysqlOK(2 + byte(packetCount%250))); err != nil {
					ctx.Builder.CloseReason = "error"
					goto done
				}
			default:
				cmds = append(cmds, "CMD_0x"+hexByte(p[0]))
				if _, err := sc.Write(mysqlErr(2+byte(packetCount%250), 1047, "08S01", "Unknown command")); err != nil {
					ctx.Builder.CloseReason = "error"
					goto done
				}
			}
		}
	done:
		if len(cmds) > 0 {
			parsed["commands"] = cmds
		}
	default: // err
		if _, err := sc.Write(mysqlErr(2, 1045, "28000",
			"Access denied for user '"+loginUsername(parsed)+"'@'"+ctx.Builder.SrcIP+"' (using password: YES)")); err != nil {
			ctx.Builder.CloseReason = "error"
			return
		}
		ctx.Builder.CloseReason = "auth_denied"
		ctx.Builder.ParseStatus = "ok"
	}
	parsed["packet_count"] = packetCount
	ctx.Builder.Parsed = parsed
}

func loginUsername(parsed map[string]interface{}) string {
	if l, ok := parsed["login"].(map[string]interface{}); ok {
		if u, ok := l["username"].(string); ok && u != "" {
			return u
		}
	}
	return "unknown"
}

// buildGreeting 构造 MySQL 握手包（带 4B 包头，seq=0）
func buildGreeting(version, plugin string) []byte {
	var b []byte
	caps := uint32(capClientProtocol41 | capClientSecureConn | capClientPluginAuth | capClientConnectWithDB)
	b = append(b, 0x0a)
	b = append(b, version...)
	b = append(b, 0x00)
	// thread_id
	thread := make([]byte, 4)
	_, _ = rand.Read(thread)
	b = append(b, thread...)
	// auth_data part1 (8B)
	part1 := make([]byte, 8)
	_, _ = rand.Read(part1)
	for _, c := range part1 {
		if c == 0 {
			c = 1
		}
		b = append(b, c)
	}
	b = append(b, 0x00) // filler
	// caps 低 16 位 + charset + status + caps 高 16 位
	var cap16 [2]byte
	binary.LittleEndian.PutUint16(cap16[:], uint16(caps))
	b = append(b, cap16[:]...)
	b = append(b, 0x21) // utf8mb4_general_ci
	var status2 [2]byte
	binary.LittleEndian.PutUint16(status2[:], 0x0002) // SERVER_STATUS_AUTOCOMMIT
	b = append(b, status2[:]...)
	var capHi [2]byte
	binary.LittleEndian.PutUint16(capHi[:], uint16(caps>>16))
	b = append(b, capHi[:]...)
	b = append(b, 21) // auth_plugin_data_len (20B + NUL)
	b = append(b, make([]byte, 10)...)
	// auth_data part2 (12B，共 20B 随机)
	part2 := make([]byte, 12)
	_, _ = rand.Read(part2)
	for _, c := range part2 {
		if c == 0 {
			c = 1
		}
		b = append(b, c)
	}
	b = append(b, 0x00)
	b = append(b, plugin...)
	b = append(b, 0x00)
	return mysqlFrame(b, 0)
}

// parseHandshakeResponse 解析客户端 41 包，返回 login 字段
func parseHandshakeResponse(pkt []byte) (map[string]interface{}, bool) {
	if len(pkt) < 32 || pkt[0] == 0xFF {
		return nil, false
	}
	caps := binary.LittleEndian.Uint32(pkt[0:4])
	pos := 32 // caps(4) + max_packet(4) + charset(1) + 23 reserved
	if pos >= len(pkt) {
		return nil, false
	}
	// username 到 \0
	end := bytesIndexNul(pkt[pos:])
	if end < 0 {
		return nil, false
	}
	login := map[string]interface{}{"username": string(pkt[pos : pos+end])}
	pos += end + 1
	// auth_response：SECURE_CONNECTION 时 1B 长度 + 数据，否则到 \0
	if caps&capClientSecureConn != 0 {
		if pos >= len(pkt) {
			return login, true
		}
		alen := int(pkt[pos])
		pos += 1 + alen
		if pos > len(pkt) {
			pos = len(pkt)
		}
	} else {
		if end2 := bytesIndexNul(pkt[pos:]); end2 >= 0 {
			pos += end2 + 1
		}
	}
	// database（CONNECT_WITH_DB）
	if caps&capClientConnectWithDB != 0 && pos < len(pkt) {
		if end3 := bytesIndexNul(pkt[pos:]); end3 >= 0 {
			login["database"] = string(pkt[pos : pos+end3])
			pos += end3 + 1
		}
	}
	// plugin（PLUGIN_AUTH）
	if caps&capClientPluginAuth != 0 && pos < len(pkt) {
		if end4 := bytesIndexNul(pkt[pos:]); end4 >= 0 {
			login["auth_plugin"] = string(pkt[pos : pos+end4])
		}
	}
	return login, true
}

func bytesIndexNul(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// readMysqlPacket 读 MySQL 包：[3B len][1B seq][payload]
func readMysqlPacket(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n > 16<<20 {
		return nil, errPacketTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

var errPacketTooLarge = &errs{msg: "mysql packet too large"}

type errs struct{ msg string }

func (e *errs) Error() string { return e.msg }

// mysqlFrame 加 4B 包头
func mysqlFrame(payload []byte, seq byte) []byte {
	out := make([]byte, 4+len(payload))
	out[0] = byte(len(payload))
	out[1] = byte(len(payload) >> 8)
	out[2] = byte(len(payload) >> 16)
	out[3] = seq
	copy(out[4:], payload)
	return out
}

// mysqlOK OK 包
func mysqlOK(seq byte) []byte {
	p := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	return mysqlFrame(p, seq)
}

// mysqlErr ERR 包
func mysqlErr(seq byte, code uint16, sqlState, msg string) []byte {
	p := []byte{0xFF, byte(code), byte(code >> 8), '#', sqlState[0], sqlState[1], sqlState[2], sqlState[3], sqlState[4]}
	p = append(p, msg...)
	return mysqlFrame(p, seq)
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func hexByte(b byte) string {
	const hexd = "0123456789abcdef"
	return string([]byte{hexd[b>>4], hexd[b&0x0f]})
}
