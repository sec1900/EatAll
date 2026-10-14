package proto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// SMB handler 分级实现：
//   - SMB1（0xFF 开头）：只记录原始字节，不回包（现代扫描器不再依赖 SMB1）
//   - SMB2（0xFE 开头）：解析 dialect 列表 + client GUID，回静态构造的
//     Negotiate Response（含固定 SPNEGO/NTLMSSP blob），之后 Session Setup → STATUS_NOT_SUPPORTED
//
// 覆盖工具场景：SMB 版本识别、EternalBlue 类检测、密码喷洒的协商阶段。

const (
	smb2StatusNotSupported = 0xC00000BB
	smb2Negotiate          = 0
	smb2SessionSetup       = 1
	smb2HeaderSize         = 64
)

// staticNtlmChallenge 固定的 SPNEGO NTLMSSP Challenge blob（来自真实抓包，M3 验收可调整）
var staticNtlmChallenge = []byte{
	0x60, 0x5A, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x50,
	0x30, 0x4E, 0xA0, 0x0E, 0x30, 0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04,
	0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA2, 0x3C, 0x04, 0x3A, 0x4E, 0x54,
	0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x82, 0x8A, 0xE2, 0x67, 0x4B,
	0x04, 0xD3, 0x91, 0x7B, 0x5F, 0x44, 0x4B, 0x4C, 0x53, 0x34, 0x45, 0x34,
	0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

// HandleSMB 处理 SMB 连接
func HandleSMB(conn net.Conn, ctx *ConnCtx) {
	sc := Wrap(conn, ctx)
	defer sc.Close()
	SetSessionDeadline(sc, ctx.Limits)
	SetIdle(sc, ctx.Limits)

	ctx.Builder.Banner = "SMB2"
	r := bufio.NewReaderSize(sc, 64<<10)
	parsed := map[string]interface{}{}

	// 第一个包决定路径：SMB1 只记录；SMB2 走协商
	pkt, err := readSMBPacket(r)
	if err != nil {
		ctx.Builder.CloseReason = closeReasonFor(err)
		ctx.Builder.Parsed = parsed
		return
	}
	if len(pkt) == 0 {
		ctx.Builder.CloseReason = "client_closed"
		ctx.Builder.Parsed = parsed
		return
	}
	if pkt[0] == 0x00 && len(pkt) >= 4 {
		// NetBIOS session header 已被 readSMBPacket 剥掉
		pkt = pkt[0:]
	}
	if len(pkt) < 4 || (pkt[0] != 0xFE && pkt[0] != 0xFF) {
		// 非 SMB2/SMB1 首字节
		ctx.Builder.ParseStatus = "failed"
		ctx.Builder.Parsed = parsed
		return
	}
	if pkt[0] == 0xFF {
		// SMB1：若客户端发起 negotiate（0x72），回静态响应（nmap 的 smb 检测依赖 SMB1 协商）
		if len(pkt) >= 36 && pkt[4] == 0x72 {
			dialect := parseSMB1Dialects(pkt)
			if dialect > 0 {
				resp := buildSMB1NegotiateResponse(pkt, dialect)
				if _, err := sc.Write(resp); err != nil {
					ctx.Builder.CloseReason = "error"
					ctx.Builder.Parsed = parsed
					return
				}
				parsed["dialects"] = []int{1}
				parsed["smb1"] = true
				parsed["negotiated_dialect"] = dialect
				ctx.Builder.ParseStatus = "ok"
				drainUntilDeadline(sc, ctx)
				ctx.Builder.Parsed = parsed
				return
			}
		}
		// 其他 SMB1 命令：只记录
		ctx.Builder.ParseStatus = "partial"
		ctx.Builder.Parsed = map[string]interface{}{"dialects": []int{1}, "smb1": true}
		drainUntilDeadline(sc, ctx)
		return
	}

	// SMB2
	if len(pkt) < smb2HeaderSize {
		ctx.Builder.ParseStatus = "partial"
		ctx.Builder.Parsed = parsed
		return
	}
	command := binary.LittleEndian.Uint16(pkt[12:14])
	messageID := pkt[24:32]
	sessionID := pkt[40:48]
	parsed["client_guid"] = parseClientGUID(pkt)

	switch command {
	case smb2Negotiate:
		dialects := parseDialects(pkt)
		parsed["dialects"] = dialects
		if ctx.PortCfg.NegReply == "static" {
			pref := preferDialect(dialects)
			parsed["negotiated_dialect"] = pref
			resp := buildNegotiateResponse(messageID, sessionID, pref)
			if _, err := sc.Write(resp); err != nil {
				ctx.Builder.CloseReason = "error"
				ctx.Builder.Parsed = parsed
				return
			}
			ctx.Builder.ParseStatus = "ok"
		} else {
			ctx.Builder.ParseStatus = "partial"
		}
	case smb2SessionSetup:
		parsed["session_setup"] = true
		// 静态拒绝
		resp := buildErrorResponse(messageID, sessionID, smb2StatusNotSupported)
		if _, err := sc.Write(resp); err != nil {
			ctx.Builder.CloseReason = "error"
			ctx.Builder.Parsed = parsed
			return
		}
		ctx.Builder.ParseStatus = "ok"
	default:
		ctx.Builder.ParseStatus = "partial"
	}

	// 后续包只记录
	drainUntilDeadline(sc, ctx)
	ctx.Builder.Parsed = parsed
}

// readSMBPacket 读一个 NetBIOS 会话包：[type 1B][len 3B BE][数据]
func readSMBPacket(r *bufio.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x00 && hdr[0] != 0xFF {
		return hdr[:], nil // 非标准首字节：交给上层判断
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n <= 0 || n > 16<<20 {
		return nil, fmt.Errorf("bad netbios length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// parseDialects 从 negotiate request 解析 dialect 列表。
// 布局：SMB2 header 64B + negotiate body（structure_size(2) dialect_count(2)
// security_mode(2) reserved(2) capabilities(4) client_guid(16) start_time(8) → dialects）
func parseDialects(pkt []byte) []int {
	body := smb2HeaderSize // 64
	if len(pkt) < body+4 {
		return nil
	}
	count := int(binary.LittleEndian.Uint16(pkt[body+2 : body+4]))
	pos := body + 36
	var out []int
	for i := 0; i < count && pos+2 <= len(pkt); i++ {
		d := int(binary.LittleEndian.Uint16(pkt[pos:]))
		out = append(out, d)
		pos += 2
	}
	return out
}

func preferDialect(dialects []int) uint16 {
	best := uint16(0x0202)
	for _, d := range dialects {
		// SMB 3.1.1 (0x0311) > 3.0.2 (0x0302) > 3.0.0 (0x0300) > 2.1 (0x0210) > 2.0.2 (0x0202)
		if d > int(best) && d <= 0x0311 {
			best = uint16(d)
		}
	}
	return best
}

func parseClientGUID(pkt []byte) string {
	body := smb2HeaderSize
	// client_guid 在 negotiate body offset 20（capabilities 之后）
	if len(pkt) < body+20+16 {
		return ""
	}
	g := pkt[body+20 : body+36]
	return fmt.Sprintf("%x-%x-%x-%x-%x", g[0:4], g[4:6], g[6:8], g[8:10], g[10:16])
}

// buildNegotiateResponse 构造 SMB2 Negotiate Response（固定模板 + 回显客户端 dialect）
func buildNegotiateResponse(messageID, sessionID []byte, dialect uint16) []byte {
	// SMB2 header (64B)
	hdr := make([]byte, smb2HeaderSize)
	copy(hdr[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(hdr[4:6], 64) // structure size
	binary.LittleEndian.PutUint16(hdr[12:14], smb2Negotiate)
	binary.LittleEndian.PutUint16(hdr[14:16], 1) // credits
	copy(hdr[24:32], messageID)
	copy(hdr[32:36], make([]byte, 4)) // process id 0
	copy(hdr[36:40], make([]byte, 4)) // tree id 0
	copy(hdr[40:48], sessionID)
	// body (65B + security blob)
	body := make([]byte, 65+len(staticNtlmChallenge))
	binary.LittleEndian.PutUint16(body[0:2], 65) // structure size
	binary.LittleEndian.PutUint16(body[2:4], 1)  // security mode: SIGNING_ENABLED
	binary.LittleEndian.PutUint16(body[4:6], dialect)
	// server guid（固定）
	copy(body[8:24], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC})
	binary.LittleEndian.PutUint32(body[24:28], 0x00000001) // capabilities: DFS
	binary.LittleEndian.PutUint32(body[28:32], 8388608)    // max transact size
	binary.LittleEndian.PutUint32(body[32:36], 8388608)    // max read size
	binary.LittleEndian.PutUint32(body[36:40], 8388608)    // max write size
	// system_time / server_start_time（固定）
	copy(body[40:48], []byte{0x00, 0x28, 0xE8, 0x7A, 0x58, 0xE7, 0xD6, 0x01})
	copy(body[48:56], []byte{0x00, 0x28, 0xE8, 0x7A, 0x58, 0xE7, 0xD6, 0x01})
	binary.LittleEndian.PutUint16(body[56:58], uint16(64+65)) // security buffer offset
	binary.LittleEndian.PutUint16(body[58:60], uint16(len(staticNtlmChallenge)))
	copy(body[65:], staticNtlmChallenge)

	raw := append(hdr, body...)
	return netbiosFrame(raw)
}

// buildErrorResponse 构造 SMB2 错误响应（header + 9B error body）
func buildErrorResponse(messageID, sessionID []byte, status uint32) []byte {
	hdr := make([]byte, smb2HeaderSize)
	copy(hdr[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(hdr[4:6], 64)
	binary.LittleEndian.PutUint32(hdr[8:12], status)
	binary.LittleEndian.PutUint16(hdr[12:14], smb2SessionSetup)
	binary.LittleEndian.PutUint16(hdr[14:16], 0)
	copy(hdr[24:32], messageID)
	copy(hdr[40:48], sessionID)
	body := make([]byte, 9)
	binary.LittleEndian.PutUint16(body[0:2], 9)
	raw := append(hdr, body...)
	return netbiosFrame(raw)
}

// parseSMB1Dialects 从 SMB1 negotiate request 解析 dialect。
// 两种格式都兼容：
//   - ASCII 字符串格式（nmap SMBProgNeg 探针等）："PC NETWORK PROGRAM 1.0\0...NT LM 0.12\0"
//   - 2B 索引格式（早期 core 协议）：每个 dialect 2 字节
// NT LM 0.12 = 7
func parseSMB1Dialects(pkt []byte) int {
	if len(pkt) < 35 {
		return 0
	}
	wordCount := int(pkt[32])
	if wordCount != 0 {
		// 非标准请求（wordcount != 0）：放弃
		return 0
	}
	byteCount := int(pkt[33]) | int(pkt[34])<<8
	end := 35 + byteCount
	if end > len(pkt) {
		end = len(pkt)
	}
	data := pkt[35:end]
	// 字符串格式：找 "NT LM 0.12"
	if bytes.Contains(data, []byte("NT LM 0.12")) {
		return 7
	}
	// 2B 索引格式
	maxIdx := 0
	for pos := 0; pos+2 <= len(data); pos += 2 {
		d := int(data[pos]) | int(data[pos+1])<<8
		if d == 7 {
			return 7
		}
		if d > maxIdx && d < 256 {
			maxIdx = d
		}
	}
	return maxIdx
}

// buildSMB1NegotiateResponse 构造 SMB1 negotiate 响应。
// 字节布局对齐 nmap-service-probes 的 microsoft-ds 匹配规则（Windows XP 风格）：
// flags=0x88 flags2=0x4001，dialect 回显 7，maxbuf 高字 0x1104，caps 0xE3FD。
// 注意：nmap 按字节匹配，语义正确性次之（现代客户端走 SMB2）。
func buildSMB1NegotiateResponse(req []byte, dialect int) []byte {
	// SMB 头（32B），回显 TID/PID/UID/MID
	hdr := make([]byte, 32)
	copy(hdr[0:4], []byte{0xFF, 'S', 'M', 'B'})
	hdr[4] = 0x72 // SMB_COM_NEGOTIATE
	hdr[9] = 0x88 // flags（XP 匹配规则要求）
	hdr[10] = 0x01
	hdr[11] = 0x40 // flags2 = 0x4001
	if len(req) >= 32 {
		copy(hdr[12:14], req[12:14]) // pid high
		copy(hdr[24:26], req[24:26]) // tid
		copy(hdr[26:28], req[26:28]) // pid low
		copy(hdr[28:30], req[28:30]) // uid
		copy(hdr[30:32], req[30:32]) // mid
	}

	// 参数：wordcount=17，34 字节。字节流对齐 XP 匹配规则：
	//   07 00 | [secmode 任意] 0A | 00 01 | 00 04 | 11 00 00 00 | 00 01 00 00 |
	//   00 00 00 00 | FD E3 00 00 | time(8) | tz(2)
	words := make([]byte, 34)
	binary.LittleEndian.PutUint16(words[0:2], uint16(dialect))
	copy(words[2:], []byte{
		0x0B, 0x0A, // secmode（低字节任意）+ 下一字段低字节
		0x00, 0x01, 0x00, 0x04, // maxmpx/maxvcs 高位字节
		0x11, 0x00, 0x00, 0x00, // maxbuf = 0x00001104（XP 值）
		0x00, 0x01, 0x00, 0x00, // maxraw
		0x00, 0x00, 0x00, 0x00, // sesskey
		0xFD, 0xE3, 0x00, 0x00, // caps = 0xE3FD
	})
	copy(words[24:32], []byte{0x00, 0x28, 0xE8, 0x7A, 0x58, 0xE7, 0xD6, 0x01}) // system time
	binary.LittleEndian.PutUint16(words[32:34], 0)                            // timezone

	// 数据：8B 加密密钥 + 2B domain 长度（bytecount=10）
	data := make([]byte, 8)
	copy(data, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0})
	data = append(data, 0x00, 0x00)

	body := append([]byte{17}, words...)
	body = append(body, byte(len(data)), byte(len(data)>>8))
	body = append(body, data...)
	return netbiosFrame(append(hdr, body...))
}

// netbiosFrame 加 NetBIOS session header
func netbiosFrame(raw []byte) []byte {
	out := make([]byte, 4+len(raw))
	out[0] = 0x00
	out[1] = byte(len(raw) >> 16)
	out[2] = byte(len(raw) >> 8)
	out[3] = byte(len(raw))
	copy(out[4:], raw)
	return out
}

// drainUntilDeadline 读到会话 deadline，纯记录
func drainUntilDeadline(conn net.Conn, ctx *ConnCtx) {
	for {
		SetIdle(conn, ctx.Limits)
		buf := make([]byte, 32<<10)
		if _, err := conn.Read(buf); err != nil {
			if ctx.Builder.CloseReason == "" {
				ctx.Builder.CloseReason = closeReasonFor(err)
			}
			return
		}
		if sc, ok := conn.(*sessionConn); ok && sc.Maxed() {
			ctx.Builder.CloseReason = "max_bytes"
			return
		}
	}
}
