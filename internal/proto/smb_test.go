package proto

import (
	"encoding/binary"
	"testing"
)

// buildNegotiateReq 构造一个最小 SMB2 negotiate request（仅 header + body 骨架）
func buildNegotiateReq(t *testing.T, dialects []uint16, guid []byte) []byte {
	t.Helper()
	pkt := make([]byte, 64+36+2*len(dialects))
	copy(pkt[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(pkt[4:6], 64)
	binary.LittleEndian.PutUint16(pkt[12:14], smb2Negotiate)
	body := 64
	binary.LittleEndian.PutUint16(pkt[body:body+2], 36)
	binary.LittleEndian.PutUint16(pkt[body+2:body+4], uint16(len(dialects)))
	copy(pkt[body+20:body+36], guid)
	pos := body + 36
	for _, d := range dialects {
		binary.LittleEndian.PutUint16(pkt[pos:pos+2], d)
		pos += 2
	}
	return pkt
}

func TestParseDialects(t *testing.T) {
	guid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	pkt := buildNegotiateReq(t, []uint16{0x0202, 0x0300, 0x0311}, guid)
	dialects := parseDialects(pkt)
	if len(dialects) != 3 || dialects[0] != 0x0202 || dialects[2] != 0x0311 {
		t.Fatalf("dialects=%v", dialects)
	}
	if g := parseClientGUID(pkt); len(g) != 36 {
		t.Fatalf("guid=%q", g)
	}
	if preferDialect(dialects) != 0x0311 {
		t.Fatalf("prefer=%d", preferDialect(dialects))
	}
}

func TestBuildNegotiateResponse(t *testing.T) {
	resp := buildNegotiateResponse(make([]byte, 8), make([]byte, 8), 0x0311)
	if len(resp) < 4+64+65 {
		t.Fatalf("resp too short: %d", len(resp))
	}
	// NetBIOS 长度头
	n := int(resp[1])<<16 | int(resp[2])<<8 | int(resp[3])
	if n+4 != len(resp) {
		t.Fatalf("netbios len mismatch: %d vs %d", n+4, len(resp))
	}
	body := resp[4+64:]
	if binary.LittleEndian.Uint16(body[0:2]) != 65 {
		t.Fatal("structure size")
	}
	if binary.LittleEndian.Uint16(body[4:6]) != 0x0311 {
		t.Fatal("dialect echo")
	}
	if binary.LittleEndian.Uint16(body[56:58]) == 0 || binary.LittleEndian.Uint16(body[58:60]) == 0 {
		t.Fatal("security buffer offset/len")
	}
}

func TestBuildErrorResponse(t *testing.T) {
	resp := buildErrorResponse(make([]byte, 8), make([]byte, 8), smb2StatusNotSupported)
	if binary.LittleEndian.Uint32(resp[4+8:4+12]) != smb2StatusNotSupported {
		t.Fatal("status")
	}
}

func TestSMB1Negotiate(t *testing.T) {
	// 构造 SMB1 negotiate request（含 NT LM 0.12 = dialect 7）
	req := make([]byte, 35+2*3)
	copy(req[0:4], []byte{0xFF, 'S', 'M', 'B'})
	req[4] = 0x72
	req[32] = 0                 // wordcount
	req[33] = 6                 // bytecount
	dialects := []int{1, 2, 7}  // PC NETWORK 1.0, LANMAN1.0, NT LM 0.12
	pos := 35
	for _, d := range dialects {
		binary.LittleEndian.PutUint16(req[pos:pos+2], uint16(d))
		pos += 2
	}
	if got := parseSMB1Dialects(req); got != 7 {
		t.Fatalf("dialect=%d want 7", got)
	}
	resp := buildSMB1NegotiateResponse(req, 7)
	// NetBIOS 长度
	n := int(resp[1])<<16 | int(resp[2])<<8 | int(resp[3])
	if n+4 != len(resp) {
		t.Fatalf("netbios len %d vs %d", n+4, len(resp))
	}
	// SMB 头
	if resp[4] != 0xFF || resp[8] != 0x72 {
		t.Fatal("bad smb1 header")
	}
	// wordcount=17（在 SMB 头 32B 之后），dialect 回显在 words[0:2]
	if resp[4+32] != 0x11 {
		t.Fatalf("wordcount: %d", resp[4+32])
	}
	words := resp[4+32+1:]
	if binary.LittleEndian.Uint16(words[0:2]) != 7 {
		t.Fatalf("dialect: %v", words[:6])
	}
	// 34B words 后是 bytecount=10
	bc := int(words[34]) | int(words[35])<<8
	if bc != 10 {
		t.Fatalf("bytecount: %d", bc)
	}
	// 对齐 nmap XP 匹配规则的关键字节
	if resp[4+9] != 0x88 || resp[4+10] != 0x01 || resp[4+11] != 0x40 {
		t.Fatalf("flags: %x %x %x", resp[4+9], resp[4+10], resp[4+11])
	}
	want := []byte{0x0B, 0x0A, 0x00, 0x01, 0x00, 0x04, 0x11}
	for i, b := range want {
		if words[2+i] != b {
			t.Fatalf("byte %d: want 0x%02x got 0x%02x", i, b, words[2+i])
		}
	}
}

func TestParseSMB1Dialects_StringFormat(t *testing.T) {
	// nmap SMBProgNeg 探针风格：ASCII 字符串 dialect
	pkt := make([]byte, 35+4+len("NT LM 0.12"))
	copy(pkt[0:4], []byte{0xFF, 'S', 'M', 'B'})
	pkt[4] = 0x72
	pkt[32] = 0 // wordcount
	pkt[33] = byte(4 + len("NT LM 0.12"))
	copy(pkt[35:], []byte{0x02, 'P', 'C', 0x00})
	copy(pkt[35+4:], []byte("NT LM 0.12"))
	if got := parseSMB1Dialects(pkt); got != 7 {
		t.Fatalf("string format dialect=%d want 7", got)
	}
	// 2B 索引格式
	pkt2 := make([]byte, 39)
	copy(pkt2[0:4], []byte{0xFF, 'S', 'M', 'B'})
	pkt2[4] = 0x72
	pkt2[32] = 0
	pkt2[33] = 4
	binary.LittleEndian.PutUint16(pkt2[35:37], 7)
	if got := parseSMB1Dialects(pkt2); got != 7 {
		t.Fatalf("index format dialect=%d want 7", got)
	}
}

