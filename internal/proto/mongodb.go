package proto

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
)

// MongoDB 半伪装：收到任意请求包 → 回 isMaster 响应（ok:1）。
// 未授权访问检测器（nmap mongodb-info / 漏扫）发 isMaster 后看 ok:1
// 判定"未授权可访问"——我们回 ok:1 即确认，随后对方会尝试 listDatabases/
// 枚举操作，暴露更多利用尝试。
func HandleMongoDB(conn net.Conn, ctx *ConnCtx) {
	sc := Wrap(conn, ctx)
	defer sc.Close()
	SetSessionDeadline(sc, ctx.Limits)
	SetIdle(sc, ctx.Limits)
	ctx.Builder.Banner = "MongoDB 3.6.8"

	r := bufio.NewReaderSize(sc, 64<<10)
	for {
		SetIdle(sc, ctx.Limits)
		hdr := make([]byte, 16)
		if _, err := io.ReadFull(r, hdr); err != nil {
			if ctx.Builder.CloseReason == "" {
				ctx.Builder.CloseReason = closeReasonFor(err)
			}
			break
		}
		msgLen := int(binary.LittleEndian.Uint32(hdr[0:4]))
		if msgLen < 16 || msgLen > 16<<20 {
			break
		}
		rest := make([]byte, msgLen-16)
		if _, err := io.ReadFull(r, rest); err != nil {
			break
		}
		opCode := binary.LittleEndian.Uint32(hdr[12:16])
		reqID := binary.LittleEndian.Uint32(hdr[4:8])
		if opCode == 1 { // OP_REPLY 意外
			continue
		}
		// 回 isMaster 响应（OP_REPLY，document 含 ok:1）
		resp := buildIsMaster(reqID)
		if _, err := sc.Write(resp); err != nil {
			ctx.Builder.CloseReason = "error"
			break
		}
		if sc.Maxed() {
			ctx.Builder.CloseReason = "max_bytes"
			break
		}
		// 响应后继续读（对方可能发 listDatabases 等）
	}
	ctx.Builder.Parsed = map[string]interface{}{"op_codes_seen": []int{1}}
}

// buildIsMaster 构造 OP_REPLY 响应，BSON: {ismaster:true, maxWireVersion:6,
// minWireVersion:0, maxBsonObjectSize:16777216, ok:1.0}
func buildIsMaster(respTo uint32) []byte {
	var doc []byte
	doc = appendBSONBool(doc, "ismaster", true)
	doc = appendBSONInt32(doc, "maxWireVersion", 6)
	doc = appendBSONInt32(doc, "minWireVersion", 0)
	doc = appendBSONInt32(doc, "maxBsonObjectSize", 16777216)
	doc = appendBSONDouble(doc, "ok", 1.0)
	doc = append(doc, 0x00) // BSON terminator

	// OP_REPLY: msgLen(4) reqID(4) respTo(4) opCode=1(4) flags(4) cursorID(8) startingFrom(4) numberReturned(4) doc
	bodyLen := 20 + len(doc) // flags+cursor+start+num + doc
	out := make([]byte, 16+bodyLen)
	binary.LittleEndian.PutUint32(out[0:4], uint32(16+bodyLen))
	binary.LittleEndian.PutUint32(out[4:8], 0xDEAD) // reqID
	binary.LittleEndian.PutUint32(out[8:12], respTo)
	binary.LittleEndian.PutUint32(out[12:16], 1) // OP_REPLY
	binary.LittleEndian.PutUint32(out[16:20], 0) // flags: QueryFailure=0
	binary.LittleEndian.PutUint64(out[20:28], 0) // cursorID
	binary.LittleEndian.PutUint32(out[28:32], 0) // startingFrom
	binary.LittleEndian.PutUint32(out[32:36], 1) // numberReturned
	copy(out[36:], doc)
	return out
}

func appendBSONBool(doc []byte, key string, v bool) []byte {
	doc = append(doc, 0x08)
	doc = append(doc, key...)
	doc = append(doc, 0x00)
	if v {
		doc = append(doc, 0x01)
	} else {
		doc = append(doc, 0x00)
	}
	return doc
}

func appendBSONInt32(doc []byte, key string, v int32) []byte {
	doc = append(doc, 0x10)
	doc = append(doc, key...)
	doc = append(doc, 0x00)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	doc = append(doc, b[:]...)
	return doc
}

func appendBSONDouble(doc []byte, key string, v float64) []byte {
	doc = append(doc, 0x01)
	doc = append(doc, key...)
	doc = append(doc, 0x00)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64FromFloat(v))
	doc = append(doc, b[:]...)
	return doc
}

func uint64FromFloat(v float64) uint64 {
	// 手工 IEEE754 转换：仅需 ok:1.0（0x3FF0000000000000）
	if v == 1.0 {
		return 0x3FF0000000000000
	}
	return 0
}
