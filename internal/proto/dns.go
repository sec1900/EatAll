package proto

import (
	"encoding/binary"
	"net"
)

// DNS handler（UDP）：解析查询 → 按配置回 static_a（指向 answer_ip，诱导继续探测）。
// 记录 qname——批量子域探测会暴露扫描字典（高情报价值）。
// 注意：DNS 会话聚合在 listener.serveUDP 中，本文件只提供解析与回包构造。

// ParseDNSQuery 解析 DNS 查询头 + 首个 question
func ParseDNSQuery(pkt []byte) (qname string, qtype string, ok bool) {
	if len(pkt) < 12 {
		return "", "", false
	}
	qdcount := binary.BigEndian.Uint16(pkt[4:6])
	if qdcount == 0 {
		return "", "", false
	}
	pos := 12
	var labels []byte
	for {
		if pos >= len(pkt) {
			return "", "", false
		}
		l := int(pkt[pos])
		if l == 0 {
			pos++
			break
		}
		if l&0xC0 == 0xC0 {
			// 压缩指针（查询侧罕见，直接跳过）
			pos += 2
			break
		}
		pos++
		if pos+l > len(pkt) {
			return "", "", false
		}
		labels = append(labels, pkt[pos:pos+l]...)
		labels = append(labels, '.')
		pos += l
	}
	if pos+4 > len(pkt) {
		return "", "", false
	}
	qtypeRaw := binary.BigEndian.Uint16(pkt[pos : pos+2])
	pos += 2
	_ = pos
	name := string(labels)
	if len(name) > 0 {
		name = name[:len(name)-1]
	}
	return name, dnsTypeName(qtypeRaw), true
}

func dnsTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 255:
		return "ANY"
	default:
		return "T" + string(rune('0'+t/100)) + string(rune('0'+(t/10)%10)) + string(rune('0'+t%10))
	}
}

// BuildDNSReply 构造 static_a 响应（flags 0x8180: QR|RD|RA, NOERROR）
func BuildDNSReply(query []byte, answerIP string) []byte {
	if len(query) < 12 {
		return nil
	}
	ip := net.ParseIP(answerIP)
	if ip == nil || ip.To4() == nil {
		return nil
	}
	ip4 := ip.To4()

	resp := make([]byte, 0, len(query)+16)
	resp = append(resp, query[0], query[1]) // ID
	resp = append(resp, 0x81, 0x80)         // flags
	resp = append(resp, query[4:6]...)      // qdcount 回显
	resp = append(resp, 0x00, 0x01)         // ancount=1
	resp = append(resp, 0x00, 0x00, 0x00, 0x00) // ns/ar
	// question 原样回显
	pos := 12
	for pos < len(query) {
		if query[pos] == 0 {
			pos++
			resp = append(resp, query[12:pos]...)
			break
		}
		pos++
	}
	// 跳过 qtype/qclass 一并回显
	if pos+4 <= len(query) {
		resp = append(resp, query[pos:pos+4]...)
		pos += 4
	}
	// answer：指针 0xC00C + A 记录
	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, 0x00, 0x01) // type A
	resp = append(resp, 0x00, 0x01) // class IN
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C) // TTL 60
	resp = append(resp, 0x00, 0x04) // rdlength
	resp = append(resp, ip4[0], ip4[1], ip4[2], ip4[3])
	return resp
}
