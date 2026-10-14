package proto

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// buildKexInitPayload 构造一个 kexinit payload（不含包壳），用于测试解析
func buildKexInitPayload(t *testing.T, kex, enc []string, extInfo bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteByte(sshMsgKexInit)
	buf.Write(make([]byte, 16)) // cookie
	writeStr := func(items []string) {
		b := []byte(strings.Join(items, ","))
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
		buf.Write(hdr[:])
		buf.Write(b)
	}
	writeStr(kex)
	writeStr([]string{"ssh-ed25519"})
	writeStr(enc)
	writeStr(enc)
	writeStr([]string{"hmac-sha2-256"})
	writeStr([]string{"hmac-sha2-256"})
	writeStr([]string{"none"}) // compression c2s（string）
	writeStr([]string{"none"}) // compression s2c（string）
	buf.Write(make([]byte, 4)) // languages c2s
	buf.Write(make([]byte, 4)) // languages s2c
	if extInfo {
		buf.WriteByte(1) // first_kex_packet_follows
	} else {
		buf.WriteByte(0)
	}
	buf.Write(make([]byte, 4)) // reserved
	return buf.Bytes()
}

func TestParseKexInit(t *testing.T) {
	payload := buildKexInitPayload(t, []string{"curve25519-sha256", "diffie-hellman-group14-sha256"}, []string{"aes128-ctr"}, true)
	// 组包
	padLen := 8 - (1+len(payload))%8
	if padLen < 4 {
		padLen += 8
	}
	pkt := make([]byte, 1+len(payload)+padLen)
	pkt[0] = byte(padLen)
	copy(pkt[1:], payload)

	ki := parseKexInit(pkt)
	if ki == nil {
		t.Fatal("parse failed")
	}
	if len(ki.KexAlgorithms) != 2 || ki.KexAlgorithms[0] != "curve25519-sha256" {
		t.Fatalf("kex=%v", ki.KexAlgorithms)
	}
	if len(ki.EncC2S) != 1 || ki.EncC2S[0] != "aes128-ctr" {
		t.Fatalf("enc=%v", ki.EncC2S)
	}
	if len(ki.CompressionC2S) != 1 || ki.CompressionC2S[0] != "none" {
		t.Fatalf("compression=%v", ki.CompressionC2S)
	}
	if !ki.FirstPacketFollows {
		t.Fatal("first_packet_follows should be true")
	}
}

func TestBuildStaticKexinit_Roundtrip(t *testing.T) {
	pkt := buildKexInitPacket(t, []string{"curve25519-sha256"}, []string{"aes128-ctr"}, false)
	client := parseKexInit(pkt[4:]) // 剥掉 4B 长度头
	if client == nil {
		t.Fatal("client kexinit parse failed")
	}
	resp := buildStaticKexinit(client)
	if len(resp) < 4 {
		t.Fatal("resp too short")
	}
	pktLen := binary.BigEndian.Uint32(resp[:4])
	if int(pktLen)+4 != len(resp) {
		t.Fatalf("packet length mismatch: %d vs %d", pktLen+4, len(resp))
	}
	// RFC 4253 §6：含 4B 长度头的总包长必须是 block 的倍数
	if len(resp)%8 != 0 {
		t.Fatalf("total packet not block aligned: %d", len(resp))
	}
	body := resp[4:]
	padLen := int(body[0])
	if padLen < 4 || padLen > 255 || padLen >= len(body) {
		t.Fatalf("bad padLen %d", padLen)
	}
	parsed := parseKexInit(body)
	if parsed == nil {
		t.Fatal("static response not parseable")
	}
	if parsed.KexAlgorithms[0] != "curve25519-sha256" {
		t.Fatalf("should prefer client kex, got %v", parsed.KexAlgorithms)
	}
}

// buildKexInitPacket 完整包（4B 长度头 + body）
func buildKexInitPacket(t *testing.T, kex, enc []string, ext bool) []byte {
	t.Helper()
	payload := buildKexInitPayload(t, kex, enc, ext)
	padLen := 8 - (1+len(payload))%8
	if padLen < 4 {
		padLen += 8
	}
	pkt := make([]byte, 4+1+len(payload)+padLen)
	binary.BigEndian.PutUint32(pkt[:4], uint32(1+len(payload)+padLen))
	pkt[4] = byte(padLen)
	copy(pkt[5:], payload)
	return pkt
}

func TestSSHVersionRe(t *testing.T) {
	m := sshVersionRe.FindSubmatch([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"))
	if m == nil || string(m[3]) != "OpenSSH_8.9p1 Ubuntu-3ubuntu0.1" {
		t.Fatalf("version parse: %v", m)
	}
	if sshVersionRe.FindSubmatch([]byte("HELLO\r\n")) != nil {
		t.Fatal("non-SSH line should not match")
	}
}
