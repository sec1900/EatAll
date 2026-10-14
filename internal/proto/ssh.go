package proto

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

// SSH handler：banner 交换 + kexinit 解析 + 可选静态 kexinit 回应。
// 真实客户端会继续完整握手（我们缺 NEWKEYS/认证）而挂起至超时——会话标 partial 可审计；
// 扫描器普遍只发版本行 + kexinit，不受影响。

const (
	sshMsgKexInit   = 0x14
	sshMaxPacketLen = 1 << 20
	sshVersionMax   = 255
)

var sshVersionRe = regexp.MustCompile(`^SSH-(\d)\.(\d)-([^\r\n]*)`)

// HandleSSH 处理 SSH 连接：读版本行 → 回伪装 banner → 解析/回应 kexinit → 记录后续流量
func HandleSSH(conn net.Conn, ctx *ConnCtx) {
	sc := Wrap(conn, ctx)
	defer sc.Close()
	SetSessionDeadline(sc, ctx.Limits)

	banner := ctx.PortCfg.Version
	if banner == "" {
		banner = "SSH-2.0-OpenSSH_7.4"
	}

	// 版本行：≤255B，5s 超时
	_ = sc.SetReadDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReaderSize(sc, 8<<10)
	line, err := readLine(r, sshVersionMax)
	if err != nil {
		ctx.Builder.CloseReason = closeReasonFor(err)
		return
	}
	ctx.Builder.ParseStatus = "partial"
	parsed := map[string]interface{}{"client_id": ""}
	if m := sshVersionRe.FindSubmatch(line); m != nil {
		parsed["client_id"] = string(m[3])
		parsed["proto_version"] = string(m[1]) + "." + string(m[2])
	} else {
		ctx.Builder.ParseStatus = "failed"
		ctx.Builder.CloseReason = "bad_version_line"
	}

	// 回 banner
	ctx.Builder.Banner = banner
	if _, err := sc.Write([]byte(banner + "\r\n")); err != nil {
		ctx.Builder.CloseReason = "error"
		return
	}

	// kexinit 解析 + 可选静态回应
	if ctx.PortCfg.StaticKexinit {
		SetIdle(sc, ctx.Limits)
		pkt, err := readSSHPacket(r)
		if err == nil {
			if ki := parseKexInit(pkt); ki != nil {
				parsed["kexinit"] = ki
				ctx.Builder.ParseStatus = "ok"
				// 静态 kexinit 回应：优先采用客户端首选的算法，延长会话
				resp := buildStaticKexinit(ki)
				if _, err := sc.Write(resp); err != nil {
					ctx.Builder.CloseReason = "error"
					return
				}
				SetIdle(sc, ctx.Limits)
			}
		}
	}

	// 继续读（记录第二阶段探测流量），直到超时/关闭
	for {
		SetIdle(sc, ctx.Limits)
		buf := make([]byte, 32<<10)
		if _, err := sc.Read(buf); err != nil {
			if ctx.Builder.CloseReason == "" {
				ctx.Builder.CloseReason = closeReasonFor(err)
			}
			break
		}
		if sc.Maxed() {
			ctx.Builder.CloseReason = "max_bytes"
			break
		}
	}

	ctx.Builder.Parsed = parsed
}

// readSSHPacket 读一个 SSH 二进制包：[uint32 len][padding_len][payload][padding]
func readSSHPacket(r *bufio.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	pktLen := binary.BigEndian.Uint32(hdr[:])
	if pktLen == 0 || pktLen > sshMaxPacketLen {
		return nil, errors.New("bad ssh packet length")
	}
	body := make([]byte, pktLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// kexinit 结构（RFC 4253 §7.1 / RFC 8308）
type kexInitInfo struct {
	KexAlgorithms      []string `json:"kex_algorithms"`
	HostKeyAlgorithms  []string `json:"host_key_algorithms"`
	EncC2S             []string `json:"enc_c2s"`
	EncS2C             []string `json:"enc_s2c"`
	MacC2S             []string `json:"mac_c2s"`
	MacS2C             []string `json:"mac_s2c"`
	CompressionC2S     []string `json:"compression_c2s"`
	CompressionS2C     []string `json:"compression_s2c"`
	FirstPacketFollows bool     `json:"first_packet_follows"`
}

// parseKexInit 解析 kexinit 包 payload（packet body: [padlen][payload][padding]）
func parseKexInit(pkt []byte) *kexInitInfo {
	if len(pkt) < 2 {
		return nil
	}
	padLen := int(pkt[0])
	if padLen > len(pkt)-1 {
		return nil
	}
	payload := pkt[1 : len(pkt)-padLen]
	if len(payload) < 1 || payload[0] != sshMsgKexInit {
		return nil
	}
	pos := 1 + 16 // msg_id + cookie
	readStr := func() (string, bool) {
		if pos+4 > len(payload) {
			return "", false
		}
		n := int(binary.BigEndian.Uint32(payload[pos:]))
		pos += 4
		if n < 0 || pos+n > len(payload) {
			return "", false
		}
		s := string(payload[pos : pos+n])
		pos += n
		return s, true
	}
	readList := func() []string {
		s, ok := readStr()
		if !ok {
			return nil
		}
		var out []string
		for _, part := range strings.Split(s, ",") {
			if part != "" {
				out = append(out, part)
			}
		}
		return out
	}

	ki := &kexInitInfo{
		KexAlgorithms:     readList(),
		HostKeyAlgorithms: readList(),
		EncC2S:            readList(),
		EncS2C:            readList(),
		MacC2S:            readList(),
		MacS2C:            readList(),
	}
	if ki.KexAlgorithms == nil {
		return nil
	}
	// compression: 两个 string（"none,zlib@openssh.com"）
	ki.CompressionC2S = readList()
	ki.CompressionS2C = readList()
	// languages: 两个 string
	readStr()
	readStr()
	// first_kex_packet_follows: boolean；reserved: uint32（跳过）
	if pos < len(payload) {
		ki.FirstPacketFollows = payload[pos] == 1
	}
	return ki
}

// buildStaticKexinit 构造合法 kexinit 回应；算法优先取客户端的首选项（在已知集合内）
func buildStaticKexinit(client *kexInitInfo) []byte {
	known := map[string]bool{
		"curve25519-sha256": true, "curve25519-sha256@libssh.org": true,
		"ecdh-sha2-nistp256": true, "diffie-hellman-group14-sha256": true,
		"diffie-hellman-group14-sha1": true, "diffie-hellman-group-exchange-sha256": true,
		"ssh-ed25519": true, "ecdsa-sha2-nistp256": true, "ssh-rsa": true,
		"rsa-sha2-256": true, "rsa-sha2-512": true,
		"chacha20-poly1305@openssh.com": true, "aes128-ctr": true, "aes256-ctr": true,
		"aes128-gcm@openssh.com": true, "aes256-gcm@openssh.com": true,
		"hmac-sha2-256": true, "hmac-sha2-512": true, "hmac-sha1": true,
		"none": true, "zlib@openssh.com": true,
	}
	prefer := func(lists []string) []string {
		for _, a := range lists {
			if known[a] {
				return []string{a}
			}
		}
		return nil
	}
	join := func(list []string, fallback ...string) []byte {
		if list == nil || len(list) == 0 {
			list = fallback
		}
		return []byte(strings.Join(list, ","))
	}

	var payload bytes.Buffer
	payload.WriteByte(sshMsgKexInit)
	cookie := make([]byte, 16)
	_, _ = rand.Read(cookie)
	payload.Write(cookie)
	writeStr := func(b []byte) {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
		payload.Write(hdr[:])
		payload.Write(b)
	}
	writeStr(join(prefer(client.KexAlgorithms), "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"))
	writeStr(join(prefer(client.HostKeyAlgorithms), "ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"))
	writeStr(join(prefer(client.EncC2S), "chacha20-poly1305@openssh.com", "aes128-ctr", "aes256-ctr"))
	writeStr(join(prefer(client.EncS2C), "chacha20-poly1305@openssh.com", "aes128-ctr", "aes256-ctr"))
	writeStr(join(prefer(client.MacC2S), "hmac-sha2-256", "hmac-sha2-512"))
	writeStr(join(prefer(client.MacS2C), "hmac-sha2-256", "hmac-sha2-512"))
	writeStr([]byte("none")) // compression c2s（string）
	writeStr([]byte("none")) // compression s2c（string）
	writeStr(nil)            // languages c2s
	writeStr(nil)            // languages s2c
	payload.WriteByte(0)     // first_kex_packet_follows
	payload.WriteByte(0)     // reserved uint32 (4B)
	payload.WriteByte(0)
	payload.WriteByte(0)
	payload.WriteByte(0)

	// 组包：RFC 4253 §6 —— 含 4B packet_length 头的总长度必须是 block(8) 的倍数；
	// padding ∈ [4,255]
	body := payload.Bytes()
	const block = 8
	totalNoPad := 4 + 1 + len(body)
	padLen := (block - totalNoPad%block) % block
	if padLen < 4 {
		padLen += block
	}
	padding := make([]byte, padLen)
	_, _ = rand.Read(padding)

	pktLen := 1 + len(body) + padLen
	out := make([]byte, 4+pktLen)
	binary.BigEndian.PutUint32(out[:4], uint32(pktLen))
	out[4] = byte(padLen)
	copy(out[5:], body)
	copy(out[5+len(body):], padding)
	return out
}
