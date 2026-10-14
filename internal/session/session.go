// Package session 定义会话数据结构与 JSONL 落盘（按 UTC 小时轮转）。
// 会话记录是一次 TCP 连接（或 UDP 聚合窗口）的双向原始字节 + 尽力而为的协议解析字段。
package session

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const SchemaVersion = 1

// Session 单条会话记录（JSONL 一行）。字段顺序即输出顺序。
type Session struct {
	Schema         int                    `json:"schema"`
	SessionID      string                 `json:"session_id"`
	TsStart        int64                  `json:"ts_start"` // unix ms UTC
	TsEnd          int64                  `json:"ts_end"`
	SrcIP          string                 `json:"src_ip"`
	SrcPort        int                    `json:"src_port"`
	DstIP          string                 `json:"dst_ip"`
	DstPort        int                    `json:"dst_port"`
	Transport      string                 `json:"transport"`  // tcp|udp
	ProtoConf      string                 `json:"proto_conf"` // 配置声明的协议
	ClientBytesB64 string                 `json:"client_bytes_b64"`
	ServerBytesB64 string                 `json:"server_bytes_b64"`
	ClientLen      int                    `json:"client_len"`
	ServerLen      int                    `json:"server_len"`
	DurationMs     int64                  `json:"duration_ms"`
	Banner         string                 `json:"banner,omitempty"` // 实际使用的诱导标识（审计）
	ParseStatus    string                 `json:"parse_status"`     // ok|partial|failed
	Parsed         map[string]interface{} `json:"parsed,omitempty"`
	CloseReason    string                 `json:"close_reason"`
	TLS            map[string]interface{} `json:"tls,omitempty"`
}

// ByteBuf 带容量上限的字节缓冲，用于边读边记录原始流量
type ByteBuf struct {
	buf       []byte
	cap       int
	truncated bool
}

func NewByteBuf(cap int) *ByteBuf {
	return &ByteBuf{cap: cap}
}

// Append 返回 false 表示超过上限（已截断，后续数据不再记录）
func (b *ByteBuf) Append(p []byte) bool {
	if len(p) == 0 {
		return !b.truncated
	}
	room := b.cap - len(b.buf)
	if room <= 0 {
		b.truncated = true
		return false
	}
	if len(p) > room {
		b.buf = append(b.buf, p[:room]...)
		b.truncated = true
		return false
	}
	b.buf = append(b.buf, p...)
	return true
}

func (b *ByteBuf) Bytes() []byte { return b.buf }
func (b *ByteBuf) Len() int      { return len(b.buf) }

// Builder 一次连接的会话构造器，由 listener 创建、handler 填充、listener 落盘
type Builder struct {
	Session
	Client *ByteBuf
	Server *ByteBuf
}

func NewBuilder(tsStart int64, srcIP string, srcPort, dstPort int, transport, proto string) *Builder {
	return &Builder{
		Session: Session{
			Schema:      SchemaVersion,
			SessionID:   newSessionID(),
			TsStart:     tsStart,
			SrcIP:       srcIP,
			SrcPort:     srcPort,
			DstPort:     dstPort,
			Transport:   transport,
			ProtoConf:   proto,
			ParseStatus: "ok",
		},
	}
}

// newSessionID 生成 UUID v4（连接级唯一标识）
func newSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand 失败时退化为时间戳（仅影响唯一性，不影响功能）
		return fmt.Sprintf("sess-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (b *Builder) SetDstIP(ip string) { b.DstIP = ip }

// Finalize 填充时间/长度/base64 字段
func (b *Builder) Finalize(tsEnd int64, closeReason string) {
	b.TsEnd = tsEnd
	b.DurationMs = tsEnd - b.TsStart
	if b.Client != nil {
		b.ClientLen = b.Client.Len()
		b.ClientBytesB64 = base64.StdEncoding.EncodeToString(b.Client.Bytes())
	}
	if b.Server != nil {
		b.ServerLen = b.Server.Len()
		b.ServerBytesB64 = base64.StdEncoding.EncodeToString(b.Server.Bytes())
	}
	b.CloseReason = closeReason
}

// Writer JSONL 写入器：单锁、每行单次 Write syscall、按 UTC 小时轮转。
// 注意：不用 bufio——大会话行（MB 级）会被拆成多次底层写，若两个进程
// 同时 O_APPEND 同一文件（误起双实例），行会互相交错。单次 Write 在本地
// 文件系统上是原子的（O_APPEND）。
type Writer struct {
	dir string
	mu  sync.Mutex

	f     *os.File
	shard string // yyyymmdd-hh
}

func NewWriter(dir string) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir sessions dir: %w", err)
	}
	w := &Writer{dir: dir}
	if err := w.openShard(time.Now().UTC().Format("20060102-15")); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) openShard(shard string) error {
	if w.f != nil {
		_ = w.f.Close()
		w.f = nil
	}
	name := filepath.Join(w.dir, "sessions-"+shard+".jsonl")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open shard %s: %w", name, err)
	}
	w.f = f
	w.shard = shard
	return nil
}

// Write 序列化并追加一行；跨小时自动轮转
func (w *Writer) Write(s *Session) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	w.mu.Lock()
	defer w.mu.Unlock()
	shard := time.UnixMilli(s.TsStart).UTC().Format("20060102-15")
	if shard != w.shard {
		if err := w.openShard(shard); err != nil {
			return err
		}
	}
	// 单次 syscall：行完整性优先于吞吐
	for len(raw) > 0 {
		n, err := w.f.Write(raw)
		if err != nil {
			return err
		}
		raw = raw[n:]
	}
	return nil
}

func (w *Writer) Flush() error {
	return nil // 直写无缓冲，数据已到内核；保留签名兼容调用方
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	return w.f.Close()
}
