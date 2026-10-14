package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestByteBuf_Cap(t *testing.T) {
	b := NewByteBuf(10)
	if !b.Append([]byte("12345")) {
		t.Fatal("append within cap")
	}
	if b.Append([]byte("abcdef")) {
		t.Fatal("append over cap should return false")
	}
	if b.Len() != 10 {
		t.Fatalf("len=%d", b.Len())
	}
	if !b.truncated {
		t.Fatal("truncated flag")
	}
}

func TestWriter_Rotation(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// 第一条：当前小时
	s1 := &Session{
		Schema:   1,
		TsStart:  time.Now().UnixMilli(),
		SrcIP:    "1.1.1.1",
		DstPort:  8080,
		Transport: "tcp",
		ProtoConf: "http",
	}
	if err := w.Write(s1); err != nil {
		t.Fatal(err)
	}
	// 第二条：上一小时（强制轮转）
	s2 := &Session{
		Schema:   1,
		TsStart:  time.Now().Add(-2 * time.Hour).UnixMilli(),
		SrcIP:    "2.2.2.2",
		DstPort:  22,
		Transport: "tcp",
		ProtoConf: "ssh",
	}
	if err := w.Write(s2); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 shards, got %d", len(entries))
	}
	raw, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "1.1.1.1") && !strings.Contains(string(raw), "2.2.2.2") {
		t.Fatalf("shard content: %s", raw)
	}
}

func TestBuilder_Finalize(t *testing.T) {
	b := NewBuilder(1000, "1.2.3.4", 5000, 8080, "tcp", "http")
	b.Client = NewByteBuf(1024)
	b.Server = NewByteBuf(1024)
	b.Client.Append([]byte("GET / HTTP/1.1"))
	b.Finalize(1500, "idle_timeout")
	if b.DurationMs != 500 || b.ClientLen != 14 || b.ClientBytesB64 == "" || b.CloseReason != "idle_timeout" {
		t.Fatalf("%+v", b)
	}
}
