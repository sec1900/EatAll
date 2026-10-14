package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadBanners_Merge(t *testing.T) {
	b, err := LoadBanners(filepath.Join("..", "..", "config", "banners.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// named 段存在
	if _, ok := b.Named["http_main"]; !ok {
		t.Fatal("named http_main missing")
	}
	// 80 引用 http_main 合并
	p80 := b.Port(80)
	if p80.Proto != "http" || p80.ServerHeader != "nginx/1.18.0" {
		t.Fatalf("port 80 merge wrong: %+v", p80)
	}
	if p80.Responses["/struts2-showcase/index.action"].Status != 200 {
		t.Fatal("responses not merged")
	}
	// ES 伪装（9200 已改为 http_es）
	p9200 := b.Port(9200)
	if !p9200.IsHTTP() {
		t.Fatalf("9200 should be http: %+v", p9200)
	}
	if p9200.Responses["/"].Body == "" {
		t.Fatal("9200 should have ES response")
	}
	// tls-http
	p8443 := b.Port(8443)
	if p8443.Proto != "tls-http" || p8443.Cert == "" {
		t.Fatalf("8443: %+v", p8443)
	}
	// ssh
	p22 := b.Port(22)
	if p22.Proto != "ssh" || !p22.StaticKexinit || p22.Version == "" {
		t.Fatalf("22: %+v", p22)
	}
	// default 兜底
	if got := b.Port(9999); got.Proto != "generic" {
		t.Fatalf("default fallback: %+v", got)
	}
	// mysql named 引用
	p3306 := b.Port(3306)
	if p3306.Proto != "mysql" || p3306.ServerVersion != "8.0.26" || p3306.AuthPlugin != "caching_sha2_password" {
		t.Fatalf("3306: %+v", p3306)
	}
}

func TestBanners_BadUseReference(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "b.yaml")
	os.WriteFile(p, []byte("named: {}\nports:\n  \"80\": { use: nope }\n"), 0o644)
	if _, err := LoadBanners(p); err == nil || !strings.Contains(err.Error(), "unknown named") {
		t.Fatalf("want unknown named error, got %v", err)
	}
}

func TestPortsConfig_Defaults(t *testing.T) {
	l := Limits{}
	l.FillDefaults()
	if l.MaxConnsPerIP != 50 || l.MaxSessionBytes != 1<<20 || l.IdleTimeoutSec != 15 {
		t.Fatalf("defaults: %+v", l)
	}
}

func TestTransportOrDefault(t *testing.T) {
	p := &PortConfig{Transport: "udp"}
	if p.TransportOrDefault() != "udp" {
		t.Fatal("udp")
	}
	p2 := &PortConfig{}
	if p2.TransportOrDefault() != "tcp" {
		t.Fatal("tcp default")
	}
}

func TestPortConfig_Equality(t *testing.T) {
	// 验证 struct 标量字段与 applyScalar 覆盖集合一致（防漏字段）
	pcType := reflect.TypeOf(PortConfig{})
	scalars := map[string]bool{}
	for i := 0; i < pcType.NumField(); i++ {
		f := pcType.Field(i)
		tag := f.Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "use" {
			continue // rawPortEntry 专用
		}
		if f.Type.Kind() != reflect.Map && f.Type.Kind() != reflect.Ptr {
			scalars[name] = true
		}
	}
	applyCases := map[string]bool{}
	for _, name := range []string{
		"proto", "server_header", "prefix_match", "version", "static_kexinit",
		"server_version", "auth_plugin", "auth_reply", "reply_mode", "info_reply",
		"banner", "login_accept", "negotiate_reply", "transport", "answer_ip", "cert", "key",
	} {
		applyCases[name] = true
	}
	for name := range scalars {
		if !applyCases[name] {
			t.Fatalf("scalar field %q missing from applyScalar", name)
		}
	}
	for name := range applyCases {
		if !scalars[name] {
			t.Fatalf("applyScalar case %q not a scalar field", name)
		}
	}
}
