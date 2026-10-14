package proto

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"eatal/internal/config"
	"eatal/internal/session"
)

func limits() config.Limits {
	l := config.Limits{}
	l.FillDefaults()
	return l
}

func parse(t *testing.T, raw string) (*parsedReq, error) {
	t.Helper()
	r := bufio.NewReader(strings.NewReader(raw))
	return parseRequest(r, limits())
}

func TestParseRequest_Normal(t *testing.T) {
	req, err := parse(t, "POST /index.php?a=1 HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\nhello=world")
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.Path != "/index.php?a=1" || req.Version != "HTTP/1.1" {
		t.Fatalf("request line: %+v", req)
	}
	if req.Headers["Host"] != "x" {
		t.Fatalf("headers: %v", req.Headers)
	}
	if string(req.Body) != "hello=world" || req.status != "ok" {
		t.Fatalf("body=%q status=%s", req.Body, req.status)
	}
}

func TestParseRequest_LFOnlyAndBareCR(t *testing.T) {
	for name, raw := range map[string]string{
		"lf":       "GET / HTTP/1.1\nHost: x\n\n",
		"bare_cr":  "GET / HTTP/1.1\rHost: x\r\r",
		"mixed_cr": "GET / HTTP/1.1\r\nHost: x\rX: 1\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			req, err := parse(t, raw)
			if err != nil {
				t.Fatal(err)
			}
			if req.Method != "GET" || req.status == "failed" {
				t.Fatalf("%+v", req)
			}
		})
	}
}

func TestParseRequest_Malformed(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		status string
	}{
		{"garbage_method", "GARBAGE{ / HTTP/1.1\r\n\r\n", "failed"},
		{"no_target", "GET\r\n\r\n", "failed"},
		{"no_version", "GET /index.php\r\nHost: x\r\n\r\n", "ok"},
		{"bad_header_no_colon", "GET / HTTP/1.1\r\nbrokenheader\r\n\r\n", "partial"},
		{"cl_mismatch", "POST / HTTP/1.1\r\nContent-Length: 99\r\n\r\nshort", "partial"},
		{"bad_cl", "POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\nx", "partial"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, err := parse(t, c.raw)
			if err != nil {
				t.Fatal(err)
			}
			if req.status != c.status {
				t.Fatalf("want status %s got %s (%+v)", c.status, req.status, req)
			}
		})
	}
}

func TestParseRequest_Chunked(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	req, err := parse(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(req.Body) != "hello world" || req.status != "ok" {
		t.Fatalf("body=%q status=%s", req.Body, req.status)
	}
}

func TestParseRequest_ChunkedExtensionAndGarbage(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\n"
	req, err := parse(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(req.Body) != "hello" {
		t.Fatalf("body=%q", req.Body)
	}
	// 畸形 chunk 大小行
	bad := "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\nhello\r\n"
	req2, err := parse(t, bad)
	if err != nil {
		t.Fatal(err)
	}
	if req2.status != "partial" {
		t.Fatalf("want partial got %s", req2.status)
	}
}

func TestParseRequest_LineTooLong(t *testing.T) {
	long := "GET / HTTP/1.1\r\nX-Filler: " + strings.Repeat("A", 100000) + "\r\n\r\n"
	req, err := parse(t, long)
	if err != nil {
		t.Fatal(err)
	}
	// 超长行吞为 partial：原始字节已由 sessionConn 完整记录，解析尽力而为
	if req.status != "partial" {
		t.Fatalf("want partial got %s", req.status)
	}
}

func TestParseRequest_BodyTruncated(t *testing.T) {
	big := "POST /x HTTP/1.1\r\nContent-Length: 200000\r\n\r\n" + strings.Repeat("B", 200000)
	r := bufio.NewReader(strings.NewReader(big))
	req, err := parseRequest(r, limits())
	if err != nil {
		t.Fatal(err)
	}
	if !req.BodyTruncated || len(req.Body) != limits().MaxBodyBytes {
		t.Fatalf("body len=%d truncated=%v", len(req.Body), req.BodyTruncated)
	}
}

func TestRouteResponse(t *testing.T) {
	pc := &config.PortConfig{
		Responses: map[string]config.HTTPResponse{
			"/index.php": {Status: 200, Body: "TP"},
		},
		Fallback: &config.HTTPResponse{Status: 404, Body: "nf"},
	}
	get := func(path string) *config.HTTPResponse {
		return routeResponse(pc, &parsedReq{Path: path})
	}
	if get("/index.php?a=1").Body != "TP" {
		t.Fatal("query should be stripped before match")
	}
	if get("/other").Status != 404 {
		t.Fatal("fallback expected")
	}
	if get("/").Status != 404 {
		t.Fatal("no root response, fallback expected")
	}
}

func TestWriteResponse_Rand16(t *testing.T) {
	pc := &config.PortConfig{ServerHeader: "nginx/1.18.0"}
	conn := &bufConn{buf: &bytes.Buffer{}}
	r := &config.HTTPResponse{
		Status: 200,
		Headers: map[string]string{
			"Set-Cookie": "PHPSESSID=$rand16",
		},
		Body: "$rand16",
	}
	if err := writeResponse(conn, r, pc.ServerHeader, &parsedReq{Path: "/"}, nil); err != nil {
		t.Fatal(err)
	}
	out := conn.buf.String()
	if !strings.Contains(out, "Server: nginx/1.18.0") {
		t.Fatal("missing server header")
	}
	if strings.Contains(out, "$rand16") {
		t.Fatal("rand16 not expanded")
	}
	if !strings.Contains(out, "Set-Cookie: PHPSESSID=") {
		t.Fatal("header rand not expanded")
	}
}

func TestWriteResponse_Lures(t *testing.T) {
	pc := &config.PortConfig{ServerHeader: "nginx/1.18.0"}
	pool := []string{"/admin/", "/login.php", "/config.php", "/upload/", "/db/", "/logs/",
		"/api/v1/users", "/api/v1/config", "/phpinfo.php", "/backup/", "/tmp/", "/include/"}
	conn := &bufConn{buf: &bytes.Buffer{}}
	r := &config.HTTPResponse{Status: 200, Body: "<html>Hi</html>"}
	req := &parsedReq{Path: "/search.php?q=<script>alert(1)</script>&id=42&long=" + strings.Repeat("A", 100)}
	if err := writeResponse(conn, r, pc.ServerHeader, req, pool); err != nil {
		t.Fatal(err)
	}
	out := conn.buf.String()
	// 首页 12 链接；此处路径非首页 → 4 链接
	if strings.Count(out, `<a href="/`) < 4 {
		t.Fatal("expected link graph injected")
	}
	// 参数反射：<script>alert(1)</script> 原样回显（不转义）→ 诱 XSS 检测
	if !strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatal("expected query param reflection (raw)")
	}
	if strings.Contains(out, strings.Repeat("A", 100)) {
		t.Fatal("overlong param should not be reflected")
	}
	if strings.Contains(out, "42") == false {
		t.Fatal("short numeric param should be reflected")
	}
}

func TestWriteResponse_FormLure(t *testing.T) {
	conn := &bufConn{buf: &bytes.Buffer{}}
	r := &config.HTTPResponse{Status: 200, Body: "<html>login</html>", Form: true}
	req := &parsedReq{Path: "/login.php"}
	if err := writeResponse(conn, r, "nginx/1.18.0", req, nil); err != nil {
		t.Fatal(err)
	}
	out := conn.buf.String()
	if !strings.Contains(out, `<form action="/login.php" method="POST">`) {
		t.Fatal("form lure missing")
	}
	if !strings.Contains(out, `name="username"`) || !strings.Contains(out, `name="password"`) {
		t.Fatal("form fields missing")
	}
}

func TestReflectParams(t *testing.T) {
	got := reflectParams("/search.php?a=hello&b=%3Cscript%3E&c="+strings.Repeat("X", 100), 3)
	if len(got) != 2 || got[0] != "hello" || got[1] != "<script>" {
		t.Fatalf("reflect: %v", got)
	}
	if reflectParams("/noquery", 3) != nil {
		t.Fatal("no query should return nil")
	}
}

// bufConn 最小 net.Conn 实现，用于单测 writeResponse
type bufConn struct {
	buf *bytes.Buffer
}

func (c *bufConn) Read(p []byte) (int, error)         { return c.buf.Read(p) }
func (c *bufConn) Write(p []byte) (int, error)        { return c.buf.Write(p) }
func (c *bufConn) Close() error                       { return nil }
func (c *bufConn) LocalAddr() net.Addr                { return dummyAddr("local") }
func (c *bufConn) RemoteAddr() net.Addr               { return dummyAddr("remote") }
func (c *bufConn) SetDeadline(t time.Time) error      { return nil }
func (c *bufConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *bufConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return "test" }
func (d dummyAddr) String() string  { return string(d) }

func TestHandleHTTP_E2E(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	pc := &config.PortConfig{
		Proto:        "http",
		ServerHeader: "nginx/1.18.0",
		Responses: map[string]config.HTTPResponse{
			"/": {Status: 200, Body: "It works!"},
		},
		Fallback: &config.HTTPResponse{Status: 404, Body: "nf"},
	}
	b := session.NewBuilder(time.Now().UnixMilli(), "1.2.3.4", 12345, 8080, "tcp", "http")
	b.Client = session.NewByteBuf(1 << 20)
	b.Server = session.NewByteBuf(1 << 20)
	ctx := &ConnCtx{Builder: b, PortCfg: pc, Limits: limits()}

	done := make(chan struct{})
	go func() {
		defer close(done)
		HandleHTTP(server, ctx)
	}()

	// net.Pipe 无缓冲：写/读必须交错（handler 读走请求才会继续）
	// 第一个请求 keep-alive；第二个带 Connection: close 让 handler 结束
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 4096)
	n, err := client.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp[:n]), "200") || !strings.Contains(string(resp[:n]), "It works!") {
		t.Fatalf("resp1: %s", resp[:n])
	}
	if _, err := client.Write([]byte("GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	n2, err := client.Read(resp)
	if err != nil && !strings.Contains(err.Error(), "closed") {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp[:n2]), "404") {
		t.Fatalf("resp2: %s", resp[:n2])
	}
	// handler 应自行结束（Connection: close）
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}
	b.Finalize(time.Now().UnixMilli(), b.CloseReason) // 模拟 listener 的收尾

	if b.Parsed == nil || b.Parsed["method"] != "GET" || b.Parsed["req_count"].(int) != 2 {
		t.Fatalf("parsed=%v", b.Parsed)
	}
	if b.CloseReason == "" || b.ParseStatus != "ok" {
		t.Fatalf("close=%s status=%s", b.CloseReason, b.ParseStatus)
	}
	if b.ClientLen == 0 || b.ServerLen == 0 {
		t.Fatalf("no bytes recorded client=%d server=%d", b.ClientLen, b.ServerLen)
	}
}

func TestWorstStatus(t *testing.T) {
	if worstStatus("ok", "partial") != "partial" || worstStatus("partial", "failed") != "failed" {
		t.Fatal("worstStatus ordering wrong")
	}
}
