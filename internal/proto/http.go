package proto

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"eatal/internal/config"
)

// 为什么不用 net/http：它是"规范服务器"——未知 method 直接 400、无 Host 部分拒绝、
// URL 被规范化改写，而扫描器（sqlmap/nuclei/xray/自研工具）常态发畸形包。
// 这里裸 TCP 手写容错解析：畸形请求也要完整记录原始字节，解析失败只影响 parsed 字段。

type parsedReq struct {
	Method        string
	Path          string
	Version       string
	Headers       map[string]string
	Body          []byte
	BodyTruncated bool
	status        string // ok|partial|failed
}

// HandleHTTP 处理一个 HTTP 连接：循环解析请求 → 按配置路由响应 → 记录会话
func HandleHTTP(conn net.Conn, ctx *ConnCtx) {
	sc := Wrap(conn, ctx)
	defer sc.Close()
	SetSessionDeadline(sc, ctx.Limits)
	handleHTTPLoop(sc, ctx)
}

// handleHTTPLoop 在给定连接上跑 HTTP 解析/响应循环（tls 解密后复用）
func handleHTTPLoop(conn net.Conn, ctx *ConnCtx) {
	SetIdle(conn, ctx.Limits)
	handleHTTPLoopReader(conn, bufio.NewReaderSize(conn, 64<<10), ctx)
}

// handleHTTPLoopReader 用外部提供的 reader 跑 HTTP 循环（generic 端口识别 HTTP 后复用）
func handleHTTPLoopReader(conn net.Conn, r *bufio.Reader, ctx *ConnCtx) {
	SetIdle(conn, ctx.Limits)

	worst := "ok"
	var first *parsedReq
	reqCount := 0

	for {
		req, err := parseRequest(r, ctx.Limits)
		if err != nil {
			// 无请求到达（超时/对端关闭）
			if ctx.Builder.CloseReason == "" {
				ctx.Builder.CloseReason = closeReasonFor(err)
			}
			break
		}
		reqCount++
		if first == nil {
			first = req
		}
		worst = worstStatus(worst, req.status)

		resp := routeResponse(ctx.PortCfg, req)
		if err := writeResponse(conn, resp, ctx.PortCfg.ServerHeader, req, ctx.LinkPool); err != nil {
			if ctx.Builder.CloseReason == "" {
				ctx.Builder.CloseReason = "error"
			}
			break
		}
		if maxed, ok := conn.(*sessionConn); ok && maxed.Maxed() {
			ctx.Builder.CloseReason = "max_bytes"
			break
		}
		if strings.Contains(strings.ToLower(req.Headers["Connection"]), "close") {
			ctx.Builder.CloseReason = "client_requested_close"
			break
		}
		if reqCount >= ctx.Limits.MaxHTTPReqs {
			ctx.Builder.CloseReason = "max_http_reqs"
			break
		}
		SetIdle(conn, ctx.Limits)
	}

	if first != nil {
		ctx.Builder.Parsed = map[string]interface{}{
			"method":         first.Method,
			"path":           first.Path,
			"http_version":   first.Version,
			"headers":        first.Headers,
			"body_b64":       base64.StdEncoding.EncodeToString(first.Body),
			"body_truncated": first.BodyTruncated,
			"req_count":      reqCount,
		}
	}
	ctx.Builder.ParseStatus = worst
	if ctx.Builder.Banner == "" {
		ctx.Builder.Banner = ctx.PortCfg.ServerHeader
	}
}

func parseRequest(r *bufio.Reader, lim config.Limits) (*parsedReq, error) {
	req := &parsedReq{Headers: map[string]string{}, status: "ok"}

	// 请求行：容忍 \n / \r\n / 裸 \r，多个连续空格
	line, err := readLine(r, lim.MaxLineBytes)
	if err != nil {
		return nil, err
	}
	var toks []string
	for _, p := range strings.Split(string(line), " ") {
		if p != "" {
			toks = append(toks, p)
		}
	}
	if len(toks) == 0 {
		// 空行（keep-alive 连接间的多余空行），跳过继续
		req.status = "partial"
		return req, nil
	}
	if !isToken(toks[0]) {
		req.status = "failed"
	}
	req.Method = toks[0]
	if len(toks) >= 2 {
		req.Path = toks[1]
	}
	if len(toks) >= 3 {
		req.Version = toks[2]
	}
	if len(toks) < 2 {
		req.status = "failed"
	}

	// 头区
	for {
		hl, err := readLine(r, lim.MaxLineBytes)
		if err != nil {
			req.status = "partial"
			return req, nil
		}
		if len(hl) == 0 {
			break
		}
		if len(req.Headers) >= 100 { // 头洪水上限
			req.status = "partial"
			break
		}
		idx := bytes.IndexByte(hl, ':')
		if idx <= 0 {
			req.status = "partial"
			continue
		}
		k := strings.TrimSpace(string(hl[:idx]))
		v := strings.TrimSpace(string(hl[idx+1:]))
		req.Headers[k] = v
	}

	// body：RFC 7230 —— Transfer-Encoding 优先于 Content-Length
	if te, ok := req.Headers["Transfer-Encoding"]; ok && strings.Contains(strings.ToLower(te), "chunked") {
		body, trunc, st := readChunked(r, lim.MaxBodyBytes)
		req.Body, req.BodyTruncated = body, trunc
		if st != "" {
			req.status = st
		}
		return req, nil
	}
	if cl, ok := req.Headers["Content-Length"]; ok {
		n, err := strconv.Atoi(strings.TrimSpace(cl))
		if err != nil || n < 0 {
			req.status = "partial"
			return req, nil
		}
		if n > 0 {
			toRead := n
			trunc := false
			if toRead > lim.MaxBodyBytes {
				toRead = lim.MaxBodyBytes
				trunc = true
			}
			buf := make([]byte, toRead)
			if _, err := io.ReadFull(r, buf); err != nil {
				req.status = "partial"
				return req, nil
			}
			req.Body, req.BodyTruncated = buf, trunc
			if trunc {
				req.status = "partial"
			}
		}
	}
	return req, nil
}

// readLine 读到 \n 结束（strip \r）；裸 \r 也视为行结束；超 max 返回行截断错误
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	line := make([]byte, 0, 256)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return line, err
		}
		if len(line) >= max {
			return line, errors.New("line too long")
		}
		switch b {
		case '\n':
			return line, nil
		case '\r':
			nb, err := r.ReadByte()
			if err != nil {
				return line, nil // \r 后无数据：视为行结束（容错）
			}
			if nb != '\n' {
				_ = r.UnreadByte() // 裸 \r：下一字节属于下一行
			}
			return line, nil
		default:
			line = append(line, b)
		}
	}
}

// readChunked 读取 chunked body，总长上限 max
func readChunked(r *bufio.Reader, max int) (body []byte, truncated bool, status string) {
	for {
		sizeLine, err := readLine(r, 1024)
		if err != nil {
			return body, truncated, "partial"
		}
		szStr := sizeLine
		if i := bytes.IndexByte(szStr, ';'); i >= 0 {
			szStr = szStr[:i] // 去 chunk extension
		}
		sz, err := strconv.ParseInt(strings.TrimSpace(string(szStr)), 16, 32)
		if err != nil || sz < 0 {
			return body, true, "partial"
		}
		if sz == 0 {
			// 吃掉 trailer 直到空行
			for {
				tl, err := readLine(r, 4096)
				if err != nil || len(tl) == 0 {
					break
				}
			}
			return body, truncated, ""
		}
		if sz > int64(max-len(body)) {
			// 超过解析上限：丢弃剩余（保持 chunk 同步），标记截断
			truncated = true
			status = "partial"
			left := sz
			skip := make([]byte, 32<<10)
			for left > 0 {
				n := int64(len(skip))
				if left < n {
					n = left
				}
				if _, err := io.ReadFull(r, skip[:n]); err != nil {
					return body, truncated, "partial"
				}
				left -= n
			}
		} else {
			chunk := make([]byte, sz)
			if _, err := io.ReadFull(r, chunk); err != nil {
				return body, truncated, "partial"
			}
			body = append(body, chunk...)
		}
		_, _ = readLine(r, 8) // chunk 后 CRLF（容忍缺失）
	}
}

// routeResponse 按路径路由响应；含 query 时先剥 query；可选 prefix 匹配
func routeResponse(pc *config.PortConfig, req *parsedReq) *config.HTTPResponse {
	path := req.Path
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if r, ok := pc.Responses[path]; ok {
		return &r
	}
	if pc.PrefixMatch {
		keys := make([]string, 0, len(pc.Responses))
		for p := range pc.Responses {
			keys = append(keys, p)
		}
		// 最长前缀优先
		for i := 0; i < len(keys); i++ {
			for j := i + 1; j < len(keys); j++ {
				if len(keys[j]) > len(keys[i]) {
					keys[i], keys[j] = keys[j], keys[i]
				}
			}
		}
		for _, p := range keys {
			if strings.HasPrefix(path, p) {
				r := pc.Responses[p]
				return &r
			}
		}
	}
	if pc.Fallback != nil {
		return pc.Fallback
	}
	return &config.HTTPResponse{Status: 404, Body: "Not Found"}
}

func writeResponse(conn net.Conn, r *config.HTTPResponse, serverHeader string,
	req *parsedReq, linkPool []string) error {
	status := r.Status
	if status == 0 {
		status = 200
	}
	body := []byte(expandRand(r.Body))
	statusText := http.StatusText(status)
	if statusText == "" {
		statusText = "OK"
	}
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + strconv.Itoa(status) + " " + statusText + "\r\n")
	if serverHeader != "" {
		b.WriteString("Server: " + serverHeader + "\r\n")
	}
	wroteCT := false
	for k, v := range r.Headers {
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Connection") {
			continue // 由本函数统一生成
		}
		if strings.EqualFold(k, "Content-Type") {
			wroteCT = true
		}
		b.WriteString(k + ": " + expandRand(v) + "\r\n")
	}
	if !wroteCT {
		b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	}
	body = injectLures(body, r, req, linkPool)
	b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	b.WriteString("Connection: close\r\n\r\n")
	_, err := conn.Write(append([]byte(b.String()), body...))
	return err
}

// injectLures 注入网站漏扫诱饵：链接图谱 + 表单 + 参数反射。
// 目标：让爬虫跟随发现深层路径、让 XSS 反射检测器发现反射点、让表单测试器提交参数。
func injectLures(body []byte, r *config.HTTPResponse, req *parsedReq, linkPool []string) []byte {
	var extra strings.Builder

	// 1. 链接图谱：首页 12 个链接，其他路径 4 个（互链让爬虫深入）
	if !r.NoLinks && len(linkPool) > 0 {
		n := 4
		if req.Path == "/" || req.Path == "" {
			n = 12
		}
		links := linkPool
		if n > len(links) {
			n = len(links)
		}
		extra.WriteString(`<div class="nav">`)
		for _, p := range links[:n] {
			extra.WriteString(`<a href="` + htmlEscape(p) + `">` + htmlEscape(strings.Trim(p, "/")) + `</a> `)
		}
		extra.WriteString(`</div>`)
	}

	// 2. 表单诱饵：POST 参数组合捕获
	if r.Form {
		action := htmlEscape(req.Path)
		extra.WriteString(`<form action="` + action + `" method="POST">`)
		for _, field := range []string{"username", "password", "email", "remember", "q"} {
			extra.WriteString(`<input type="text" name="` + field + `" value="">`)
		}
		extra.WriteString(`<button type="submit">Submit</button></form>`)
	}

	// 3. 参数反射：query 参数值回显（不转义——触发 XSS 反射检测，诱出 payload 变体）
	reflects := reflectParams(req.Path, 3)
	reflects = append(reflects, reflectPayloads(req, 2)...) // body/header 特征串回显（漏洞确认诱饵）
	for _, v := range reflects {
		extra.WriteString(`<div class="result">` + v + `</div>`)
	}

	if extra.Len() == 0 {
		return body
	}
	out := make([]byte, 0, len(body)+extra.Len())
	out = append(out, body...)
	out = append(out, extra.String()...)
	return out
}

// reflectParams 提取 query 参数值用于反射（≤64 字符、可打印、非空，最多 count 个）
func reflectParams(path string, count int) []string {
	i := strings.IndexByte(path, '?')
	if i < 0 {
		return nil
	}
	q, err := url.ParseQuery(path[i+1:])
	if err != nil {
		return nil
	}
	var out []string
	for _, vals := range q {
		for _, v := range vals {
			if v == "" || len(v) > 64 {
				continue
			}
			printable := true
			for _, c := range v {
				if c < 0x20 || c == 0x7f {
					printable = false
					break
				}
			}
			if !printable {
				continue
			}
			out = append(out, v)
			if len(out) >= count {
				return out
			}
		}
	}
	return out
}

// reflectPayloads 提取 body/header 中的漏洞特征串用于回显（漏洞确认诱饵）。
// struts2/shiro/log4j 等回显型检测器：发 payload 后检查响应是否原样回显——
// 回显即"确认漏洞存在"，随后扫描器会进入利用阶段发完整 RCE 链。
func reflectPayloads(req *parsedReq, count int) []string {
	var out []string
	// body 中的特征片段（含 OGNL/JNDI/命令等特征词的 ≤64 字符片段）
	body := req.Body
	markers := []string{"${", "%{", "#{", "{{", "jndi:", "<script", "cmd", "exec", "Runtime", "ognl"}
	if len(body) > 0 {
		text := string(body)
		for _, m := range markers {
			idx := strings.Index(text, m)
			if idx < 0 {
				continue
			}
			start := idx - 8
			if start < 0 {
				start = 0
			}
			end := idx + 64
			if end > len(text) {
				end = len(text)
			}
			seg := text[start:end]
			if isPrintable(seg) {
				out = append(out, seg)
				if len(out) >= count {
					return out
				}
			}
		}
	}
	// header 中的特征值（如 struts2 的 Content-Type OGNL）
	for k, v := range req.Headers {
		low := strings.ToLower(v)
		for _, m := range []string{"${", "%{", "jndi:", "ognl"} {
			if strings.Contains(low, m) && len(v) <= 128 && isPrintable(v) {
				out = append(out, v)
				if len(out) >= count {
					return out
				}
			}
		}
		_ = k
	}
	return out
}

func isPrintable(s string) bool {
	for _, c := range s {
		if c < 0x20 && c != '\n' && c != '\r' && c != '\t' {
			return false
		}
	}
	return true
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

// expandRand 把 $rand16 占位符展开为 16 位随机 hex（每次出现独立）
func expandRand(s string) string {
	if !strings.Contains(s, "$rand16") {
		return s
	}
	var sb strings.Builder
	for {
		i := strings.Index(s, "$rand16")
		if i < 0 {
			sb.WriteString(s)
			break
		}
		sb.WriteString(s[:i])
		sb.WriteString(randHex(16))
		s = s[i+len("$rand16"):]
	}
	return sb.String()
}

func randHex(n int) string {
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		// 加密随机失败时退化为时间戳（仅影响诱导质量，不影响捕获）
		b = []byte(strconv.FormatInt(time.Now().UnixMilli(), 10))
	}
	return hex.EncodeToString(b)
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))
		if !ok {
			return false
		}
	}
	return true
}

func worstStatus(a, b string) string {
	rank := func(s string) int {
		switch s {
		case "failed":
			return 2
		case "partial":
			return 1
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

func closeReasonFor(err error) string {
	if err == nil {
		return "closed"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "idle_timeout"
	}
	if errors.Is(err, io.EOF) {
		return "client_closed"
	}
	return "error"
}
