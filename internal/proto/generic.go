package proto

import (
	"bufio"
	"net"
	"strings"
)

// HandleGeneric 兜底 handler：可选回 banner，纯原始字节记录至超时/关闭。
// 关键增强：若客户端首块数据是 HTTP 请求（扫描器对任意端口打 HTTP POC——
// 如 WebLogic 7001 端口被打 wls-wsat 反序列化），自动转 HTTP 解析，让
// 攻击流量进入 parsed 字段和 POC 重建管线。
func HandleGeneric(conn net.Conn, ctx *ConnCtx) {
	sc := Wrap(conn, ctx)
	defer sc.Close()
	SetSessionDeadline(sc, ctx.Limits)

	if ctx.PortCfg.Banner != "" {
		ctx.Builder.Banner = ctx.PortCfg.Banner
		if _, err := sc.Write([]byte(ctx.PortCfg.Banner)); err != nil {
			ctx.Builder.CloseReason = "error"
			return
		}
	}

	r := bufio.NewReaderSize(sc, 8<<10)
	// HTTP 识别：peek 首 16 字节（不消费）
	if head, err := r.Peek(16); err == nil && looksLikeHTTP(head) {
		ctx.Builder.ProtoConf = "http" // 修正协议标记（影响 parsed 与 POC 重建）
		handleHTTPLoopReader(sc, r, ctx)
		return
	}

	// 纯 generic 记录循环
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
	ctx.Builder.Parsed = map[string]interface{}{}
}

// looksLikeHTTP 判断首块字节是否 HTTP 请求行（方法 + 空格开头）
func looksLikeHTTP(b []byte) bool {
	upper := strings.ToUpper(string(b))
	for _, m := range []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
		"OPTIONS ", "PATCH ", "TRACE ", "CONNECT ", "PROPFIND ", "M-SEARCH "} {
		if strings.HasPrefix(upper, m) {
			return true
		}
	}
	return false
}
