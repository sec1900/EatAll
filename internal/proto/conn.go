package proto

import (
	"log/slog"
	"net"
	"time"

	"eatal/internal/config"
	"eatal/internal/session"
)

// ConnCtx 传给各协议 handler 的连接级上下文
type ConnCtx struct {
	Builder  *session.Builder
	PortCfg  *config.PortConfig
	Limits   config.Limits
	Log      *slog.Logger
	LinkPool []string // 链接图谱伪路径池（网站漏扫爬虫诱饵）
}

// sessionConn 包装 net.Conn：读/写时同步把原始字节记入会话缓冲（带上限）
type sessionConn struct {
	net.Conn
	client      *session.ByteBuf
	server      *session.ByteBuf
	clientMaxed bool
	serverMaxed bool
}

func (c *sessionConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && !c.clientMaxed {
		if !c.client.Append(p[:n]) {
			c.clientMaxed = true
		}
	}
	return n, err
}

func (c *sessionConn) Write(p []byte) (int, error) {
	if len(p) > 0 && !c.serverMaxed {
		if !c.server.Append(p) {
			c.serverMaxed = true
		}
	}
	return c.Conn.Write(p)
}

func (c *sessionConn) Maxed() bool { return c.clientMaxed || c.serverMaxed }

// Wrap 包装连接并初始化会话缓冲
func Wrap(conn net.Conn, ctx *ConnCtx) *sessionConn {
	return &sessionConn{
		Conn:   conn,
		client: ctx.Builder.Client,
		server: ctx.Builder.Server,
	}
}

// SetIdle 设置单次读空闲超时
func SetIdle(c net.Conn, limits config.Limits) {
	_ = c.SetReadDeadline(time.Now().Add(time.Duration(limits.IdleTimeoutSec) * time.Second))
}

// SetSessionDeadline 设置会话总时长上限
func SetSessionDeadline(c net.Conn, limits config.Limits) {
	_ = c.SetDeadline(time.Now().Add(time.Duration(limits.MaxSessionSec) * time.Second))
}
