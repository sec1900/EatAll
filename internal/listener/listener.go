// Package listener 管理多端口监听：每端口一个 goroutine + 每连接 goroutine，
// per-IP 限流 + 全局并发信号量，单端口失败只告警不阻塞，支持优雅退出。
package listener

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"eatal/internal/config"
	"eatal/internal/proto"
	"eatal/internal/rate"
	"eatal/internal/session"
)

type Manager struct {
	cfg     *config.Config
	banners *config.Banners
	sess    *session.Writer
	log     *slog.Logger
	limiter *rate.Limiter
	sem     chan struct{}

	mu              sync.Mutex
	listeners       []io.Closer
	wg              sync.WaitGroup
	closed          bool
	listenFailWarns int // 全端口模式下批量告警聚合
}

func New(cfg *config.Config, banners *config.Banners, sess *session.Writer, log *slog.Logger) *Manager {
	return &Manager{
		cfg:     cfg,
		banners: banners,
		sess:    sess,
		log:     log,
		limiter: rate.New(cfg.Limits.MaxConnsPerIP),
		sem:     make(chan struct{}, cfg.Limits.MaxGlobalConns),
	}
}

// Start 解析端口表并启动监听。单端口失败只告警，不阻塞其他端口。
func (m *Manager) Start(ctx context.Context) error {
	ports, err := parsePortSpecs(m.cfg.ListenPorts)
	if err != nil {
		return err
	}
	for _, p := range ports {
		pc := m.banners.Port(p.port)
		if p.transport == "udp" {
			m.wg.Add(1)
			go m.serveUDP(ctx, p.port, &pc)
			continue
		}
		m.wg.Add(1)
		go m.serveTCP(ctx, p.port, &pc)
	}
	return nil
}

type portSpec struct {
	port      int
	transport string
}

func parsePortSpecs(specs []string) ([]portSpec, error) {
	var out []portSpec
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		transport := "tcp"
		if i := strings.Index(spec, "/"); i >= 0 {
			transport = strings.ToLower(spec[i+1:])
			spec = spec[:i]
		}
		if transport != "tcp" && transport != "udp" {
			return nil, fmt.Errorf("bad transport in port spec %q", spec)
		}
		if strings.Contains(spec, "-") {
			parts := strings.SplitN(spec, "-", 2)
			lo, err1 := strconv.Atoi(parts[0])
			hi, err2 := strconv.Atoi(parts[1])
			if err1 != nil || err2 != nil || lo <= 0 || hi < lo || hi > 65535 {
				return nil, fmt.Errorf("bad port range %q", spec)
			}
			for p := lo; p <= hi; p++ {
				out = append(out, portSpec{p, transport})
			}
			continue
		}
		p, err := strconv.Atoi(spec)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("bad port %q", spec)
		}
		out = append(out, portSpec{p, transport})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].port < out[j].port })
	return out, nil
}

func (m *Manager) serveTCP(ctx context.Context, port int, pc *config.PortConfig) {
	defer m.wg.Done()
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		// 全端口模式下系统占用端口会批量失败——前 20 个逐个告警，之后静默
		m.mu.Lock()
		if m.listenFailWarns < 20 {
			m.listenFailWarns++
			m.mu.Unlock()
			m.log.Warn("listen failed", "port", port, "err", err)
		} else {
			m.mu.Unlock()
		}
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = ln.Close()
		return
	}
	m.listeners = append(m.listeners, ln)
	m.mu.Unlock()
	m.log.Info("listening", "port", port, "proto", pc.Proto, "transport", "tcp")

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
		}
		m.wg.Add(1)
		go m.handleConn(ctx, conn, pc)
	}
}

func (m *Manager) handleConn(ctx context.Context, conn net.Conn, pc *config.PortConfig) {
	defer m.wg.Done()

	remote := conn.RemoteAddr().(*net.TCPAddr)
	ip := remote.IP.String()

	select {
	case m.sem <- struct{}{}:
		defer func() { <-m.sem }()
	case <-ctx.Done():
		_ = conn.Close()
		return
	}

	if !m.limiter.Acquire(ip) {
		// 超限：写一条摘要会话（无流量），直接 RST
		ts := time.Now().UnixMilli()
		b := session.NewBuilder(ts, ip, remote.Port, conn.LocalAddr().(*net.TCPAddr).Port, "tcp", pc.Proto)
		b.Client = session.NewByteBuf(0)
		b.Server = session.NewByteBuf(0)
		b.ParseStatus = "ok"
		b.Finalize(ts, "rate_limited")
		_ = m.sess.Write(&b.Session)
		_ = conn.Close()
		return
	}
	defer m.limiter.Release(ip)

	b := session.NewBuilder(time.Now().UnixMilli(), ip, remote.Port,
		conn.LocalAddr().(*net.TCPAddr).Port, "tcp", pc.Proto)
	b.Client = session.NewByteBuf(m.cfg.Limits.MaxSessionBytes)
	b.Server = session.NewByteBuf(m.cfg.Limits.MaxSessionBytes)
	b.SetDstIP(conn.LocalAddr().(*net.TCPAddr).IP.String())

	ctx2 := &proto.ConnCtx{
		Builder:  b,
		PortCfg:  pc,
		Limits:   m.cfg.Limits,
		Log:      m.log,
		LinkPool: m.banners.LinkPool,
	}
	handleProto(conn, ctx2)
	if b.CloseReason == "" {
		b.CloseReason = "closed"
	}
	b.Finalize(time.Now().UnixMilli(), b.CloseReason)
	if err := m.sess.Write(&b.Session); err != nil {
		m.log.Error("write session", "err", err)
	}
}

// serveUDP 通用 UDP 捕获：按 (src_ip, src_port) 聚合 10s 窗口
func (m *Manager) serveUDP(ctx context.Context, port int, pc *config.PortConfig) {
	defer m.wg.Done()
	addr := fmt.Sprintf(":%d", port)
	pcx, err := net.ListenPacket("udp", addr)
	if err != nil {
		m.log.Warn("udp listen failed", "port", port, "err", err)
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = pcx.Close()
		return
	}
	m.listeners = append(m.listeners, pcx)
	m.mu.Unlock()
	m.log.Info("listening", "port", port, "proto", pc.Proto, "transport", "udp")

	go func() {
		<-ctx.Done()
		_ = pcx.Close()
	}()

	// windows: src -> 聚合会话
	type window struct {
		builder  *session.Builder
		buf      *session.ByteBuf
		queries  []map[string]interface{}
		replies  int
	}
	windows := make(map[string]*window)
	var wmu sync.Mutex

	// flush：在锁内摘除并取出会话，锁外落盘（避免与追加竞态）
	flush := func(key string, reason string) {
		wmu.Lock()
		w, ok := windows[key]
		delete(windows, key)
		wmu.Unlock()
		if !ok {
			return
		}
		if pc.Proto == "dns" {
			// 空切片而非 nil：nil 会被 JSON 序列化为 null，Python 侧迭代崩溃
			queries := w.queries
			if queries == nil {
				queries = []map[string]interface{}{}
			}
			parsed := map[string]interface{}{"queries": queries, "replies_sent": w.replies}
			w.builder.Parsed = parsed
		} else {
			w.builder.Parsed = map[string]interface{}{}
		}
		w.builder.Finalize(time.Now().UnixMilli(), reason)
		_ = m.sess.Write(&w.builder.Session)
	}
	// 定期清理超窗会话
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-t.C:
				wmu.Lock()
				for k, w := range windows {
					if now.UnixMilli()-w.builder.TsStart > 10_000 {
						wmu.Unlock()
						flush(k, "udp_window_end")
						wmu.Lock()
					}
				}
				wmu.Unlock()
			}
		}
	}()

	buf := make([]byte, 64<<10)
	for {
		n, raddr, err := pcx.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			return
		}
		if n == 0 {
			continue
		}
		key := raddr.String()
		wmu.Lock()
		w, ok := windows[key]
		if !ok {
			b := session.NewBuilder(time.Now().UnixMilli(), raddr.(*net.UDPAddr).IP.String(),
				raddr.(*net.UDPAddr).Port, port, "udp", pc.Proto)
			b.SetDstIP(pcx.LocalAddr().(*net.UDPAddr).IP.String())
			w = &window{builder: b, buf: session.NewByteBuf(m.cfg.Limits.MaxSessionBytes)}
			windows[key] = w
		}
		w.buf.Append(buf[:n])
		if pc.Proto == "dns" {
			if qname, qtype, ok := proto.ParseDNSQuery(buf[:n]); ok {
				w.queries = append(w.queries, map[string]interface{}{"qname": qname, "qtype": qtype})
				if pc.AnswerIP != "" {
					reply := proto.BuildDNSReply(buf[:n], pc.AnswerIP)
					if reply != nil {
						if _, err := pcx.WriteTo(reply, raddr); err == nil {
							w.replies++
						}
					}
				}
			}
		}
		wmu.Unlock()
	}
}

// handleProto 按配置协议分发；未知协议回退 generic
func handleProto(conn net.Conn, ctx *proto.ConnCtx) {
	switch ctx.PortCfg.Proto {
	case "http":
		proto.HandleHTTP(conn, ctx)
	case "tls-http":
		proto.HandleTLS(conn, ctx)
	case "ssh":
		proto.HandleSSH(conn, ctx)
	case "mysql":
		proto.HandleMySQL(conn, ctx)
	case "postgres":
		proto.HandlePostgres(conn, ctx)
	case "mongodb":
		proto.HandleMongoDB(conn, ctx)
	case "redis":
		proto.HandleRedis(conn, ctx)
	case "ftp":
		proto.HandleFTP(conn, ctx)
	case "smb":
		proto.HandleSMB(conn, ctx)
	default:
		proto.HandleGeneric(conn, ctx)
	}
}

// Shutdown 关闭所有监听并等待 in-flight 会话写完
func (m *Manager) Shutdown(timeout time.Duration) {
	m.mu.Lock()
	m.closed = true
	for _, l := range m.listeners {
		_ = l.Close()
	}
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		m.log.Warn("shutdown timeout, some sessions may be lost")
	}
	if err := m.sess.Flush(); err != nil {
		m.log.Error("flush sessions", "err", err)
	}
}
