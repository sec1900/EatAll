// EatAll 捕获代理：多协议蜜罐，捕获攻击流量到 data/sessions/*.jsonl
package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"eatal/internal/config"
	"eatal/internal/listener"
	"eatal/internal/session"
)

func main() {
	var (
		cfgPath   = flag.String("config", "config/config.yaml", "主配置路径")
		bannerP   = flag.String("banners", "config/banners.yaml", "诱导层配置路径")
		sessDir   = flag.String("sessions", "", "会话输出目录（默认取配置）")
		logFile   = flag.String("log", "", "日志文件（默认取配置）")
		shutdown  = flag.Duration("shutdown-timeout", 5*time.Second, "优雅退出等待上限")
	)
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}
	if *sessDir != "" {
		cfg.SessionsDir = *sessDir
	}
	if *logFile != "" {
		cfg.LogFile = *logFile
	}
	banners, err := config.LoadBanners(*bannerP)
	if err != nil {
		slog.Error("load banners", "err", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.LogFile)
	logger.Info("eatal proxy starting",
		"config", *cfgPath, "sessions", cfg.SessionsDir, "ports", cfg.ListenPorts)

	if err := os.MkdirAll(cfg.SessionsDir, 0o755); err != nil {
		logger.Error("mkdir sessions", "err", err)
		os.Exit(1)
	}
	if cfg.LogFile != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.LogFile), 0o755); err != nil {
			logger.Error("mkdir logs", "err", err)
			os.Exit(1)
		}
	}

	sess, err := session.NewWriter(cfg.SessionsDir)
	if err != nil {
		logger.Error("init session writer", "err", err)
		os.Exit(1)
	}
	defer sess.Close()

	mgr := listener.New(cfg, banners, sess, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := mgr.Start(ctx); err != nil {
		logger.Error("start listeners", "err", err)
		os.Exit(1)
	}

	// 周期 flush：让 ingest 管道能在 ~1s 内看到新会话（bufio 缓冲 64KB 太久）
	flushTicker := time.NewTicker(time.Second)
	defer flushTicker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-flushTicker.C:
				if err := sess.Flush(); err != nil {
					logger.Error("flush sessions", "err", err)
				}
			}
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	mgr.Shutdown(*shutdown)
	logger.Info("bye")
}

func newLogger(path string) *slog.Logger {
	level := slog.LevelInfo
	opts := &slog.HandlerOptions{Level: level}
	if path == "" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	multi := io.MultiWriter(f, os.Stderr)
	return slog.New(slog.NewTextHandler(multi, opts))
}
