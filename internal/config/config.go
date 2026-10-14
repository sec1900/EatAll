package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Limits 资源护栏：所有上限默认值见 DefaultLimits
type Limits struct {
	MaxConnsPerIP   int `yaml:"max_conns_per_ip"`
	MaxSessionBytes int `yaml:"max_session_bytes"`  // 单方向字节上限
	IdleTimeoutSec  int `yaml:"idle_timeout_sec"`   // 单次读空闲超时
	MaxSessionSec   int `yaml:"max_session_sec"`    // 会话最大时长
	MaxHTTPReqs     int `yaml:"max_http_reqs_per_conn"`
	MaxLineBytes    int `yaml:"max_line_bytes"` // HTTP 单行上限
	MaxBodyBytes    int `yaml:"max_body_bytes"` // HTTP body 解析上限
	MaxGlobalConns  int `yaml:"max_global_conns"`
}

func (l *Limits) FillDefaults() {
	if l.MaxConnsPerIP == 0 {
		l.MaxConnsPerIP = 50
	}
	if l.MaxSessionBytes == 0 {
		l.MaxSessionBytes = 1 << 20
	}
	if l.IdleTimeoutSec == 0 {
		l.IdleTimeoutSec = 15
	}
	if l.MaxSessionSec == 0 {
		l.MaxSessionSec = 60
	}
	if l.MaxHTTPReqs == 0 {
		l.MaxHTTPReqs = 10
	}
	if l.MaxLineBytes == 0 {
		l.MaxLineBytes = 64 << 10
	}
	if l.MaxBodyBytes == 0 {
		l.MaxBodyBytes = 64 << 10
	}
	if l.MaxGlobalConns == 0 {
		l.MaxGlobalConns = 1024
	}
}

type Config struct {
	ListenPorts []string `yaml:"listen_ports"`
	SessionsDir string   `yaml:"sessions_dir"`
	LogFile     string   `yaml:"log_file"`
	Limits      Limits   `yaml:"limits"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.Limits.FillDefaults()
	return &cfg, nil
}
