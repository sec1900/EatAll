package config

import (
	"fmt"
	"os"
	"sort"
	"strconv"

	"gopkg.in/yaml.v3"
)

// HTTPResponse 一条伪路径的响应模板
type HTTPResponse struct {
	Status  int               `yaml:"status"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
	Form    bool              `yaml:"form"` // 自动追加登录表单诱饵（捕获 POST 参数组合）
	NoLinks bool              `yaml:"no_links"` // 不追加链接图谱
}

// rawPortEntry 端口条目原始形态：use 引用 + 内联的端口配置字段
type rawPortEntry struct {
	Use        string `yaml:"use"`
	PortConfig `yaml:",inline"`
}

// PortConfig 单个端口的完整配置（merge 解析后的形态）
type PortConfig struct {
	Proto         string                  `yaml:"proto"`
	ServerHeader  string                  `yaml:"server_header"`
	Responses     map[string]HTTPResponse `yaml:"responses"`
	Fallback      *HTTPResponse           `yaml:"fallback"`
	PrefixMatch   bool                    `yaml:"prefix_match"`
	Version       string                  `yaml:"version"`       // ssh banner，如 SSH-2.0-OpenSSH_7.4
	StaticKexinit bool                    `yaml:"static_kexinit"` // ssh 是否回静态 kexinit
	ServerVersion string                  `yaml:"server_version"` // mysql 版本
	AuthPlugin    string                  `yaml:"auth_plugin"`    // mysql 认证插件
	AuthReply     string                  `yaml:"auth_reply"`     // mysql 认证回应: err|ok
	ReplyMode     string                  `yaml:"reply_mode"`     // redis: info|ok|err
	InfoReply     string                  `yaml:"info_reply"`     // redis 伪造 INFO 块
	Banner        string                  `yaml:"banner"`         // ftp/generic banner
	LoginAccept   bool                    `yaml:"login_accept"`   // ftp PASS 是否 230
	NegReply      string                  `yaml:"negotiate_reply"` // smb: static|none
	Transport     string                  `yaml:"transport"`      // tcp|udp
	AnswerIP      string                  `yaml:"answer_ip"`      // dns static_a 回包 IP
	Cert          string                  `yaml:"cert"`           // tls
	Key           string                  `yaml:"key"`            // tls
}

func (p *PortConfig) IsHTTP() bool {
	return p.Proto == "http" || p.Proto == "tls-http"
}

func (p *PortConfig) TransportOrDefault() string {
	if p.Transport == "udp" {
		return "udp"
	}
	return "tcp"
}

// Banners 诱导层配置。
// 解析时先读成 map 再按 "use" 引用做深合并（map 合并、标量覆盖、指针可覆盖），
// 避免 YAML 零值无法区分"未设置"的问题。
type Banners struct {
	Named    map[string]PortConfig `yaml:"named"`
	Ports    map[string]PortConfig `yaml:"ports"`
	LinkPool []string              `yaml:"link_pool"` // 链接图谱伪路径池（爬虫诱饵）
	// defaultPort 是 "default" 条目解析后的兜底配置
	defaultPort PortConfig
	hasDefault  bool
}

// PoolLinks 取链接池中随机 count 个路径（首页 12-15 个，伪路径 3-5 个）
func (b *Banners) PoolLinks(count int) []string {
	if len(b.LinkPool) == 0 {
		return nil
	}
	n := count
	if n > len(b.LinkPool) {
		n = len(b.LinkPool)
	}
	// 取池中前 n 个（池配置即路径顺序，确定性优于随机——爬虫可复现）
	return b.LinkPool[:n]
}

func LoadBanners(path string) (*Banners, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read banners %s: %w", path, err)
	}

	// 第一遍：读成 raw map，保留字段存在性
	var root map[string]yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse banners %s: %w", path, err)
	}
	b := &Banners{Named: map[string]PortConfig{}, Ports: map[string]PortConfig{}}

	if lpNode, ok := root["link_pool"]; ok {
		var pool []string
		if err := lpNode.Decode(&pool); err != nil {
			return nil, fmt.Errorf("parse link_pool: %w", err)
		}
		b.LinkPool = pool
	}

	namedNode, _ := root["named"]
	namedRaw, _ := mapOf(&namedNode)
	for name, node := range namedRaw {
		var pc PortConfig
		if err := node.Decode(&pc); err != nil {
			return nil, fmt.Errorf("parse named %q: %w", name, err)
		}
		b.Named[name] = pc
	}

	portsNode, _ := root["ports"]
	portsRaw, _ := mapOf(&portsNode)
	keys := make([]string, 0, len(portsRaw))
	for k := range portsRaw {
		keys = append(keys, k)
	}
	sort.Strings(keys) // 固定处理顺序，default 最后解析
	for _, key := range keys {
		node := portsRaw[key]
		var entry rawPortEntry
		if err := node.Decode(&entry); err != nil {
			return nil, fmt.Errorf("parse port %q: %w", key, err)
		}
		pc := entry.PortConfig
		if entry.Use != "" {
			base, ok := b.Named[entry.Use]
			if !ok {
				return nil, fmt.Errorf("port %q references unknown named config %q", key, entry.Use)
			}
			merged, err := mergeOverlay(&node, base)
			if err != nil {
				return nil, fmt.Errorf("merge port %q: %w", key, err)
			}
			pc = merged
		}
		if key == "default" {
			b.defaultPort = pc
			b.hasDefault = true
			continue
		}
		b.Ports[key] = pc
	}
	return b, nil
}

// mapOf 取 mapping 节点下所有 key->node
func mapOf(n *yaml.Node) (map[string]yaml.Node, bool) {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, false
	}
	m := make(map[string]yaml.Node, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		m[n.Content[i].Value] = *n.Content[i+1]
	}
	return m, true
}

// mergeOverlay 把 port 条目（含 use）叠加到 named 基础上。
// 规则：仅覆盖"显式出现"的字段；responses map 做 key 级合并；标量直接覆盖。
func mergeOverlay(portNode *yaml.Node, base PortConfig) (PortConfig, error) {
	fields, ok := mapOf(portNode)
	if !ok {
		return base, nil
	}
	out := base
	for k, node := range fields {
		switch k {
		case "use":
			// 已处理
		case "responses":
			var add map[string]HTTPResponse
			if err := node.Decode(&add); err != nil {
				return out, err
			}
			if out.Responses == nil {
				out.Responses = map[string]HTTPResponse{}
			}
			for p, r := range add {
				out.Responses[p] = r
			}
		case "fallback":
			var fb HTTPResponse
			if err := node.Decode(&fb); err != nil {
				return out, err
			}
			out.Fallback = &fb
		default:
			// 标量：包成单键 mapping 再解码（node 本身是标量值，直接 decode 进 struct 会报错）
			var tmp PortConfig
			mapping := yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: k},
					&node,
				},
			}
			if err := mapping.Decode(&tmp); err != nil {
				return out, err
			}
			applyScalar(&out, k, &tmp)
		}
	}
	return out, nil
}

func applyScalar(dst *PortConfig, key string, src *PortConfig) {
	switch key {
	case "proto":
		dst.Proto = src.Proto
	case "server_header":
		dst.ServerHeader = src.ServerHeader
	case "prefix_match":
		dst.PrefixMatch = src.PrefixMatch
	case "version":
		dst.Version = src.Version
	case "static_kexinit":
		dst.StaticKexinit = src.StaticKexinit
	case "server_version":
		dst.ServerVersion = src.ServerVersion
	case "auth_plugin":
		dst.AuthPlugin = src.AuthPlugin
	case "auth_reply":
		dst.AuthReply = src.AuthReply
	case "reply_mode":
		dst.ReplyMode = src.ReplyMode
	case "info_reply":
		dst.InfoReply = src.InfoReply
	case "banner":
		dst.Banner = src.Banner
	case "login_accept":
		dst.LoginAccept = src.LoginAccept
	case "negotiate_reply":
		dst.NegReply = src.NegReply
	case "transport":
		dst.Transport = src.Transport
	case "answer_ip":
		dst.AnswerIP = src.AnswerIP
	case "cert":
		dst.Cert = src.Cert
	case "key":
		dst.Key = src.Key
	}
}

// Port 按端口号取配置，无则回 default（仍无则给一个 generic 兜底）
func (b *Banners) Port(port int) PortConfig {
	if pc, ok := b.Ports[strconv.Itoa(port)]; ok {
		return pc
	}
	if b.hasDefault {
		return b.defaultPort
	}
	return PortConfig{Proto: "generic"}
}
