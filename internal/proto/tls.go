package proto

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
)

// TLS handler：静态自签证书终止 TLS，记录 ClientHello 元数据（SNI/cipher suites/
// 版本——扫描器指纹来源），解密后复用 HTTP 解析循环。

// HandleTLS 处理 TLS 包装的 HTTP 连接
func HandleTLS(conn net.Conn, ctx *ConnCtx) {
	sc := Wrap(conn, ctx) // 外层记录加密原始字节
	defer sc.Close()
	SetSessionDeadline(sc, ctx.Limits)
	SetIdle(sc, ctx.Limits)

	cert, err := loadCert(ctx.PortCfg.Cert, ctx.PortCfg.Key)
	if err != nil {
		ctx.Builder.CloseReason = "server_policy"
		return
	}

	tlsMeta := map[string]interface{}{}
	tc := tls.Server(sc, &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			tlsMeta["sni"] = chi.ServerName
			var suites []string
			for _, s := range chi.CipherSuites {
				suites = append(suites, fmt.Sprintf("0x%04x", s))
			}
			tlsMeta["cipher_suites"] = suites
			var vers []string
			for _, v := range chi.SupportedVersions {
				vers = append(vers, tlsVersionName(v))
			}
			tlsMeta["tls_versions"] = vers
			return cert, nil
		},
	})
	SetIdle(sc, ctx.Limits)
	if err := tc.Handshake(); err != nil {
		// 握手失败（客户端中止/非 TLS 流量）：原始字节已记录
		if ctx.Builder.CloseReason == "" {
			ctx.Builder.CloseReason = closeReasonFor(err)
		}
		if ctx.Builder.ParseStatus == "ok" {
			ctx.Builder.ParseStatus = "partial"
		}
		ctx.Builder.TLS = tlsMeta
		return
	}
	// 解密流上跑 HTTP 循环；注意 handleHTTPLoop 的 SetIdle 作用于 sc 的 deadline
	handleHTTPLoop(tc, ctx)
	ctx.Builder.TLS = tlsMeta
	ctx.Builder.Banner = ctx.PortCfg.ServerHeader
}

// loadCert 加载自签证书（每次连接加载 pem 小文件，可接受）
func loadCert(certPath, keyPath string) (*tls.Certificate, error) {
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("tls cert/key not configured")
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
