package proto

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
)

// Redis handler：RESP 解析 + 分命令回应表（不要一刀切回错——未授权访问判定器依赖
// INFO/SET 等命令的成功响应，回错会截断利用链记录）。

// HandleRedis 处理 Redis 连接
func HandleRedis(conn net.Conn, ctx *ConnCtx) {
	sc := Wrap(conn, ctx)
	defer sc.Close()
	SetSessionDeadline(sc, ctx.Limits)
	SetIdle(sc, ctx.Limits)

	// 连接即回 banner（真实 Redis 无 banner，但 +OK 能引导更多工具继续）
	banner := ctx.PortCfg.Banner
	if banner == "" {
		banner = "+OK\r\n"
	}
	ctx.Builder.Banner = "Redis " + redisVersionOf(ctx)
	if _, err := sc.Write([]byte(banner)); err != nil {
		ctx.Builder.CloseReason = "error"
		return
	}

	r := bufio.NewReaderSize(sc, 64<<10)
	var commands [][]string
	responsesSent := 0

	for {
		SetIdle(sc, ctx.Limits)
		cmd, err := readRedisCommand(r)
		if err != nil {
			if ctx.Builder.CloseReason == "" {
				ctx.Builder.CloseReason = closeReasonFor(err)
			}
			break
		}
		if len(cmd) == 0 {
			continue
		}
		commands = append(commands, cmd)
		upper := strings.ToUpper(cmd[0])
		var resp string
		switch upper {
		case "PING":
			resp = "+PONG\r\n"
		case "AUTH", "SELECT", "FLUSHALL", "FLUSHDB", "SET", "SETEX", "MSET", "HSET", "DEL", "EXPIRE", "SAVE", "BGSAVE":
			resp = "+OK\r\n"
		case "INFO":
			if info := ctx.PortCfg.InfoReply; info != "" {
				resp = redisBulkString(info + "\n")
			} else {
				resp = redisBulkString("redis_version:" + redisVersionOf(ctx) + "\n")
			}
		case "CONFIG":
			if len(cmd) >= 2 && strings.ToUpper(cmd[1]) == "GET" {
				resp = "$-1\r\n" // null bulk：表示未配置
			} else {
				resp = "+OK\r\n"
			}
		case "QUIT":
			resp = "+OK\r\n"
			if _, err := sc.Write([]byte(resp)); err == nil {
				responsesSent++
			}
			ctx.Builder.CloseReason = "client_closed"
			goto done
		case "GET", "MGET", "HGETALL", "KEYS", "TTL", "TYPE", "STRLEN":
			resp = "$-1\r\n" // key 不存在
		default:
			resp = "-ERR unknown command '" + cmd[0] + "'\r\n"
		}
		if _, err := sc.Write([]byte(resp)); err != nil {
			ctx.Builder.CloseReason = "error"
			break
		}
		responsesSent++
		if sc.Maxed() {
			ctx.Builder.CloseReason = "max_bytes"
			break
		}
	}
done:
	if len(commands) > 0 {
		ctx.Builder.Parsed = map[string]interface{}{
			"commands":       commands,
			"responses_sent": responsesSent,
		}
	}
	ctx.Builder.ParseStatus = "ok"
}

func redisVersionOf(ctx *ConnCtx) string {
	if v := extractRedisVersion(ctx.PortCfg.InfoReply); v != "" {
		return v
	}
	return "5.0.14"
}

func extractRedisVersion(info string) string {
	for _, line := range strings.Split(info, "\n") {
		if strings.HasPrefix(line, "redis_version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "redis_version:"))
		}
	}
	return ""
}

// readRedisCommand 读一条命令：RESP 数组或内联命令行
func readRedisCommand(r *bufio.Reader) ([]string, error) {
	first, err := r.Peek(1)
	if err != nil {
		return nil, err
	}
	if first[0] == '*' {
		// RESP 数组
		line, err := readLine(r, 4096)
		if err != nil {
			return nil, err
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(line[1:])))
		if err != nil || n < 0 || n > 10000 {
			return nil, errInvalidRedisArray
		}
		cmd := make([]string, 0, n)
		for i := 0; i < n; i++ {
			bl, err := readLine(r, 4096)
			if err != nil {
				return nil, err
			}
			if len(bl) == 0 || bl[0] != '$' {
				return nil, errInvalidRedisBulk
			}
			blen, err := strconv.Atoi(strings.TrimSpace(string(bl[1:])))
			if err != nil || blen < 0 || blen > 16<<20 {
				return nil, errInvalidRedisBulk
			}
			buf := make([]byte, blen)
			if _, err := io.ReadFull(r, buf); err != nil {
				return nil, err
			}
			_, _ = readLine(r, 8) // 尾随 CRLF
			cmd = append(cmd, string(buf))
		}
		return cmd, nil
	}
	// 内联命令
	line, err := readLine(r, 4096)
	if err != nil {
		return nil, err
	}
	var parts []string
	for _, p := range strings.Fields(string(line)) {
		parts = append(parts, p)
	}
	return parts, nil
}

var (
	errInvalidRedisArray = &errs{msg: "invalid redis array"}
	errInvalidRedisBulk  = &errs{msg: "invalid redis bulk"}
)

// redisBulkString 构造 RESP bulk string
func redisBulkString(s string) string {
	return "$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n"
}
