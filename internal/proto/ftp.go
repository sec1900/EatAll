package proto

import (
	"bufio"
	"net"
	"strings"
)

// FTP handler：220 banner + 行式命令表。PASS 明文被记录（弱口令情报）。
// MVP 不实现数据连接（PASV/EPSV → 502）。

// HandleFTP 处理 FTP 连接
func HandleFTP(conn net.Conn, ctx *ConnCtx) {
	sc := Wrap(conn, ctx)
	defer sc.Close()
	SetSessionDeadline(sc, ctx.Limits)

	banner := ctx.PortCfg.Banner
	if banner == "" {
		banner = "220 (vsFTPd 3.0.3)\r\n"
	}
	if !strings.HasSuffix(banner, "\n") {
		banner += "\r\n"
	}
	ctx.Builder.Banner = strings.TrimSpace(banner)
	if _, err := sc.Write([]byte(banner)); err != nil {
		ctx.Builder.CloseReason = "error"
		return
	}

	r := bufio.NewReaderSize(sc, 8<<10)
	var commands []map[string]string
	for {
		SetIdle(sc, ctx.Limits)
		line, err := readLine(r, 4096)
		if err != nil {
			if ctx.Builder.CloseReason == "" {
				ctx.Builder.CloseReason = closeReasonFor(err)
			}
			break
		}
		lineStr := strings.TrimSpace(string(line))
		if lineStr == "" {
			continue
		}
		parts := strings.SplitN(lineStr, " ", 2)
		cmd := strings.ToUpper(parts[0])
		arg := ""
		if len(parts) > 1 {
			arg = parts[1]
		}
		commands = append(commands, map[string]string{"cmd": cmd, "arg": arg})

		var resp string
		switch cmd {
		case "USER":
			resp = "331 Please specify the password.\r\n"
		case "PASS":
			if ctx.PortCfg.LoginAccept {
				resp = "230 Login successful.\r\n"
			} else {
				resp = "530 Login incorrect.\r\n"
			}
		case "SYST":
			resp = "215 UNIX Type: L8\r\n"
		case "FEAT":
			resp = "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n SIZE\r\n211 End\r\n"
		case "PWD", "XPWD":
			resp = "257 \"/\" is the current directory\r\n"
		case "CWD", "CDUP":
			resp = "250 Directory successfully changed.\r\n"
		case "TYPE":
			resp = "200 Switching to binary mode.\r\n"
		case "PASV", "EPSV", "PORT", "EPRT":
			resp = "502 Command not implemented.\r\n"
		case "SIZE":
			resp = "550 Could not get file size.\r\n"
		case "QUIT":
			resp = "221 Goodbye.\r\n"
			if _, err := sc.Write([]byte(resp)); err == nil {
				ctx.Builder.CloseReason = "client_closed"
			}
			goto done
		default:
			resp = "500 Unknown command.\r\n"
		}
		if _, err := sc.Write([]byte(resp)); err != nil {
			ctx.Builder.CloseReason = "error"
			break
		}
		if sc.Maxed() {
			ctx.Builder.CloseReason = "max_bytes"
			break
		}
	}
done:
	if len(commands) > 0 {
		ctx.Builder.Parsed = map[string]interface{}{"commands": commands}
	}
	ctx.Builder.ParseStatus = "ok"
}
