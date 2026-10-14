# EatAll 部署指南

## 目录结构

```
/opt/eatal/
├── bin/eatal-proxy          # Go 捕获代理（单二进制，静态编译）
├── config/config.yaml       # 生产端口表（22/80/443/445/3306/6379/...）
├── config/banners.yaml      # 诱导层配置
├── config/certs/            # 自签 TLS 证书
├── data/sessions/           # 会话 JSONL（按 UTC 小时轮转）
├── data/logs/               # 代理日志
├── pipeline/                # Python 分析管道
├── out/templates/           # 吸收的 Nuclei 模板
└── deploy/eatal-proxy.service
```

## Linux VPS 部署

```bash
# 1. 交叉编译（在开发机）
GOOS=linux GOARCH=amd64 go build -o bin/eatal-proxy ./cmd/proxy
# 或直接在 VPS 上: go build -o bin/eatal-proxy ./cmd/proxy

# 2. 安装
mkdir -p /opt/eatal
cp -r bin config pipeline out scripts deploy /opt/eatal/
go run scripts/gen-cert.go        # 生成自签证书（或 openssl）

# 3. systemd
cp deploy/eatal-proxy.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now eatal-proxy
journalctl -u eatal-proxy -f

# 4. Python 管道（长驻）+ 展示界面
cd /opt/eatal/pipeline
python -m venv .venv && .venv/bin/pip install -r requirements.txt
# 生产建议用 supervisor 或 systemd 同款 unit 托管
.venv/bin/python main.py run          # ingest + build + 扫描事件计算
.venv/bin/python main.py dashboard --port 9090   # 展示界面

# 访问展示界面（局域网可访问——界面暴露捕获数据，仅限受信网络！）
#   http://<VPS-IP>:9090
```

## Windows 开发环境

```powershell
# 高位端口配置，无需管理员
go run ./cmd/proxy -config config/config.dev.yaml
# 或
.\bin\eatal-proxy.exe -config config/config.dev.yaml
```

注意事项：
- Windows 上 1024 以下端口需管理员权限；445 可能被系统 Server 服务占用
- 禁止同时起两个代理实例写同一 sessions 目录（行完整性依赖单进程 O_APPEND）
- 磁盘水位：会话默认单方向 1MB 上限，扫描高峰期注意 data/sessions 膨胀，建议配日志轮转/定时清理

## 防火墙

蜜罐需要对外可达：`ufw allow 22/tcp 53/udp 80/tcp 443/tcp 21/tcp 445/tcp 3306/tcp 6379/tcp ...`

## 验证

```bash
curl -sk https://127.0.0.1:8443/actuator/env     # TLS + 伪 actuator
nmap -sV -p 22,80,443,3306,6379 127.0.0.1        # 应识别伪装 banner
redis-cli -h 127.0.0.1 -p 6379 info               # 回伪造 INFO
```
