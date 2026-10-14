# EatAll — POC 吸收系统

防御性安全研究工具：任何漏扫/攻击者扫描我们的蜜罐资产时，自动捕获对方攻击流量，
解析识别扫描器指纹，重建为 **Nuclei YAML 模板** 入库，可直接被 nuclei 加载使用。

```
扫描器/攻击者 ──> 蜜罐(Go 代理, 多协议 banner 伪装)
                      │ JSONL 会话记录
                      ▼
               Python 分析管道 ──> out/templates/poc-*.yaml ──> nuclei -t
```

## 特性

- **协议无关捕获**：HTTP / SSH / MySQL / Redis / FTP / SMB / DNS / TLS / 任意端口兜底
- **诱导层**：banner 伪装 + 伪漏洞路径（struts2 / thinkphp / weblogic / actuator / solr 等），
  让扫描器把 POC 打全（nmap -sV 可识别出自洽的伪造服务）
- **扫描器指纹**：HTTP UA、SSH kexinit 算法组合、TLS ClientHello、行为模式
- **POC 重建**：熵识别 + 多会话 LCS 归一化 → Nuclei http/tcp/network/dns 模板
- **去重入库**：SQLite 索引 + 置信度管理，重复攻击自动合并

## 快速开始

```bash
# 构建 + 证书
make build cert

# 开发运行（高位端口，Windows 免管理员）
make dev        # = bin/eatal-proxy -config config/config.dev.yaml

# 测试
make test       # Go 单测

# 冒烟验证
curl -i http://127.0.0.1:8081/struts2-showcase/index.action
nmap -sV -p 8022,8081,8443,8445,33061 127.0.0.1

# Python 管道（长驻：ingest → build → 扫描事件计算）
cd pipeline && pip install -r requirements.txt
python main.py run             # 长驻（--validate 会逐模板跑 nuclei 校验，慢，仅建议单次构建用）
python main.py dashboard       # 展示界面 http://<本机>:9090（默认 0.0.0.0，局域网可访问）
python main.py scan            # 手动触发版本对比计算（扫描事件 diff + 库快照）
```

## 让漏扫扫我：使用流程

```
① 启动三件套：
     bin\eatal-proxy.exe -config config\config.dev.yaml   # 蜜罐代理（监听端口）
     python pipeline\main.py run                           # 分析管道（自动吸收）
     python pipeline\main.py dashboard                     # 展示界面 http://<IP>:9090
② 漏扫扫哪个 IP：运行本系统那台机器的 IP
     - 漏扫与系统同机：127.0.0.1（仅验证用）
     - 局域网漏扫：ipconfig 查本机 IPv4（如 192.168.1.100）
     - 生产 VPS：VPS 公网 IP
③ 端口可见性：蜜罐监听哪些端口，扫描器才探测哪些端口（closed 端口应用层不可见）
     dev 配置（免管理员）: 8081 http · 8022 ssh · 8443 tls · 33061 mysql · 63791 redis
                           8021 ftp · 8445 smb · 8053 dns · 7000-7100 兜底
     生产配置: 22 · 53/udp · 80 · 443 · 21 · 445 · 3306 · 6379 · 8080 · 8443 · 9200 · 7000-7100
     想捕获更多探测 → config.yaml listen_ports 加宽端口段（如 "1-1000"、"8000-9000"）
④ 防火墙/安全组：放行上述端口（Windows 入站规则 / 云安全组），否则外部扫不到
⑤ 对方扫完你能看到：
     - 实时（2s 内）：总览页会话流（哪个 IP、哪些端口、什么协议、banner）
     - 扫描结束 +2 分钟：版本页扫描事件（端口清单 + 每端口服务/攻击标记 + 吸收的 POC）
     - 对方升级再扫：版本对比（🟢 新增 POC / 🔴 移除 POC）
```

## 展示界面与版本控制

- 界面 7 个页签：总览 / 会话 / 扫描器 / **端口** / POC 库 / 版本 / **控制台**（扫描/攻击/克隆快速操作），轮询刷新
- **端口视角**：端口矩阵（每个端口被探测情况）+ 端口详情（探测内容、关联 POC）；
  扫描事件显示"扫过的端口清单" + 每端口攻击/探测意图分类
  （mysql_brute / ssh_brute_probe / ftp_brute / unauthorized_probe / smb_probe /
  poc_attempt / port_probe / dns_enum）
- **版本控制**：同一扫描器（源 IP+指纹）相邻两次扫描自动 diff——🟢 新增 POC、🔴 移除 POC、
  unchanged 计数；同一扫描器每次扫描 = 一个版本（V1/V2…），每次新扫描记录一条版本快照
- 扫描事件按"空闲间隔 > 120s 为新扫描"分割（环境变量 `EATALL_EPISODE_GAP_SEC` 可调）；
  事件在扫描结束后 ~2 分钟自动闭合
- **探活噪音过滤**：同路径高频重复的 HTTP 流量（health check / 前端轮询）自动剔除，
  不参与事件分割（否则事件永不闭合）；非 HTTP 重复连接视为爆破攻击信号不剔除
- 注意：请求内容变化的 POC 会表现为"新增+移除"（模板 id 含请求哈希）
- 监听边界：只看到"对我们监听端口发起的连接"；closed 端口的 SYN 扫描应用层不可见——
  想拿全量 POC 需监听宽端口段（config.broad.yaml ≈2100 端口 / config.full.yaml 全端口仅限 Linux）

## 文档

- **`docs/USAGE.md` — 使用手册（完整操作流程，先读这个）**
- `docs/design.md` — 架构设计
- `docs/schema.md` — 会话 JSONL 契约（Go/Python 解耦边界）
- `docs/deploy.md` — Linux VPS 部署 / systemd

## 合规说明

捕获对象是打向自有资产的入站流量（等同蜜罐），属防御性监控；吸收的 POC 仅用于
授权范围内的测试。商业扫描器插件库的提取/传播违反 EULA，请勿扩散。
