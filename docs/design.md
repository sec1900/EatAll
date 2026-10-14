# EatAll — POC 吸收系统（方向B：流量捕获式 POC 提取）

## 定位

防御性安全研究系统：任何漏扫/攻击者扫描我们的蜜罐资产时，系统自动把对方攻击流量捕获、
解析、识别扫描器指纹、重建为 Nuclei YAML 模板、入库，形成可持续吸收、可直接被 nuclei
加载的 POC 库。方向是"打向我"——捕获入站流量属防御性监控。

## 架构

```
攻击者/漏扫 ──扫──> 蜜罐端口(Go代理, 多协议banner伪装)
                      │ 双向原始字节捕获（JSONL，UTC 小时轮转）
                      ▼
                  data/sessions/*.jsonl  ←── 解耦边界（契约见 schema.md）
                      │ ingest 轮询（offset 断点续传）
                      ▼
        Python 管道: 解码器 → 流聚合 → 指纹 → POC重建 → SQLite
                      ▼
              out/templates/poc-*.yaml → nuclei -t 直接加载
```

## 模块

### Go 捕获代理（cmd/proxy + internal/）

| 模块 | 职责 |
|---|---|
| internal/config | 主配置 + banners.yaml 加载（named-reference merge 解析，支持端口覆盖） |
| internal/session | 会话数据结构 + JSONL writer（单行单次 Write syscall，O_APPEND 原子性） |
| internal/listener | 多端口 TCP/UDP 监听、per-IP 限流、全局并发信号量、优雅退出 |
| internal/proto | 协议 handler：http（裸 TCP 手写解析）/ ssh / mysql / redis / ftp / smb / dns(udp) / tls-http / generic |
| internal/rate | per-IP 并发上限 |

协议要点：
- **HTTP 不用 net/http**：它拒绝畸形请求并改写原始字节，而扫描器常态发畸形包。手写容错解析（CR/LF 混用、裸 CR、未知 method、超长行），解析失败仍完整记录原始字节
- **SSH**：banner 交换 + kexinit 二进制解析（算法列表是指纹关键）+ 静态 kexinit 回应（真实客户端会挂起至超时，可审计）
- **MySQL**：伪造 greeting（版本与认证插件自洽），解析 41 握手包取 username/database
- **Redis**：分命令回应表（INFO 回伪造块、CONFIG GET 回 $-1、其余 +OK），避免一刀切回错截断利用链
- **SMB**：SMB1 negotiate 响应字节级对齐 nmap-service-probes 的 microsoft-ds 匹配规则；SMB2 静态 negotiate + SPNEGO blob
- **TLS**：自签证书终止，记录 ClientHello 元数据（SNI/cipher/版本），解密流复用 HTTP 解析循环
- **DNS(UDP)**：查询解析 + static_a 回包（指向 answer_ip 诱导继续探测）

### Python 分析管道（pipeline/）

| 模块 | 职责 |
|---|---|
| main.py | 长驻编排，子命令 ingest/fingerprint/build |
| ingest.py | 2s 轮询 + offset 持久化（.ingest_state.json 断点续传） |
| decoders/ | 协议解码器（优先复用 Go parsed 字段，失败时从原始字节深解析） |
| fingerprint.py | 扫描器指纹：HTTP UA / SSH kexinit 算法组合 / TLS ClientHello / 行为模式 |
| poc_builder/ | normalize（熵识别 + 多会话 LCS 求稳定字节）→ 各协议模板构建 → emit（Nuclei YAML） |
| db.py | SQLite 三表：sessions / flows / pocs（normalized_req_hash UNIQUE 去重） |

### 诱导层（config/banners.yaml）

- 每端口配置 banner 伪装 + 伪漏洞路径（struts2/thinkphp/weblogic/actuator/solr/druid/phpinfo/.git 等）
- banner 与响应版本自洽（nginx banner 配 nginx 风格 404），避免一眼蜜罐
- `$rand16` 占位由代理展开为随机 hex

## 数据流示例

1. 扫描器 GET /struts2-showcase/index.action → 代理回 200 特征页 → JSONL 记录完整请求/响应字节
2. Python ingest 解码出 method/path/headers → 指纹识别（UA → xray/nuclei/...）
3. normalize 识别高熵参数值 → 生成 Nuclei http 模板（matcher 取服务端稳定特征串）
4. 模板写入 out/templates/，pocs 表登记（status=unverified，置信度 0.4）
5. 同一攻击再次命中 → hit_count+1，不重复建模板

## 局限

- 流量捕获只能拿到"指纹匹配上且打过来"的 POC；全量覆盖需配合公开 POC 库交叉补齐
- 无回显/反连型漏洞的检测逻辑无法从流量重建（只能重建请求侧）
- 商业扫描器的判断逻辑是编译/加密的，流量只能还原请求半截
- 合规边界：捕获自有资产入站流量合法；吸收的 POC 仅用于授权测试；商业插件库提取违反 EULA

## 后续（M5）

自动重放验证（打到隔离靶场，成功则 status=verified, confidence=1.0）、CVE 编号映射、SSH 完整握手模拟。
