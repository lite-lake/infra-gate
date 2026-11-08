# Infra Gate

带 WAF 的反向代理网关（Go / Gin / [Coraza WAF](https://github.com/corazawaf/coraza)）：单二进制，承载虚拟主机路由、SSL 证书（本地/远程 API/代理三类模式）、OWASP CRS、IP 黑名单、失败锁定、访问审计与只读可观测 API。

> Lite Lake 基础设施开源项目之一 · BSD-2-Clause License

## 主要功能

- **反向代理**：多端口虚拟主机、随机负载均衡、后端健康检查
- **WAF 安全防护**：基于 Coraza v3 引擎，集成 OWASP CRS 规则集，支持自定义规则和 IP 白名单
- **IP 黑名单**：定时同步外部威胁情报（USTC blackip）到本地内存，微秒级拦截已知恶意 IP，支持 block/detect/disabled 模式与本地白名单豁免
- **SSL/TLS 证书管理**：支持本地证书和远程证书 API，自动检查更新，通配符域名匹配，SNI 支持
- **WebSocket 代理**：RFC 6455 合规，帧级代理，Ping/Pong 心跳，扩展与子协议协商
- **HTTP/2 支持**：完整 HTTP/2 代理（含 HTTP/2-to-HTTP/2 转发）
- **智能 Gzip 压缩**：延迟压缩决策，按 Content-Type 自动判断，支持请求体 gzip 解压
- **Admin 只读可观测 API**：`X-API-Key` 认证的 JSON 端点（站点状态、证书信息、WAF 统计与事件、IP 黑名单状态与事件）；**自带管理面板已拆除（零自有管理页面）**，看板由 Admin Center 承接
- **生命周期通知**：启动/停止等关键事件通过企业微信群机器人推送
- **请求追踪**：TraceID 生成与传播，贯穿日志与转发请求
- **优雅关闭**：有序停止 HTTP/HTTPS 服务、WebSocket 连接排空、连接池清理

## 快速开始

```bash
# 运行程序
go run main.go

# 构建二进制
go build -o infra-gate ./

# 运行测试
go test ./...
```

程序默认读取 `configs/server.yml` 配置文件。可参考 `configs/server.sample.yml` 和 `configs/server.ssl.sample.yml` 了解完整配置示例。

## 配置说明

配置文件位于 `configs/server.yml`，采用 YAML 格式。以下为完整配置结构参考：

### 服务器配置 (`server`)

```yaml
server:
  port: 80                    # HTTP 监听端口
  g_zip_enabled: true          # 全局启用 gzip 压缩
  g_zip_level: 6               # 压缩级别 (1=BestSpeed, 9=BestCompression, -2=默认)
  g_zip_min_size: 0            # 触发压缩的最小响应体大小（字节）
  http2_enabled: false         # 启用 HTTP/2（需要 TLS）
  trusted_proxies:             # 受信代理 IP/CIDR 列表，用于解析真实客户端 IP
    - "127.0.0.1"
    - "10.0.0.0/8"
  strict_path_check: true      # 请求路径规范化强制（段级校验，非规范路径 400）。nil=true 默认开，显式 false 为逃生口（启动 Warn）
  websocket_insecure_skip: false  # （Deprecated）全局 WSS 上游跳过 TLS 验证：兼容期作 per-host `web_socket_insecure_skip` 为 nil 时的缺省，非零值启动 Warn；新配置请用 per-host 字段
  websocket:
    handshake_timeout: 30s     # WebSocket 握手超时
    idle_timeout: 5m           # 空闲超时（无帧读取）
    ping_interval: 30s         # 心跳 Ping 间隔
```

### 虚拟主机配置 (`hosts`)

```yaml
hosts:
  - name: example.com          # 虚拟主机名（匹配 Host 头，`*` 为通配符）
    port: 80                   # HTTP 监听端口
    ssl_port: 443              # HTTPS 监听端口（可选）
    backend:                   # 后端地址列表（支持 http/https）
      - "http://10.0.0.1:8080"
      - "http://10.0.0.2:8080"
    health_check: "/health"           # 健康检查路径
    health_check_interval: 10s        # 健康检查间隔
    health_check_timeout: 5s          # 健康检查超时
    health_check_enabled: true        # 是否启用（nil 默认启用）
    # --- 以下为可选覆盖项（nil = 继承全局配置）---
    g_zip_enabled: true               # 覆盖全局 gzip 设置
    http2_enabled: true               # 覆盖全局 HTTP/2 设置
    preserve_host_header: false       # 保留客户端原始 Host 头
    override_host: "backend.internal" # 自定义 Host 头（优先级最高）
    override_origin: "https://app.example.com"  # 自定义 Origin 头
    strip_proxy_headers: false        # 剥离所有代理相关头部
    robots_deny_all: false            # 强制覆盖 /robots.txt 拒绝所有爬虫（nil=false）
    allowed_ips: ["10.72.0.0/24"]     # 仅允许这些来源 IP/CIDR 访问（nil=不限制）
    web_socket_insecure_skip: false   # per-host WSS 上游跳过 TLS 验证（nil=继承全局，per-host 优先；显式 true 启动 Warn）
    auth: ...                         # 密码门（password 必填；ttl/public_paths/max_failures/lock_duration 可选）
    ssl_config: ...                   # 虚拟主机级 SSL 配置（覆盖全局）
    waf: ...                          # 虚拟主机级 WAF 配置（覆盖全局）
    text: "static response"           # 静态文本响应（无 backend 时使用）
```

#### Host 头处理优先级

1. `override_host` — 显式指定 Host 头值
2. `preserve_host_header: false` — 重写为后端地址
3. `preserve_host_header: true` — 保留客户端原始 Host 头

#### `strip_proxy_headers`

设置为 `true` 时不添加以下代理头部，适用于伪装成客户端直接请求的场景（如反向代理到第三方 API）：

- `X-Forwarded-For` / `X-Forwarded-Proto` / `X-Forwarded-Host` / `X-Forwarded-Port`
- `Forwarded` (RFC 7239)
- `X-Lite-Gate-Forwarded-For` / `X-Lite-Gate-Forwarded-Host` / `X-Lite-Gate-Trace-Id`
- `Via`

#### `robots_deny_all`

设置为 `true` 时，infra-gate 在网关层直接拦截 `GET /robots.txt`，返回拒绝所有搜索引擎爬虫的固定响应（`User-agent: * / Disallow: /`），**不转发给后端**——即使后端配置了自己的 robots.txt 也会被覆盖。响应体内含英文注释说明来源，便于排查。`nil`/`false` 时该功能关闭，`/robots.txt` 正常代理给后端。响应使用 `Cache-Control: no-cache`，配置变更后立即生效。

#### `allowed_ips`

设置为非空（来源 IP/CIDR 列表）时，infra-gate 仅允许这些来源访问该虚拟主机，其他来源返回 `403 Forbidden`，不进入代理/WAF 流程。客户端真实 IP 通过 `ResolveClientIP` 解析（正确处理可信代理的 X-Forwarded-For 链），与 WAF 的客户端 IP 判定一致，避免伪造转发头绕过。`nil`/空表示不限制。

适用场景：服务仅需通过 EasyTier mesh 虚拟网（按环境规划内网网段，如 dev / prod 各一段）访问，拒绝公网来源。健康检查直连后端（不经 host 路由），不受 `allowed_ips` 影响。

#### 作为 frp 隧道入口

infra-gate 可作为 frp 隧道的入口网关，实现公网到内网的 HTTP 穿透。在此场景下，yamlops 会自动为隧道路由生成 host 条目，使用以下特殊配置：

```yaml
hosts:
  - name: pay-dev.example.net       # 隧道域名
    backend:
      - "http://frps-node2:80"       # 指向 frps 容器的 vhost_http_port
    preserve_host_header: true      # 必须保留 Host 头（frps 依赖它匹配隧道）
    health_check_enabled: false     # 隧道路由禁用健康检查
```

> 这些 host 条目由 yamlops 根据 `tunnel-server` 的 `tunnel_routes` 自动注入，无需手动配置。由配套部署工具按隧道服务的 tunnel_routes 自动注入。

架构流程：
```
外部 HTTPS 请求 → gate prod (TLS 终止 + WAF) → frps (按 Host 头路由) → TLS 隧道 → frpc → gate dev → 业务服务
```

### SSL 证书配置 (`ssl` / `ssl_config`)

支持全局配置（`ssl`）和虚拟主机级覆盖（`hosts[].ssl_config`），支持本地和远程两种模式：

```yaml
# 本地证书
ssl:
  local:
    enabled: true
    cert_dir: "configs/cert/example.com"

# 远程证书
ssl:
  remote:
    enabled: true
    endpoint: "https://cert-api.example.com/cert/json"
    auto_update: true                    # 启用自动更新
    update_check_window: "00:00-00:59"   # 检查时间窗口（支持跨午夜）
    api_key: "your-api-key"              # API Key 认证（可选）
    timeout: 6m                          # 请求超时（默认 6 分钟）

# 远程证书代理配置
ssl:
  remote:
    enabled: true
    endpoint: "https://cert-api.example.com/cert/json"
    proxy:
      enabled: true
      url: "http://proxy.internal:8080"
      username: ""    # 可选
      password: ""    # 可选
```

支持本地 + 远程双模式同时配置：优先使用磁盘缓存，其次本地文件，最后远程 API。自动更新在证书即将过期时（30 天阈值）触发，通过指纹比对检测实际变更。详细说明请参考 [SSL 证书功能使用指南](docs/ssl-guide.md)。

### WAF 配置 (`waf`)

支持全局配置和虚拟主机级覆盖。CRS 完全不可用（无可用缓存/金副本且下载也失败）时按 `waf.crs.failure_policy` 处置：`fail`（缺省，安全缺省）→ WAF 构造失败、服务拒绝启动；`degrade` → 该配置不启用 WAF、监听器照常启动并发高优告警。

**全局配置（2 个字段）：**

| 字段 | 说明 |
|------|------|
| `enabled` | 总开关。`false` → 所有主机 WAF 一律不启用 |
| `default_mode` | 默认运行模式：`block`（阻断）/ `detect`（仅检测）/ `disabled`（停用）|

**虚拟主机配置（1 个字段）：**

| 字段 | 说明 |
|------|------|
| `default_mode` | 覆盖全局 `default_mode`。不写则继承全局 |

```yaml
waf:
  enabled: true
  default_mode: block
  whitelist:
    enabled: true
    ip_ranges:           # IP 白名单（CIDR 或单 IP），白名单内 IP 跳过所有 WAF 检查
      - "10.0.0.0/8"
      - "192.168.1.100"
  crs:
    enabled: true
    version: "v4.19.0"   # OWASP CRS 版本
    failure_policy: fail # CRS 完全不可用时策略：fail=WAF 构造失败、拒绝启动（缺省）/ degrade=该配置无 WAF 启动+高优告警
    golden_dir: "/app/crs"  # 金副本根目录（只读，不写缓存），缺省 /app/crs；显式空串=禁用金副本
    download:
      timeout: 60         # 下载总预算（秒），配置值即总预算，<=0/缺省 = 60（无最小钳制）
      retry_count: 2      # 总预算内最大下载轮数，<=0/缺省 = 2；每轮先直连后代理
      # mirror_url: "https://crsmirror.example.com"  # CRS 镜像端点（仅 https；支持列表，失败自动切换下一个）
      # mirror_allow_insecure_http: false  # 明文 http 镜像放行开关（缺省 false，明文 http 启动校验直接报错；内网明文镜像需显式 true 放行）
      # pinned_sha256: "<64 位十六进制>"  # 期望 tarball sha256 pin（最高优先，优先于镜像内 /app/crs/pins.sha256 清单；配置与清单都无该版本 → 拒绝下载，走 failure_policy 处置）
      proxy:
        enabled: false
        url: "http://proxy.internal:8080"
        username: ""
        password: ""
  custom:
    enabled: true
    rules_file: "configs/custom-rules.conf"  # 自定义 ModSecurity 规则文件
  debug:
    log_level: 3          # 调试日志级别 (0-4)
    log_file: "stdout"    # 调试日志输出路径
```

虚拟主机级覆盖示例：

```yaml
hosts:
  - name: test.example.com
    port: 80
    text: "WAF disabled"
    waf:
      default_mode: disabled  # 该主机停用 WAF

  - name: new-service.example.com
    port: 80
    backend:
      - http://localhost:3000
    waf:
      default_mode: detect  # 该主机仅检测，不阻断
```

自定义规则文件使用 ModSecurity/Coraza SecRule 语法，示例请参考 `configs/custom-rules.conf`。

### IP 黑名单配置（`blacklist`）

支持全局配置和虚拟主机级覆盖。基于外部威胁情报数据源（默认 [USTC blackip](https://blackip.ustc.edu.cn/)，聚合 Spamhaus DROP、firehol_level1、Feodo Tracker 等），定时同步全量列表到本地内存，在请求链最前端（host 匹配之后、`allowed_ips` 之前）以微秒级成本拦截已知恶意 IP——命中即返回 403（复用 WAF 的 `blocked.html` 拦截页），省掉整个 gzip/WAF/代理链路开销。

**运行模式（`default_mode`）：**

| 模式 | 行为 |
|------|------|
| `block` | 命中黑名单返回 403（`blocked.html`），默认值 |
| `detect` | 仅记录事件与统计，不拦截；用于灰度观察误杀率 |
| `disabled` | 该范围不做黑名单检查（主要用于 host 级覆盖） |

**灰度建议**：首期上线全局设 `detect`，观察 3~7 天确认无误杀（通过 Admin 只读 API / Admin Center 网关看板核查命中统计与事件）后再切 `block`；流量敏感或内部专用 host 可用 host 级 `disabled`/`detect`。

**全局配置项：**

| 字段 | 说明 |
|------|------|
| `enabled` | 总开关。`false` → 所有主机不做黑名单检查（零开销路径） |
| `default_mode` | 默认运行模式：`block` / `detect` / `disabled`，空 = `block` |
| `sources` | 数据源列表，每项含 `name`（唯一，作缓存文件名与展示标识）与 `url`（纯文本全量列表端点，每行一条 IP 或 CIDR） |
| `update_interval` | 定时刷新间隔，最低 30m，`0`/缺省 = 默认 1h（附加随机抖动，多节点错峰） |
| `timeout` | 单次拉取超时，`0`/缺省 = 默认 60s，上限 5m |
| `proxy` | 拉取代理（结构与 `waf.crs.download.proxy` 一致），直连可达时保持关闭 |
| `whitelist` | 本地豁免 IP/CIDR 列表（最高优先级，豁免办公出口/监控探针等；非法条目启动时 Warn 告警并跳过，不阻断启动） |
| `ignore_private_ips` | 私有/保留网段（回环/私有/链路本地/CGNAT/组播/保留段）一律不拦截，缺省 `true`。应对上游 feed 混入保留网段（实测含 `169.254.0.0/16`） |
| `allow_http_source` | 允许 `http://` 明文数据源。缺省 `false`（仅 https，明文 http 源启动校验直接报错）；内网明文 feed 需显式 `true` 放行 |
| `max_entries` | 防追加式投毒的增长上限基数，缺省 `200000`：新 feed 去重条目数超过 `max(2×上次成功条目数, max_entries)` 时拒绝替换、保留旧表 |

```yaml
blacklist:
  enabled: true
  default_mode: detect          # 首期上线建议 detect，观察无误杀后切 block
  sources:
    - name: ustc
      url: "https://blackip.ustc.edu.cn/list.php?txt"
  update_interval: 1h           # 最低 30m
  timeout: 60s                  # 上限 5m
  proxy:                        # 结构与 waf.crs.download.proxy 一致
    enabled: false
    url: ""
    username: ""
    password: ""
  whitelist:                    # 本地豁免（公网 IP；私有段无需配置）
    - "203.0.113.10"
  ignore_private_ips: true      # 私有/保留网段一律不拦截
  # allow_http_source: false    # 明文 http 数据源放行开关（缺省 false，仅 https）
  # max_entries: 200000         # 增长上限基数（防追加式投毒），缺省 200000
```

虚拟主机级覆盖示例（不设置则继承全局）：

```yaml
hosts:
  - name: test.example.com
    port: 80
    text: "blacklist disabled"
    blacklist:
      default_mode: disabled    # 该主机关闭黑名单检查（可选 block / detect / disabled）
```

**容错与防误杀行为：**

- **fail-open**：黑名单是增益层而非安全底线。冷启动无磁盘缓存且首次拉取失败时空列表启动（等价于功能未生效），Error 日志 + Admin 可见，不阻断服务启动（与 WAF 的 fail-closed 相反，有意为之）
- **防污染**：拉取结果有效条目 < 1000 或 < 上次条目数的 50% 时拒绝替换内存列表，保留旧表继续服务（应对上游异常返回 HTML 错误页等场景）
- **旧表兜底**：周期刷新失败（网络/5xx/超时）时保留旧表持续生效，下周期自动重试
- **本地白名单**：`blacklist.whitelist` 优先于黑名单查询，命中白名单直接放行且不记事件
- **保留网段过滤**：`ignore_private_ips: true` 时构建期过滤私有/保留网段，避免上游 feed 瑕疵误伤内网来源
- **真实 IP 判定**：客户端 IP 通过 `ResolveClientIP` + `trusted_proxies` 解析，与 WAF 一致，防伪造 XFF 绕过；查询前做 `To4()` 归一化处理 v4-mapped IPv6 变形

**磁盘缓存**：拉取成功后写入 `cache/blacklist/<name>.txt`（原子写：临时文件 + rename），重启时优先加载缓存再异步首刷，避免冷启动空窗。Docker 部署已挂载 `./cache` 卷，无需额外配置。

**Admin 可观测入口**（面板已拆除，仅 API）：

- API：`GET /api/blacklist/stats`（统计快照）、`GET /api/blacklist/events?limit=50`（近期命中事件，上限 200）
- 展示：Admin Center 网关看板（AC gateways 子页，X-API-Key 轮询）

配置无热加载（启动读一次），黑名单配置变更需重启，与 WAF 行为一致。

### 日志配置 (`logger`)

```yaml
logger:
  level: 1                 # 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR, 4=FATAL
  enable_console: true     # 控制台输出
  enable_file: true        # 文件输出
  log_dir: "./applogs"     # 日志目录
  archive_dir: ""          # 归档目录（空则同 log_dir）
  max_retention_days: 30   # 归档保留天数
  enable_color: true       # 控制台彩色输出
```

日志按级别分文件（`debug.log`、`info.log`、`warn.log`、`error.log`），每日自动轮转并 ZIP 归档。

### 通知配置 (`notification`)

```yaml
notification:
  enabled: false
  url: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx"  # 企业微信群机器人 Webhook
  timeout: 5s
```

生命周期事件通知（共 13 种，与 `internal/notification/notifier.go` eventMap 一致）：生命周期 `starting` / `started` / `start_failed` / `stopping` / `stopped` / `ready`（全端口绑定就绪）；证书 `cert_ready` / `cert_failed`；WAF/CRS `waf_crs_degraded`（高优）/ `waf_crs_stale_start` / `waf_crs_recovered` / `waf_crs_refresh_failed`；密码门 `auth_lockout`。消息包含应用名、构建 ID、主机名、部署环境信息和时间戳。

## Admin 只读可观测 API（无自有面板）

通过环境变量启用，独立端口运行。自带管理面板已整体拆除（见演进记录）——**零自有管理页面**、无登录/会话/CSRF，仅保留只读 JSON API 与健康探针；唯一认证通道为 `X-API-Key`，看板与运维入口为 Admin Center。

### 环境变量

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| `LITE_ADMIN_DOMAIN` | Admin 域名（必须，同时用于 Host 校验） | — |
| `LITE_ADMIN_HTTPS` | 是否使用 HTTPS | `true` |
| `LITE_ADMIN_PORT` | 监听端口 | `30443`（HTTPS）/ `30080`（HTTP） |
| `LITE_ADMIN_READONLY_API_KEYS` | 只读 API Key 列表（逗号分隔，多把并存支持轮换） | 空（所有只读请求 401） |
| `LITE_ADMIN_ALLOWED_IPS` | 来源 IP 允许名单（逗号分隔 IP/CIDR，按直连对端评估，不命中 403，含免认证探针在内全部端点受限；非法条目启动即失败） | 未设置 = 私网+回环（127/8、::1/128、10/8、172.16/12、192.168/16，覆盖 mesh）；显式设置空串 = 不限制（启动 Warn） |

设置 `LITE_ADMIN_DOMAIN` 即启用 Admin 服务。默认使用 HTTPS（TLS 1.2+），复用网关的证书管理器加载 Admin 域名的证书；`LITE_ADMIN_HTTPS=false` 明文运行时启动 Warn 一条（X-API-Key 与响应明文可被链路窃听，M4）。

> 面板拆除后 `LITE_ADMIN_USERNAME` / `LITE_ADMIN_PASSWORD` 已废除、不再读取，部署 env 已同步清理。

### 只读 API Key 认证（AC 网关看板数据源）

配置 `LITE_ADMIN_READONLY_API_KEYS` 后，八个只读端点（`GET /api/sites`、`GET /api/certs`、`GET /api/system`、`GET /api/waf/stats`、`GET /api/waf/events`、`GET /api/waf/events/:id`、`GET /api/blacklist/stats`、`GET /api/blacklist/events`）接受 `X-API-Key` 认证，供 Admin Center（AC）等内部系统轮询：

- 请求携带 `X-API-Key` 头且命中任一已配置 key → 放行（`crypto/subtle` 常数时间比较，遍历全部 key 不短路）；
- 已配置 key 但未携带或未命中 → `401`；未配置任何 key 时任何请求 → `401`（无会话回退）；
- 页面路由（`/`、`/login`、`/sites`、`/certs`、`/waf`、`/blacklist`）与静态资源已全部拆除，访问返回 `404`；
- **仅覆盖上述八个只读 GET 端点**——无任何写操作。

```bash
# 示例：配置两把 key（新旧并存轮换期）
export LITE_ADMIN_READONLY_API_KEYS='old-key-base64url,new-key-base64url'
curl -H 'X-API-Key: new-key-base64url' https://gate.example.cn:30443/api/certs
```

### 免认证健康检查

Admin 服务启用后，自动暴露以下免认证健康检查端点（供 Uptime Kuma / Docker HEALTHCHECK 等监控探测，与 lite-backend 的 `/api/health`、`/api/ready` 对齐）：

| 端点 | 类型 | 说明 |
|------|------|------|
| `GET /api/health` | 存活探针 | 进程可响应即返回 `200` `{"status":"ok",...}` |
| `GET /api/ready` | 就绪探针 | 聚合网关全部 host 后端健康状态；任一后端不健康返回 `503` `{"status":"degraded","hosts":{...}}`，全部健康返回 `200`。`hosts.<name>` 仅含 `status` / `backends_total` / `backends_healthy` 计数（M4：原 `backends` 地址→布尔清单已收敛为计数，响应体不再暴露后端地址） |

> **访问约束**：仍受 Admin 服务全局 Host 校验（Host 必须等于 `LITE_ADMIN_DOMAIN`，如 `https://gate.{node}.v-{env}.mesh.example.net:30443/api/health`）与来源 IP 允许名单（`LITE_ADMIN_ALLOWED_IPS`，按直连对端评估，名单外一律 403，M4）；免认证、不需要任何 API Key。就绪探针对「无后端数据的 host（健康检查禁用或启动初期）」标记 `pending`、`backends_healthy=0`，不计入降级判定。

### 页面路由（已拆除）

面板拆除（迭代 4b）后全部页面路由与静态资源不存在，访问返回 `404`：

| 原页面 | 路径 | 现状 |
|------|------|------|
| 登录 | `/login`、`/logout` | 404（登录/会话/CSRF 体系已删除） |
| 仪表盘 | `/` | 404 |
| 站点 | `/sites` | 404 |
| 证书 | `/certs` | 404 |
| WAF | `/waf` | 404 |
| IP 黑名单 | `/blacklist` | 404 |

看板由 Admin Center 网关子页（WAF/黑名单/节点/证书/域名）承接。

### JSON API

| 接口 | 说明 |
|------|------|
| `GET /api/health` | 存活探针（免认证） |
| `GET /api/ready` | 就绪探针（免认证，聚合后端健康） |
| `GET /api/sites` | 虚拟主机列表及后端健康状态（`X-API-Key` 认证） |
| `GET /api/certs` | 证书信息列表（`X-API-Key` 认证） |
| `GET /api/system` | 系统信息（端口、Admin URL；`X-API-Key` 认证） |
| `GET /api/waf/stats` | WAF 阻断统计（按主机、总计、最近阻断；`X-API-Key` 认证） |
| `GET /api/waf/events` | 近期 WAF 阻断事件（默认 100 条，`?limit=` 上限 200；`X-API-Key` 认证） |
| `GET /api/waf/events/:id` | 单条 WAF 事件详情（`X-API-Key` 认证） |
| `GET /api/blacklist/stats` | IP 黑名单统计（数据源条目数、上次更新、命中计数；`X-API-Key` 认证） |
| `GET /api/blacklist/events` | 近期 IP 黑名单命中事件（默认 50 条，`?limit=` 上限 200；`X-API-Key` 认证） |

## Docker 部署

```bash
# 生产镜像
docker build -f Dockerfile-prod -t infra-gate:prod .

# 开发镜像
docker build -f Dockerfile-dev -t infra-gate:dev .

# 运行
docker run -d \
  --name infra-gate \
  -p 80:80 \
  -p 443:443 \
  -v $(pwd)/configs:/app/configs \
  -v $(pwd)/cache:/app/cache \
  -v $(pwd)/applogs:/app/applogs \
  infra-gate:prod
```

镜像特性：多阶段构建，非 root 用户运行，时区 `Asia/Shanghai`，二进制已剥离调试信息。

## 部署环境变量

以下环境变量用于标识部署环境，会写入日志和通知消息：

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| `DEPLOY_ENV_NAME` | 环境名称 | `local` |
| `DEPLOY_ZONE_NAME` | 区域名称 | — |
| `DEPLOY_SERVER_NAME` | 服务器名称 | — |
| `DEPLOY_SERVICE_NAME` | 服务名称 | — |
| `LITE_BUILD_ID` | 构建 ID（CI 注入） | — |

## 项目结构

```
infra-gate/
├── main.go                    # 入口点
├── go.mod
├── configs/                   # 配置文件
│   ├── server.yml             # 活动配置
│   ├── server.sample.yml      # 完整示例配置
│   ├── server.ssl.sample.yml  # SSL 示例配置
│   └── custom-rules.conf      # 自定义 WAF 规则示例
├── templates/                 # HTML 错误页面模板
│   ├── blocked.html           # WAF 拦截页 (403)
│   ├── upstream_error.html    # 上游错误页 (502)
│   └── system_error.html      # 系统错误页 (500)
├── internal/                  # 业务逻辑
│   ├── admin/                 # Admin 只读可观测 API（面板已拆除）
│   ├── blacklist/             # IP 黑名单（内存存储/定时拉取/统计）
│   ├── cert/                  # SSL 证书管理
│   ├── config/                # 配置结构与校验
│   ├── crs/                   # OWASP CRS 规则集管理
│   ├── deployinfo/            # 部署环境信息
│   ├── health/                # 后端健康检查
│   ├── infrastructs/logger/   # 自定义日志框架
│   ├── middleware/            # HTTP 中间件（gzip 压缩/解压）
│   ├── netutil/               # 网络工具（受信代理、客户端 IP 解析）
│   ├── notification/          # 生命周期事件通知
│   ├── proxy/                 # 核心反向代理逻辑
│   ├── server/                # HTTP 服务器编排
│   ├── templates/             # 模板渲染器
│   ├── trace/                 # 请求 TraceID 管理
│   └── waf/                   # WAF 中间件与统计
├── cache/                     # 运行时缓存（CRS 规则、证书、IP 黑名单）
├── applogs/                   # 运行时日志（gitignore）
├── docs/                      # 文档
├── Dockerfile-dev             # 开发镜像
├── Dockerfile-prod            # 生产镜像
├── .cnb.yml                   # CNB CI/CD 配置
└── .drone.yml                 # Drone CI 配置
```

## 技术信息

- **语言**: Go 1.26.10
- **主要依赖**: Gin (Web 框架)、Coraza v3 (WAF 引擎)、go-yaml (YAML 解析)、golang.org/x/net (HTTP/2)
- **安全特性**: TLS 1.2+ 强密码套件、Slowloris 防护、1MB 请求头限制、WAF fail-closed
