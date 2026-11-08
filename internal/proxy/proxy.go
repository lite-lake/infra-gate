package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lite-lake/infra-gate/internal/health"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
	"github.com/lite-lake/infra-gate/internal/templates"
	"github.com/lite-lake/infra-gate/internal/trace"
	"golang.org/x/net/http2"
)

// WSConfig 保存 WebSocket 代理的可配置超时参数
type WSConfig struct {
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	PingInterval     time.Duration
	// ConnLimit WS 连接三级上限治理（F1d，内部PRD §4.1.3）：
	// nil = 不限制（resource_governance.enabled=false 逃生口）
	ConnLimit WSConnLimit
	// ConnLimitHost 连接计数的 host 维度键（host 配置名，有界键空间）
	ConnLimitHost string
}

// WSConnLimit WS 连接上限接口（*resguard.ConnLimiter 天然满足；接口化便于
// proxy 包测试注入 fake，避免 proxy → resguard 直接依赖）
type WSConnLimit interface {
	// Acquire 三级试占（全局/per-host/per-IP），任一超限返回 false
	Acquire(host, ip string) bool
	// Release 释放一次占用（与 Acquire 成对）
	Release(host, ip string)
}

// UpstreamConfig F1c 上游连接池与超时配置（内部PRD §4.1.4）：
// MaxConnsPerHost 单 host 连接上限（原 0=无上限，现缺省 256）；
// ResponseHeaderTimeout 等待后端响应头时长（缺省维持 1800s 零回归，D1）。
// 两项均由 config 层完成 server/host 合并后传入
type UpstreamConfig struct {
	MaxConnsPerHost       int
	ResponseHeaderTimeout time.Duration
}

// defaultWSConfig 返回默认的 WebSocket 配置
func defaultWSConfig() WSConfig {
	return WSConfig{
		HandshakeTimeout: 30 * time.Second,
		IdleTimeout:      5 * time.Minute,
		PingInterval:     30 * time.Second,
	}
}

// forwardedForAppend 与 config.ForwardedForAppend 对应（proxy 包不反向依赖 config，
// 取值一致性由 config.Validate 保证）：forwarded_for=append 的 mesh 追加语义取值。
const forwardedForAppend = "append"

type Proxy struct {
	backends              []string
	healthy               map[string]bool
	healthFailCount       map[string]int // P2-53: 连续失败计数
	healthSuccessCount    map[string]int // P2-53: 连续成功计数
	healthChecker         *health.Checker
	mutex                 sync.RWMutex
	logger                logger.ILogger
	renderer              *templates.Renderer
	transport             *http.Transport
	trustedProxies        []*net.IPNet
	websocketInsecureSkip bool
	preserveHostHeader    bool
	overrideHost          string // 自定义Host头值，优先级最高
	overrideOrigin        string // 自定义Origin头值，用于覆盖客户端Origin
	clearAcceptEncoding   bool   // 是否清除发给上游的 Accept-Encoding 头，避免双重压缩
	stripProxyHeaders     bool   // 是否剥离所有代理相关头部
	forwardedFor          string // per-host 转发策略（v1.1）：""=边缘语义（恒删头重建），forwardedForAppend=mesh 追加语义
	wsWG                  sync.WaitGroup
	wsShutdown            chan struct{}
	wsShutdownOnce        sync.Once
	wsConfig              WSConfig
}

// isTrustedDirectPeer 判断直连对端是否命中 server.trusted_proxies 网段
// （v1.1：forwarded_for=append host 的追加门槛）。gate 未配置 trusted_proxies
// 或直连对端不在网段时返回 false —— fail-safe 回退边缘语义。
func (p *Proxy) isTrustedDirectPeer(r *http.Request) bool {
	if len(p.trustedProxies) == 0 {
		return false
	}
	directIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(directIP); err == nil {
		directIP = host
	}
	directNetIP := net.ParseIP(directIP)
	return directNetIP != nil && netutil.IsIPInNetworks(directNetIP, p.trustedProxies)
}

// getClientInfo 解析真实客户端信息（IP、proto、完整 XFF 链）。
// v1.1 起（内部PRD per-host 转发策略）仅在 forwarded_for=append 且直连对端
// 受信的分支被调用（供 Forwarded 头 for= 取解析结果）；缺省 host 恒为边缘语义，
// 不再经此函数解析 XFF。
func (p *Proxy) getClientInfo(r *http.Request) (string, string, string) {
	directAddr := r.RemoteAddr
	directIP := directAddr
	if host, _, err := net.SplitHostPort(directAddr); err == nil {
		directIP = host
	}

	var xffChain []string
	if existingXff := r.Header.Get("X-Forwarded-For"); existingXff != "" {
		xffChain = strings.Split(existingXff, ",")
		for i, ip := range xffChain {
			xffChain[i] = strings.TrimSpace(ip)
		}
	}
	xffChain = append(xffChain, directIP)
	fullXff := strings.Join(xffChain, ", ")

	if len(p.trustedProxies) == 0 {
		proto := "http"
		if r.TLS != nil {
			proto = "https"
		}
		return directIP, proto, fullXff
	}

	directNetIP := net.ParseIP(directIP)
	if directNetIP == nil || !netutil.IsIPInNetworks(directNetIP, p.trustedProxies) {
		proto := "http"
		if r.TLS != nil {
			proto = "https"
		}
		return directIP, proto, fullXff
	}

	clientIP := netutil.ResolveClientIP(r, p.trustedProxies)

	var clientProto string
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		protos := strings.Split(xfp, ",")
		for i := len(protos) - 1; i >= 0; i-- {
			proto := strings.TrimSpace(strings.ToLower(protos[i]))
			if proto == "http" || proto == "https" {
				clientProto = proto
				break
			}
		}
	}

	if clientProto == "" {
		clientProto = "http"
		if r.TLS != nil {
			clientProto = "https"
		}
	}

	return clientIP, clientProto, fullXff
}

type ForwardedHeaders struct {
	XForwardedFor   string
	XForwardedProto string
	XForwardedHost  string
	XForwardedPort  string
	Forwarded       string
}

func (p *Proxy) buildForwardedHeaders(r *http.Request) ForwardedHeaders {
	directAddr := r.RemoteAddr
	directIP := directAddr
	if host, _, err := net.SplitHostPort(directAddr); err == nil {
		directIP = host
	}

	// v1.1 per-host 转发策略（内部PRD）：
	// appendTrusted 仅在 forwarded_for=append（mesh 域名 host）且直连对端 ∈
	// server.trusted_proxies 时为 true。缺省 host（forwarded_for=""）恒为边缘语义，
	// 与 trusted_proxies 完全无关（行为等同 trustedProxies 为空）；append host
	// 直连对端不受信（或 gate 未配 trusted_proxies）时 fail-safe 回退边缘语义。
	appendTrusted := p.forwardedFor == forwardedForAppend && p.isTrustedDirectPeer(r)

	var trustedProto string
	var trustedHost string

	if appendTrusted {
		// mesh 追加语义：Proto/Host 仅继承上一跳的值（取入站链最右合法值）；
		// XFF 走下方追加分支（入站原值 + 直连对端），不再单值重建
		if existingXfp := r.Header.Get("X-Forwarded-Proto"); existingXfp != "" {
			protos := strings.Split(existingXfp, ",")
			for i := len(protos) - 1; i >= 0; i-- {
				proto := strings.TrimSpace(strings.ToLower(protos[i]))
				if proto == "http" || proto == "https" {
					trustedProto = proto
					break
				}
			}
		}

		if existingXfh := r.Header.Get("X-Forwarded-Host"); existingXfh != "" {
			hosts := strings.Split(existingXfh, ",")
			if len(hosts) > 0 {
				trustedHost = strings.TrimSpace(hosts[len(hosts)-1])
			}
		}
	}

	// 出站 XFF（v1.0 决策 D1 单值重建 + v1.1 per-host 追加分支）：
	// - 边缘语义（缺省 host / append 未受信回退）：恒为直连对端 IP（单值），
	//   入站伪造链一律丢弃，每跳删旧重建，应用只需信任直连对端一段；
	// - append 受信：入站 XFF 原值 + ", " + 直连对端 IP（入站为空则单值直连 IP）。
	//   ServeHTTP / websocket 复制循环均先删/跳过入站头再写入本值，
	//   入站原值从未修改的原始请求 r 捕获（等价于 Via 的「Del 前捕获 + 追加重建」模式）。
	outboundXFF := directIP
	clientIP := directIP
	if appendTrusted {
		if inboundXFF := strings.Join(r.Header.Values("X-Forwarded-For"), ", "); inboundXFF != "" {
			outboundXFF = inboundXFF + ", " + directIP
		}
		// Forwarded 头 for= 使用解析后的真实客户端 IP（getClientInfo 受信分支）
		clientIP, _, _ = p.getClientInfo(r)
	}

	clientProto := "http"
	// 对于HTTP/2请求，优先使用:scheme伪头
	if r.ProtoMajor == 2 && r.URL.Scheme != "" {
		clientProto = r.URL.Scheme
	} else if r.TLS != nil {
		clientProto = "https"
	}
	if trustedProto != "" {
		clientProto = trustedProto
	}

	clientHost := r.Host
	if trustedHost != "" {
		clientHost = trustedHost
	}

	// H19: 不从 Host 头解析端口作为 X-Forwarded-Port（概念错误）
	// Host 头中的端口是客户端访问代理的端口，不是客户端源端口
	// 使用标准端口 80/443 作为目标端口标识
	clientPort := "80"
	if clientProto == "https" {
		clientPort = "443"
	}

	// P2-7: 传入 clientHost 而非使用 r.Host，并添加 by= 参数
	forwardedHeader := buildForwardedHeader(r, clientIP, clientProto, clientHost)

	return ForwardedHeaders{
		XForwardedFor:   outboundXFF,
		XForwardedProto: clientProto,
		XForwardedHost:  clientHost,
		XForwardedPort:  clientPort,
		Forwarded:       forwardedHeader,
	}
}

// buildForwardedHeader 构建 RFC 7239 Forwarded 头
// P2-7: 添加 by= 参数（标识本代理），host= 使用 clientHost 而非 r.Host
func buildForwardedHeader(r *http.Request, clientIP, clientProto, clientHost string) string {
	parts := make([]string, 0, 5)

	forIP := clientIP
	if ip := net.ParseIP(clientIP); ip != nil {
		if ip.To4() == nil {
			forIP = fmt.Sprintf("[%s]", clientIP)
		}
	}
	parts = append(parts, fmt.Sprintf("for=%s", forIP))

	// by= 标识接收请求的代理节点，使用 _ (RFC 7239 占位符) 表示不暴露内部地址
	parts = append(parts, "by=_")

	parts = append(parts, fmt.Sprintf("proto=%s", clientProto))
	parts = append(parts, fmt.Sprintf("host=%s", clientHost))

	return strings.Join(parts, ";")
}

// NewProxy 创建代理实例
// H37: interval/timeout 使用 time.Duration 而非 int 秒数，避免亚秒级截断
// forwardedFor 为 per-host 转发策略（v1.1）：""=边缘语义（恒删头重建），
// forwardedForAppend=mesh 追加语义（直连对端受信时追加入站 XFF/Proto/Host）
func NewProxy(backends []string, healthPath string, interval, timeout time.Duration, log logger.ILogger, renderer *templates.Renderer, trustedProxies []string, websocketInsecureSkip bool, preserveHostHeader bool, overrideHost string, overrideOrigin string, clearAcceptEncoding bool, healthCheckEnabled bool, stripProxyHeaders bool, forwardedFor string, wsConfig WSConfig, upstream UpstreamConfig) *Proxy {
	if upstream.MaxConnsPerHost <= 0 {
		upstream.MaxConnsPerHost = 256
	}
	if upstream.ResponseHeaderTimeout <= 0 {
		upstream.ResponseHeaderTimeout = 1800 * time.Second
	}
	if wsConfig.HandshakeTimeout == 0 || wsConfig.IdleTimeout == 0 || wsConfig.PingInterval == 0 {
		defaults := defaultWSConfig()
		if wsConfig.HandshakeTimeout == 0 {
			wsConfig.HandshakeTimeout = defaults.HandshakeTimeout
		}
		if wsConfig.IdleTimeout == 0 {
			wsConfig.IdleTimeout = defaults.IdleTimeout
		}
		if wsConfig.PingInterval == 0 {
			wsConfig.PingInterval = defaults.PingInterval
		}
	}
	p := &Proxy{
		backends:              backends,
		healthy:               make(map[string]bool),
		healthFailCount:       make(map[string]int),
		healthSuccessCount:    make(map[string]int),
		logger:                log,
		renderer:              renderer,
		trustedProxies:        netutil.ParseTrustedProxies(trustedProxies),
		websocketInsecureSkip: websocketInsecureSkip,
		preserveHostHeader:    preserveHostHeader,
		overrideHost:          overrideHost,
		overrideOrigin:        overrideOrigin,
		clearAcceptEncoding:   clearAcceptEncoding,
		stripProxyHeaders:     stripProxyHeaders,
		forwardedFor:          forwardedFor,
		wsShutdown:            make(chan struct{}),
		wsConfig:              wsConfig,
		transport: &http.Transport{
			// L2（内部PRD）：显式禁用环境代理——ProxyFromEnvironment 会让
			// HTTP_PROXY/HTTPS_PROXY 环境变量劫持全部后端出网流量；后端 mesh/直连
			// 即主路径，确需代理的出网场景走显式配置
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   60 * time.Second,
				KeepAlive: 90 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        200,
			MaxIdleConnsPerHost: 100,
			// F1c（内部PRD §4.1.4）：上游连接池上限（原 0=无上限；缺省由
			// config 层取 256，LLM host 建议 512+ 经 per-host 覆盖传入）。h2 上游不受
			// 该值约束（对端 MAX_CONCURRENT_STREAMS 自然限流，接受现状）
			MaxConnsPerHost:       upstream.MaxConnsPerHost,
			IdleConnTimeout:       600 * time.Second,
			TLSHandshakeTimeout:   30 * time.Second,
			ExpectContinueTimeout: 10 * time.Second,
			// F1c：等待后端响应头时长（缺省 1800s 维持零回归，D1；per-host 可收紧）
			ResponseHeaderTimeout: upstream.ResponseHeaderTimeout,
			ReadBufferSize:        64 * 1024,
			WriteBufferSize:       64 * 1024,
			DisableCompression:    clearAcceptEncoding,
		},
	}

	if err := http2.ConfigureTransport(p.transport); err != nil {
		log.Warn("Failed to configure HTTP/2 transport, h2c support may be limited",
			logger.NewField("error", err))
	}

	// Initialize all backends as healthy
	for _, backend := range backends {
		p.healthy[backend] = true
	}

	// Start health checker
	if healthCheckEnabled {
		p.healthChecker = health.NewChecker(backends, healthPath, interval, timeout, p.updateHealthStatus, log)
		p.healthChecker.Start()
	}

	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get TraceId from request
	traceId := trace.GetTraceIdFromRequest(r)
	loggerWithTrace := p.logger
	if traceId != "" {
		loggerWithTrace = p.logger.WithTraceId(traceId)
	}

	// 检测并记录HTTP/2连接信息
	isHTTP2 := r.ProtoMajor == 2
	if isHTTP2 {
		loggerWithTrace.Debug("HTTP/2 connection detected",
			logger.NewField("proto", r.Proto),
			logger.NewField("method", r.Method),
			logger.NewField("path", r.URL.Path),
			logger.NewField("host", r.Host))
	}

	backend, err := p.selectBackend()
	if err != nil {
		loggerWithTrace.Warn("Service unavailable",
			logger.NewField("path", r.URL.Path),
			logger.NewField("method", r.Method))

		// 使用模板渲染器渲染上游服务器错误页面
		if p.renderer != nil {
			p.renderer.RenderUpstreamError(w, traceId, err.Error(), "", http.StatusServiceUnavailable, 0, 30)
		} else {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		}
		return
	}

	// Parse backend URL
	backendURL, err := url.Parse(backend)
	if err != nil {
		loggerWithTrace.Error("Failed to parse backend URL",
			logger.NewField("backend", netutil.RedactURL(backend)),
			logger.NewField("error", err))

		// 使用模板渲染器渲染系统错误页面
		if p.renderer != nil {
			p.renderer.RenderSystemError(w, traceId, "URL解析错误", "错误", r.URL.Path, "")
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// Check if this is a WebSocket upgrade request (RFC 6455)
	isWebSocket := netutil.IsWebSocketUpgrade(r)

	// Handle WebSocket connections separately
	if isWebSocket {
		p.handleWebSocket(w, r, backend, backendURL, traceId, loggerWithTrace)
		return
	}

	// Create proxy request
	proxyReq := r.Clone(r.Context())

	// 处理HTTP/2伪头
	// HTTP/2伪头以":"开头，不应该直接转发给HTTP/1.1后端
	// 这些伪头在http.Request对象中已经被正确映射到相应字段：
	// :authority -> r.Host
	// :scheme -> r.URL.Scheme (但我们会使用后端URL的scheme)
	// :method -> r.Method
	// :path -> r.URL.Path 和 r.URL.RawQuery
	if isHTTP2 {
		loggerWithTrace.Debug("Processing HTTP/2 pseudo-headers",
			logger.NewField("authority", r.Host),
			logger.NewField("scheme", r.URL.Scheme),
			logger.NewField("method", r.Method),
			logger.NewField("path", r.URL.Path),
			logger.NewField("query", r.URL.RawQuery))

		// 对于HTTP/2请求，确保Host头被正确设置
		// :authority伪头已经被Go的HTTP/2实现映射到r.Host
		if r.Host == "" && r.URL.Host != "" {
			proxyReq.Host = r.URL.Host
		}

		// 确保请求路径正确（:path伪头已映射到r.URL.Path和r.URL.RawQuery）
		// 对于HTTP/2，路径应该是绝对路径或完整URL
		if r.URL.Scheme == "" {
			// 如果原始请求没有scheme，根据TLS状态推断
			if r.TLS != nil {
				proxyReq.URL.Scheme = "https"
			} else {
				proxyReq.URL.Scheme = "http"
			}
		}
	}

	proxyReq.URL.Scheme = backendURL.Scheme
	proxyReq.URL.Host = backendURL.Host
	// 根据配置决定Host头（优先级：overrideHost > !preserveHostHeader > preserveHostHeader）
	if p.overrideHost != "" {
		proxyReq.Host = p.overrideHost
	} else if !p.preserveHostHeader {
		proxyReq.Host = backendURL.Host
	}
	proxyReq.RequestURI = ""

	// Remove hop-by-hop headers
	// RFC 7230 Section 6.1: Connection header中列出的每个头名也是hop-by-hop的，必须被移除
	hopByHopHeaders := []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Trailer", "Transfer-Encoding", "Upgrade",
		"Proxy-Connection", "HTTP2-Settings",
	}
	if connHeaders := r.Header["Connection"]; len(connHeaders) > 0 {
		for _, h := range connHeaders {
			// P2-21: Connection 头值可能用逗号分隔多个头名，需要逐个解析
			for _, part := range strings.Split(h, ",") {
				trimmed := strings.TrimSpace(part)
				if trimmed != "" && !strings.EqualFold(trimmed, "close") && !strings.EqualFold(trimmed, "keep-alive") {
					hopByHopHeaders = append(hopByHopHeaders, trimmed)
				}
			}
		}
	}
	for _, header := range hopByHopHeaders {
		proxyReq.Header.Del(header)
	}

	// Handle TE header per RFC 7230 Section 4.3
	// Only remove "trailers" value, preserve other TE values like "compress", "gzip"
	teHeader := proxyReq.Header.Get("Te")
	if teHeader != "" {
		teValues := strings.Split(teHeader, ",")
		var filtered []string
		for _, v := range teValues {
			v = strings.TrimSpace(strings.ToLower(v))
			if v != "trailers" && v != "" {
				filtered = append(filtered, strings.TrimSpace(v))
			}
		}
		if len(filtered) > 0 {
			proxyReq.Header.Set("Te", strings.Join(filtered, ", "))
		} else {
			proxyReq.Header.Del("Te")
		}
	}

	// HTTP/2伪头处理说明：
	// Go的HTTP/2实现会自动将伪头映射到http.Request的标准字段，
	// 不会将它们放入Header中，因此无需手动删除。
	// - :authority -> r.Host
	// - :scheme -> r.URL.Scheme
	// - :method -> r.Method
	// - :path -> r.URL.Path
	// ForceAttemptHTTP2已设置为true，支持HTTP/2到HTTP/2的直接转发。
	// 当后端支持HTTP/2时，transport会自动升级到HTTP/2连接。

	// Always remove client-sent proxy headers to prevent spoofing
	// This runs regardless of stripProxyHeaders setting
	// Via / X-Lite-Gate-Forwarded-For 为逐跳追加语义（内部PRD §4.1）：
	// 删除前先捕获入站原值，重建时拼接为「原值 + ", " + 本跳值」，保留多跳审计轨迹
	// v1.1 per-host 转发策略：forwarded_for=append 受信直连时，XFF/Proto/Host 的
	// 入站原值由 buildForwardedHeaders(r) 从未修改的原始请求捕获，重建为追加/继承
	// 形态单行（语义上等于「不删 + 追加」，且避免多行头重复）；其余情况一律删旧重建。
	inboundVia := strings.Join(proxyReq.Header.Values("Via"), ", ")
	inboundGateForwardedFor := strings.Join(proxyReq.Header.Values("X-Lite-Gate-Forwarded-For"), ", ")
	proxyReq.Header.Del("X-Forwarded-For")
	proxyReq.Header.Del("X-Forwarded-Host")
	proxyReq.Header.Del("X-Forwarded-Proto")
	proxyReq.Header.Del("X-Forwarded-Port")
	proxyReq.Header.Del("Forwarded")
	// X-Real-IP 全链路禁用（内部PRD §4.1）：gate 永不生成、永不透传，
	// 客户端伪造值一律删除；WebSocket 路径在头复制循环中同步跳过（websocket.go）。
	proxyReq.Header.Del("X-Real-IP")
	proxyReq.Header.Del("X-Lite-Gate-Forwarded-For")
	proxyReq.Header.Del("X-Lite-Gate-Forwarded-Host")
	proxyReq.Header.Del(trace.TraceIdHeader)
	// traceparent 每跳删除重建（内部PRD §5.3）：入站值（含伪造）不透传，
	// 由下方按本跳权威 traceId 重新生成（trace-id 与 X-Lite-Gate-Trace-Id 一致）
	proxyReq.Header.Del(trace.TraceParentHeader)
	proxyReq.Header.Del("Via")

	// 根据配置决定是否添加代理相关头部
	if !p.stripProxyHeaders {
		// Build forwarded headers preserving trusted proxy chain info
		forwardedHeaders := p.buildForwardedHeaders(r)

		proxyReq.Header.Add("X-Forwarded-For", forwardedHeaders.XForwardedFor)
		proxyReq.Header.Add("X-Forwarded-Proto", forwardedHeaders.XForwardedProto)
		proxyReq.Header.Add("X-Forwarded-Host", forwardedHeaders.XForwardedHost)
		proxyReq.Header.Add("X-Forwarded-Port", forwardedHeaders.XForwardedPort)
		proxyReq.Header.Add("Forwarded", forwardedHeaders.Forwarded)

		// Add custom forwarding headers
		// X-Lite-Gate-Forwarded-For 逐跳逗号追加（内部PRD §4.1）：
		// 本跳记录直连对端 RemoteAddr（含端口），入站原值在前，多跳轨迹可审计
		gateForwardedFor := r.RemoteAddr
		if inboundGateForwardedFor != "" {
			gateForwardedFor = inboundGateForwardedFor + ", " + gateForwardedFor
		}
		proxyReq.Header.Add("X-Lite-Gate-Forwarded-For", gateForwardedFor)
		proxyReq.Header.Add("X-Lite-Gate-Forwarded-Host", r.Host)
		if traceId != "" {
			proxyReq.Header.Add(trace.TraceIdHeader, traceId)
			// traceparent 出站重建（内部PRD §5.3）：每跳新生成 parent-id，
			// flags 继承本跳回填值（server 中间件已按采信/生成语义写入）；
			// 权威 ID 为旧格式兼容采信时无法构建 W3C 头，BuildTraceParent 返回空跳过
			tpFlags := ""
			if _, _, f, ok := trace.ParseTraceParent(r.Header.Get(trace.TraceParentHeader)); ok {
				tpFlags = f
			}
			if tp := trace.BuildTraceParent(traceId, tpFlags); tp != "" {
				proxyReq.Header.Set(trace.TraceParentHeader, tp)
			}
		}

		// Add Via header per RFC 7230 Section 5.7.1
		// Format: Via: [protocol-version] [proxy-name]
		// 逐跳逗号追加：入站原值已在上方 Del 前捕获（此前在 Del 之后读 proxyReq 的
		// Via 永远读不到入站原值，导致多跳轨迹丢失）
		viaValue := "1.1 lite-gate"
		if r.ProtoMajor == 2 {
			viaValue = "2.0 lite-gate"
		}
		if inboundVia != "" {
			viaValue = inboundVia + ", " + viaValue
		}
		proxyReq.Header.Set("Via", viaValue)
	}

	// 如果配置了 overrideOrigin，覆盖 Origin 头
	if p.overrideOrigin != "" {
		proxyReq.Header.Set("Origin", p.overrideOrigin)
		p.logger.Debug("Overrode Origin header for upstream request",
			logger.NewField("origin", p.overrideOrigin),
			logger.NewField("path", r.URL.Path))
	}

	// 如果启用了 clearAcceptEncoding（即本地 gzip 中间件启用），清除发给上游的 Accept-Encoding
	// 这样可以避免双重压缩，并确保 WAF 能看到明文响应
	if p.clearAcceptEncoding {
		proxyReq.Header.Del("Accept-Encoding")
		p.logger.Debug("Cleared Accept-Encoding header for upstream request",
			logger.NewField("path", r.URL.Path))
	}

	// Forward request
	// 注意：完全不修改 Accept-Encoding 头，100% 尊重客户端的原始请求
	// 这样 Docker Registry、API 等特殊协议才能正常工作
	// gzip 压缩由 server.go 中的 gzip 中间件统一处理（基于配置）

	// Handle Expect: 100-continue
	// 如果客户端发送了Expect: 100-continue头，我们需要先与后端进行握手
	// transport的ExpectContinueTimeout配置会自动处理大部分情况，
	// 但我们需要确保在特殊情况下也能正确处理
	if strings.EqualFold(r.Header.Get("Expect"), "100-continue") {
		loggerWithTrace.Debug("Handling Expect: 100-continue request",
			logger.NewField("backend", netutil.RedactURL(backend)),
			logger.NewField("path", r.URL.Path))
		// http.Transport会根据ExpectContinueTimeout自动处理100-continue
		// 如果后端在超时时间内没有响应100 Continue，transport会继续发送请求体
	}

	resp, err := p.transport.RoundTrip(proxyReq)
	if err != nil {
		errType, _ := detectUpstreamErrorType(err)
		statusCode := getHTTPStatusCodeForError(errType)
		userMessage := getErrorMessageForType(errType)

		loggerWithTrace.Error("Backend request failed",
			logger.NewField("backend", netutil.RedactURL(backend)),
			logger.NewField("path", r.URL.Path),
			logger.NewField("error", err),
			logger.NewField("error_type", errType),
			logger.NewField("status_code", statusCode))

		if p.renderer != nil {
			p.renderer.RenderUpstreamError(w, traceId, userMessage, backend, statusCode, 0, 30)
		} else {
			http.Error(w, userMessage, statusCode)
		}
		return
	}
	defer resp.Body.Close()

	// Check if upstream response is already compressed
	upstreamContentEncoding := resp.Header.Get("Content-Encoding")
	if upstreamContentEncoding != "" {
		loggerWithTrace.Debug("Upstream response already compressed",
			logger.NewField("backend", netutil.RedactURL(backend)),
			logger.NewField("path", r.URL.Path),
			logger.NewField("content_encoding", upstreamContentEncoding))
	}

	// Copy headers, filtering hop-by-hop headers and gateway-authoritative headers.
	// H16: 保留 Trailer 声明头（声明哪些 trailer 字段会出现），仅移除逐跳头。
	//
	// 本名单语义 = 逐跳头 + 网关权威响应头。网关权威响应头由网关唯一决定，上游
	//（内层 gate/后端）返回的同名头一律丢弃，响应侧唯一注入点是 server 的 Set：
	//   - trace 头（内部PRD §5.3 决策 D3）：上游同名头丢弃；traceparent/
	//     tracestate 按 W3C §6.3 不随响应下发（决策 D7）。
	//   - HSTS 归网关（内部PRD §5.1 决策 D1）：网关做 TLS 终止，per-host
	//     hsts 是唯一权威，单点写入即唯一来源。上游 HSTS 一律丢弃，不论本跳是否
	//     下发——与 hsts:"off"＝「不下发」的既有语义自洽，也与链路深度、上游实现、
	//     配置标注完整性解耦（每多一跳就多一条 Add 的结构性双发由此根治）。
	//   - CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy 等安全头
	//     归应用，网关不介入，勿把整组安全头纳入本名单（内部PRD §4.5 实测
	//     无重复，归属应用）。
	responseHopByHopHeaders := []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Transfer-Encoding", "Upgrade",
		"Proxy-Connection", "HTTP2-Settings",
		"Strict-Transport-Security",
		trace.TraceIdHeader, trace.TraceParentHeader, trace.TraceStateHeader,
	}

	// Also remove headers listed in Connection header
	if connHeaders := resp.Header["Connection"]; len(connHeaders) > 0 {
		for _, h := range connHeaders {
			// P2-21: Connection 头值可能用逗号分隔多个头名
			for _, part := range strings.Split(h, ",") {
				trimmed := strings.TrimSpace(part)
				if trimmed != "" {
					responseHopByHopHeaders = append(responseHopByHopHeaders, trimmed)
				}
			}
		}
	}

	for key, values := range resp.Header {
		// Skip hop-by-hop headers
		shouldSkip := false
		for _, hopHeader := range responseHopByHopHeaders {
			if strings.EqualFold(key, hopHeader) {
				shouldSkip = true
				break
			}
		}
		if shouldSkip {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Restore Content-Length if it was stripped by the transport.
	// Go's http.Transport transparently decompresses gzip responses when it
	// auto-added Accept-Encoding: gzip, removing both Content-Encoding and
	// Content-Length from resp.Header. It also de-chunks chunked responses,
	// stripping Transfer-Encoding without setting Content-Length. In both cases
	// resp.ContentLength holds the correct decoded body length (or -1 if unknown).
	// Without Content-Length or Transfer-Encoding, HTTP/1.1 clients cannot
	// determine response body boundaries, causing "unexpected EOF" errors.
	if w.Header().Get("Content-Length") == "" && resp.ContentLength >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}

	// （内部PRD §5.3）原此处的 TraceId 响应头冗余 Add 已删除：
	// 响应侧唯一注入点收敛到 server 中间件（决策 D3），上游同名头已在上方复制循环过滤

	// Copy status code
	w.WriteHeader(resp.StatusCode)

	// Copy body with flush support
	// H17: 仅对 SSE/streaming 响应逐次 flush，大文件传输使用 buffer 减少 flush 开销
	var bytesCopied int64
	flusher, ok := w.(http.Flusher)
	// 检测 SSE/streaming 响应，这些需要逐次 flush
	isStreaming := strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") ||
		resp.StatusCode == http.StatusNoContent ||
		resp.TransferEncoding != nil && len(resp.TransferEncoding) > 0
	if ok && isStreaming {
		buf := make([]byte, 64*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				written, writeErr := w.Write(buf[:n])
				bytesCopied += int64(written)
				if writeErr != nil {
					loggerWithTrace.Error("Failed to write response body",
						logger.NewField("backend", netutil.RedactURL(backend)),
						logger.NewField("error", writeErr))
					return
				}
				flusher.Flush()
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				loggerWithTrace.Error("Failed to read response body",
					logger.NewField("backend", netutil.RedactURL(backend)),
					logger.NewField("error", err))
				return
			}
		}
	} else if ok {
		// H17: 非 streaming 响应使用更大 buffer 且仅在 buffer 满时 flush
		buf := make([]byte, 64*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				written, writeErr := w.Write(buf[:n])
				bytesCopied += int64(written)
				if writeErr != nil {
					loggerWithTrace.Error("Failed to write response body",
						logger.NewField("backend", netutil.RedactURL(backend)),
						logger.NewField("error", writeErr))
					return
				}
			}
			if err == io.EOF {
				// 最后一次 flush 确保所有数据发送
				flusher.Flush()
				break
			}
			if err != nil {
				loggerWithTrace.Error("Failed to read response body",
					logger.NewField("backend", netutil.RedactURL(backend)),
					logger.NewField("error", err))
				return
			}
		}
	} else {
		bytesCopied, err = io.Copy(w, resp.Body)
		if err != nil {
			loggerWithTrace.Error("Failed to copy response body",
				logger.NewField("backend", netutil.RedactURL(backend)),
				logger.NewField("error", err))
			return
		}
	}

	loggerWithTrace.Debug("Successfully proxied request",
		logger.NewField("backend", netutil.RedactURL(backend)),
		logger.NewField("path", r.URL.Path),
		logger.NewField("status", resp.StatusCode),
		logger.NewField("bytes", bytesCopied),
		logger.NewField("client_proto", r.Proto),
		logger.NewField("server_proto", resp.Proto),
		logger.NewField("is_http2_client", isHTTP2),
		logger.NewField("is_http2_server", resp.ProtoMajor == 2))
}

func (p *Proxy) Stop() {
	p.logger.Info("Stopping proxy")
	if p.healthChecker != nil {
		p.healthChecker.Stop()
	}

	// Signal all WebSocket connections to shut down
	p.wsShutdownOnce.Do(func() {
		close(p.wsShutdown)
	})

	// Wait for WebSocket connections to close (with timeout)
	// P2-39: 增加 WebSocket 关闭超时到 30s，10s 可能不足以完成关闭握手
	wsDone := make(chan struct{})
	go func() {
		p.wsWG.Wait()
		close(wsDone)
	}()
	select {
	case <-wsDone:
		p.logger.Info("All WebSocket connections closed gracefully")
	case <-time.After(30 * time.Second):
		// P2-39: 超时后不再等待，wsWG 中的 goroutine 会在 wsShutdown 信号后自行退出
		p.logger.Warn("Timed out waiting for WebSocket connections to close, proceeding with shutdown")
	}

	// Close idle transport connections to release backend connection pool
	p.transport.CloseIdleConnections()
}
