package proxy

import (
	"bufio"
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
	"github.com/lite-lake/infra-gate/internal/trace"
)

// handleWebSocketUpgrade handles the WebSocket handshake with the backend
func (p *Proxy) handleWebSocketUpgrade(r *http.Request, backendURL *url.URL, traceId string) (net.Conn, *bufio.Reader, *http.Response, error) {
	// Determine the scheme for the backend WebSocket connection
	wsScheme := "ws"
	if backendURL.Scheme == "https" {
		wsScheme = "wss"
	}

	// Create the WebSocket URL
	wsURL := &url.URL{
		Scheme:   wsScheme,
		Host:     backendURL.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	// Generate a new Sec-WebSocket-Key for the backend connection
	secKey := make([]byte, 16)
	if _, err := crand.Read(secKey); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate WebSocket key: %w", err)
	}
	backendKey := base64.StdEncoding.EncodeToString(secKey)

	// Build the WebSocket upgrade request
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "GET %s HTTP/1.1\r\n", wsURL.RequestURI())
	// 根据配置决定 Host 头（优先级：overrideHost > !preserveHostHeader > preserveHostHeader）
	// 与 HTTP 请求路径保持一致
	if p.overrideHost != "" {
		fmt.Fprintf(&buf, "Host: %s\r\n", p.overrideHost)
	} else if !p.preserveHostHeader {
		fmt.Fprintf(&buf, "Host: %s\r\n", backendURL.Host)
	} else {
		fmt.Fprintf(&buf, "Host: %s\r\n", r.Host)
	}
	fmt.Fprintf(&buf, "Upgrade: websocket\r\n")
	fmt.Fprintf(&buf, "Connection: Upgrade\r\n")
	fmt.Fprintf(&buf, "Sec-WebSocket-Key: %s\r\n", backendKey)
	fmt.Fprintf(&buf, "Sec-WebSocket-Version: 13\r\n")

	// Add Origin header if present or overridden
	if p.overrideOrigin != "" {
		fmt.Fprintf(&buf, "Origin: %s\r\n", p.overrideOrigin)
	} else if origin := r.Header.Get("Origin"); origin != "" {
		fmt.Fprintf(&buf, "Origin: %s\r\n", origin)
	}

	// Copy relevant WebSocket headers from the original request
	if ext := r.Header.Get("Sec-WebSocket-Extensions"); ext != "" {
		fmt.Fprintf(&buf, "Sec-WebSocket-Extensions: %s\r\n", ext)
	}
	if proto := r.Header.Get("Sec-WebSocket-Protocol"); proto != "" {
		fmt.Fprintf(&buf, "Sec-WebSocket-Protocol: %s\r\n", proto)
	}

	// Copy relevant headers from the original request
	// P2-19: 完整的 hop-by-hop 头过滤列表
	for key, values := range r.Header {
		lowerKey := strings.ToLower(key)
		// Skip hop-by-hop headers, WebSocket-specific headers, and proxy headers we already handled
		if lowerKey == "upgrade" || lowerKey == "connection" ||
			lowerKey == "keep-alive" || lowerKey == "proxy-authenticate" ||
			lowerKey == "proxy-authorization" || lowerKey == "proxy-connection" ||
			lowerKey == "te" || lowerKey == "trailer" || lowerKey == "transfer-encoding" ||
			lowerKey == "sec-websocket-key" || lowerKey == "sec-websocket-version" ||
			lowerKey == "sec-websocket-extensions" || lowerKey == "sec-websocket-protocol" ||
			lowerKey == "host" || lowerKey == "origin" || lowerKey == "x-forwarded-for" ||
			lowerKey == "x-forwarded-host" || lowerKey == "x-forwarded-proto" ||
			lowerKey == "x-forwarded-port" || lowerKey == "forwarded" ||
			lowerKey == "x-real-ip" ||
			lowerKey == "x-lite-gate-forwarded-for" ||
			lowerKey == "x-lite-gate-forwarded-host" ||
			lowerKey == "x-lite-gate-trace-id" ||
			// traceparent 每跳删除重建（内部PRD §5.4）：入站值不透传，
			// 下方按本跳权威 traceId 重新生成
			lowerKey == "traceparent" ||
			lowerKey == "http2-settings" {
			continue
		}
		for _, value := range values {
			fmt.Fprintf(&buf, "%s: %s\r\n", key, value)
		}
	}

	// X-Lite-Gate-Forwarded-For 逐跳逗号追加（内部PRD §4.1，与 HTTP 路径语义
	// 一致）：入站原值 + 本跳直连对端 RemoteAddr（含端口），保留多跳审计轨迹。
	// 入站原值已在上方的头复制循环中跳过（避免与追加值重复），此处从 r.Header 捕获。
	// WebSocket 不追加 Via（维持现状：经本 gate 的 WS 流量不在 Via 中体现）。
	gateForwardedFor := r.RemoteAddr
	if inboundGateForwardedFor := strings.Join(r.Header.Values("X-Lite-Gate-Forwarded-For"), ", "); inboundGateForwardedFor != "" {
		gateForwardedFor = inboundGateForwardedFor + ", " + gateForwardedFor
	}

	// v1.1 per-host 转发策略与 HTTP 路径同源：append 分支（forwarded_for=append 且
	// 直连对端受信时，XFF 追加直连对端、Proto/Host 继承入站最右合法值）在
	// buildForwardedHeaders 内实现；上方复制循环已跳过入站转发头（含 XFF），
	// 入站原值从未修改的原始请求 r 捕获，因此握手头不会出现重复行。
	// WS 无 Via（维持现状）；X-Lite-Gate-Forwarded-For 追加照旧。
	forwardedHeaders := p.buildForwardedHeaders(r)

	// 根据配置决定是否添加代理相关头部
	if !p.stripProxyHeaders {
		fmt.Fprintf(&buf, "X-Forwarded-Proto: %s\r\n", forwardedHeaders.XForwardedProto)
		fmt.Fprintf(&buf, "X-Forwarded-For: %s\r\n", forwardedHeaders.XForwardedFor)
		fmt.Fprintf(&buf, "X-Forwarded-Host: %s\r\n", forwardedHeaders.XForwardedHost)
		fmt.Fprintf(&buf, "X-Forwarded-Port: %s\r\n", forwardedHeaders.XForwardedPort)
		fmt.Fprintf(&buf, "Forwarded: %s\r\n", forwardedHeaders.Forwarded)

		fmt.Fprintf(&buf, "X-Lite-Gate-Forwarded-For: %s\r\n", gateForwardedFor)
		fmt.Fprintf(&buf, "X-Lite-Gate-Forwarded-Host: %s\r\n", r.Host)

		if traceId != "" {
			fmt.Fprintf(&buf, "X-Lite-Gate-Trace-Id: %s\r\n", traceId)
			// traceparent 出站（内部PRD §5.4）：与普通代理路径语义一致，
			// 每跳新 parent-id；权威 ID 为旧格式兼容采信时无法构建 W3C 头，跳过
			tpFlags := ""
			if _, _, f, ok := trace.ParseTraceParent(r.Header.Get(trace.TraceParentHeader)); ok {
				tpFlags = f
			}
			if tp := trace.BuildTraceParent(traceId, tpFlags); tp != "" {
				fmt.Fprintf(&buf, "%s: %s\r\n", trace.TraceParentHeader, tp)
			}
		}
	}

	fmt.Fprintf(&buf, "\r\n")

	// Connect to the backend
	var conn net.Conn
	var err error
	if wsScheme == "wss" {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: p.websocketInsecureSkip,
		}
		// v1.2：TLS SNI（ServerName）与上方 Host 行同源——配置 override_host 时
		// SNI 使用 override 主机名（剥离可选端口），使按 mesh 域名部署证书的上游
		// 网关在 TLS 握手阶段即能选中正确证书/虚拟主机，证书校验也按该域名进行；
		// 未配置 override 时维持原行为：非跳过验证时用后端地址主机名，
		// 跳过验证时留空（由 tls.Dialer 按拨号地址推断 SNI）。
		if p.overrideHost != "" {
			tlsConfig.ServerName = overrideHostServerName(p.overrideHost)
		} else if !p.websocketInsecureSkip && backendURL.Hostname() != "" {
			tlsConfig.ServerName = backendURL.Hostname()
		}
		dialer := &tls.Dialer{
			Config: tlsConfig,
		}
		ctx, cancel := context.WithTimeout(context.Background(), p.wsConfig.HandshakeTimeout)
		defer cancel()
		conn, err = dialer.DialContext(ctx, "tcp", wsDialAddr(backendURL))
	} else {
		conn, err = net.DialTimeout("tcp", wsDialAddr(backendURL), p.wsConfig.HandshakeTimeout)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to connect to backend: %w", err)
	}

	// Set handshake deadline
	conn.SetDeadline(time.Now().Add(p.wsConfig.HandshakeTimeout))

	// Send the upgrade request
	if _, err := conn.Write(buf.Bytes()); err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("failed to send WebSocket upgrade request: %w", err)
	}

	// Read the response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, r)
	if err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("failed to read WebSocket upgrade response: %w", err)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("backend returned status %d instead of 101", resp.StatusCode)
	}

	// P2-18: 验证后端 101 响应中的 Upgrade 和 Connection 头
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("backend 101 response missing valid Upgrade: websocket header")
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Connection")), "upgrade") {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("backend 101 response missing valid Connection: upgrade header")
	}

	// Validate Sec-WebSocket-Accept
	expectedAccept := generateWebSocketAcceptKey(backendKey)
	if resp.Header.Get("Sec-WebSocket-Accept") != expectedAccept {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("invalid Sec-WebSocket-Accept header from backend")
	}

	// Clear the deadline after successful handshake
	conn.SetDeadline(time.Time{})

	return conn, reader, resp, nil
}

// overrideHostServerName 从 override_host 值提取 TLS ServerName（SNI）。
// SNI 不允许携带端口，因此剥离可选的 ":port" 部分；支持 "host"、"host:port"
// 与 IPv6 "[::1]:443" 形态，无端口时原样返回。
func overrideHostServerName(overrideHost string) string {
	if host, _, err := net.SplitHostPort(overrideHost); err == nil && host != "" {
		return host
	}
	return overrideHost
}

// wsDialAddr 返回 WebSocket 后端拨号地址：backendURL.Host 缺省端口时按 scheme
// 补默认端口（wss/https → 443，ws/http → 80）。net.Dialer 与 tls.Dialer 不像
// http.Transport 会自动补默认端口，无端口地址直接报 "missing port in address"。
// 带端口的 Host 原样返回；IPv6 由 JoinHostPort 重新加方括号。
func wsDialAddr(backendURL *url.URL) string {
	if backendURL.Port() != "" {
		return backendURL.Host
	}
	if backendURL.Scheme == "wss" || backendURL.Scheme == "https" {
		return net.JoinHostPort(backendURL.Hostname(), "443")
	}
	return net.JoinHostPort(backendURL.Hostname(), "80")
}

// handleWebSocket handles WebSocket connections
func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request, backend string, backendURL *url.URL, traceId string, loggerWithTrace logger.ILogger) {
	// H13: 检查是否已进入关闭流程，避免在 wsWG.Wait() 之后新增连接
	select {
	case <-p.wsShutdown:
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	default:
	}
	// ★F1d WS 连接上限（内部PRD §4.1.3）：wsShutdown 检查之后、wsWG.Add
	// 之前 Acquire，defer Release；超限 503 + Retry-After。per-IP 键 = 直连对端
	//（边缘连接 ACL 口径，与 allowed_ips/admin 一致）
	if p.wsConfig.ConnLimit != nil {
		directIP := netutil.DirectRemoteIP(r)
		if !p.wsConfig.ConnLimit.Acquire(p.wsConfig.ConnLimitHost, directIP) {
			loggerWithTrace.Warn("WebSocket connection rejected: connection limit reached",
				logger.NewField("host", p.wsConfig.ConnLimitHost),
				logger.NewField("client_ip", directIP),
				logger.NewField("path", r.URL.Path))
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Service Unavailable: WebSocket connection limit reached", http.StatusServiceUnavailable)
			return
		}
		defer p.wsConfig.ConnLimit.Release(p.wsConfig.ConnLimitHost, directIP)
	}
	p.wsWG.Add(1)
	defer p.wsWG.Done()
	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		loggerWithTrace.Error("ResponseWriter does not support Hijacker")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		loggerWithTrace.Error("Failed to hijack client connection",
			logger.NewField("error", err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Connect to the backend and perform WebSocket handshake
	backendConn, backendReader, backendResp, err := p.handleWebSocketUpgrade(r, backendURL, traceId)
	if err != nil {
		errType, _ := detectUpstreamErrorType(err)
		statusCode := getHTTPStatusCodeForError(errType)
		userMessage := getErrorMessageForType(errType)

		loggerWithTrace.Error("WebSocket upgrade to backend failed",
			logger.NewField("backend", netutil.RedactURL(backend)),
			logger.NewField("path", r.URL.Path),
			logger.NewField("error", err),
			logger.NewField("error_type", errType),
			logger.NewField("status_code", statusCode))

		statusText := http.StatusText(statusCode)
		errResp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
			statusCode, statusText, len(userMessage), userMessage)
		clientConn.Write([]byte(errResp))
		return
	}
	defer backendConn.Close()

	// Send 101 Switching Protocols response to client
	secKey := r.Header.Get("Sec-WebSocket-Key")
	secAccept := generateWebSocketAcceptKey(secKey)

	var response bytes.Buffer
	fmt.Fprintf(&response, "HTTP/1.1 101 Switching Protocols\r\n")
	fmt.Fprintf(&response, "Upgrade: websocket\r\n")
	fmt.Fprintf(&response, "Connection: Upgrade\r\n")
	fmt.Fprintf(&response, "Sec-WebSocket-Accept: %s\r\n", secAccept)

	// Verify and negotiate subprotocol
	// P2-17: 客户端可能用逗号分隔的单个 header 发送多个协议，需要按逗号分割
	clientProtocols := r.Header["Sec-WebSocket-Protocol"]
	var allClientProtocols []string
	for _, proto := range clientProtocols {
		for _, p := range strings.Split(proto, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				allClientProtocols = append(allClientProtocols, p)
			}
		}
	}

	backendProtocol := backendResp.Header.Get("Sec-WebSocket-Protocol")
	if len(allClientProtocols) > 0 && backendProtocol != "" {
		// 检查后端返回的协议是否在客户端请求的协议列表中
		found := false
		for _, proto := range allClientProtocols {
			if strings.EqualFold(proto, backendProtocol) {
				found = true
				loggerWithTrace.Debug("WebSocket subprotocol negotiated",
					logger.NewField("subprotocol", backendProtocol))
				break
			}
		}
		if !found {
			// P2-16: 必须将 502 响应写入 clientConn，否则客户端只看到连接关闭
			loggerWithTrace.Error("WebSocket subprotocol negotiation failed",
				logger.NewField("client_protocols", allClientProtocols),
				logger.NewField("backend_protocol", backendProtocol))
			body := "WebSocket subprotocol mismatch"
			errResp := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
				len(body), body)
			clientConn.Write([]byte(errResp))
			return
		}
		fmt.Fprintf(&response, "Sec-WebSocket-Protocol: %s\r\n", backendProtocol)
	}

	// Verify and negotiate extensions
	clientExtensions := r.Header.Get("Sec-WebSocket-Extensions")
	backendExtensions := backendResp.Header.Get("Sec-WebSocket-Extensions")
	acceptedExtensions := ""
	if clientExtensions != "" && backendExtensions != "" {
		// 解析客户端请求的扩展和后端返回的扩展，验证匹配
		// 只有双方都支持的扩展才能转发
		acceptedExtensions = negotiateExtensions(clientExtensions, backendExtensions)
		if acceptedExtensions != "" {
			fmt.Fprintf(&response, "Sec-WebSocket-Extensions: %s\r\n", acceptedExtensions)
		} else if clientExtensions != "" && backendExtensions == "" {
			// 客户端请求扩展但后端没有返回，不转发任何扩展
		}
	} else if backendExtensions != "" {
		// 客户端没有请求扩展，但后端返回了扩展（不应该发生，但保守处理不转发）
	}

	// C13: 检测是否协商了 permessage-deflate 扩展，传递给帧解析器
	permessageDeflate := isPermessageDeflateEnabled(acceptedExtensions)

	if traceId != "" {
		fmt.Fprintf(&response, "X-Lite-Gate-Trace-Id: %s\r\n", traceId)
	}
	fmt.Fprintf(&response, "\r\n")

	if _, err := clientConn.Write(response.Bytes()); err != nil {
		loggerWithTrace.Error("Failed to send WebSocket upgrade response to client",
			logger.NewField("error", err))
		return
	}

	loggerWithTrace.Debug("WebSocket connection established",
		logger.NewField("backend", netutil.RedactURL(backend)),
		logger.NewField("path", r.URL.Path))

	// Start bidirectional proxy
	p.proxyWebSocket(clientConn, clientBuf, backendConn, backendReader, loggerWithTrace, backend, r.URL.Path, permessageDeflate)
}

// isPermessageDeflateEnabled 检查协商的扩展中是否包含 permessage-deflate
func isPermessageDeflateEnabled(extensions string) bool {
	if extensions == "" {
		return false
	}
	for _, ext := range parseWebSocketExtensions(extensions) {
		if strings.EqualFold(ext.Name, "permessage-deflate") {
			return true
		}
	}
	return false
}

// proxyWebSocket proxies WebSocket frames bidirectionally
// permessageDeflate 表示是否协商了 permessage-deflate 扩展，影响 RSV1 位校验
func (p *Proxy) proxyWebSocket(clientConn net.Conn, clientReader *bufio.ReadWriter, backendConn net.Conn, backendReader *bufio.Reader, loggerWithTrace logger.ILogger, backend string, path string, permessageDeflate bool) {
	var wg sync.WaitGroup
	wg.Add(3)

	done := make(chan struct{})
	var closeOnce sync.Once
	closeConns := func() {
		close(done)
		clientConn.Close()
		backendConn.Close()
	}

	clientWriter := newWsConnWriter(clientConn)
	backendWriter := newWsConnWriter(backendConn)

	// Client to backend
	go func() {
		defer wg.Done()
		defer closeOnce.Do(closeConns)

		for {
			// Set read deadline for idle timeout
			clientConn.SetReadDeadline(time.Now().Add(p.wsConfig.IdleTimeout))

			frame, err := readWebSocketFrame(clientReader.Reader, "client", permessageDeflate)
			if err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
					loggerWithTrace.Error("Failed to read WebSocket frame from client",
						logger.NewField("backend", netutil.RedactURL(backend)),
						logger.NewField("path", path),
						logger.NewField("error", err))
				}
				return
			}

			// Clear deadline after successful read
			clientConn.SetReadDeadline(time.Time{})

			// Parse frame header
			b1 := frame[0]
			fin := (b1 & 0x80) != 0
			opcode := b1 & 0x0F

			// Check for close frame
			if opcode == wsOpcodeClose {
				// Send close frame to backend
				if err := backendWriter.writeFrame(frame); err != nil {
					loggerWithTrace.Error("Failed to send close frame to backend",
						logger.NewField("error", err))
				}
				return
			}

			// Handle ping frame from client - send pong back to client AND forward to backend
			// Per RFC 6455 Section 5.4, control frames can be inserted in the middle of a fragmented message
			if opcode == wsOpcodePing {
				// Send pong back to client first (server→client: must NOT mask)
				pongFrame, err := createPongFrameToClient(frame)
				if err != nil {
					loggerWithTrace.Error("Failed to create pong frame for client",
						logger.NewField("error", err))
					return
				}
				if err := clientWriter.writeFrame(pongFrame); err != nil {
					loggerWithTrace.Error("Failed to send pong frame to client",
						logger.NewField("error", err))
					return
				}
				loggerWithTrace.Debug("Sent pong frame to client")

				// Forward ping frame to backend per RFC 6455
				if err := backendWriter.writeFrame(frame); err != nil {
					if !strings.Contains(err.Error(), "use of closed network connection") {
						loggerWithTrace.Error("Failed to forward ping frame to backend",
							logger.NewField("backend", netutil.RedactURL(backend)),
							logger.NewField("path", path),
							logger.NewField("error", err))
					}
					return
				}
				loggerWithTrace.Debug("Forwarded ping frame to backend")
				continue
			}

			// Handle pong frame from client - forward to backend
			// Per RFC 6455 Section 5.4, control frames can be inserted in the middle of a fragmented message
			if opcode == wsOpcodePong {
				loggerWithTrace.Debug("Received pong frame from client, forwarding to backend")
				if err := backendWriter.writeFrame(frame); err != nil {
					if !strings.Contains(err.Error(), "use of closed network connection") {
						loggerWithTrace.Error("Failed to forward pong frame to backend",
							logger.NewField("backend", netutil.RedactURL(backend)),
							logger.NewField("path", path),
							logger.NewField("error", err))
					}
					return
				}
				continue
			}

			// Forward frame to backend (includes fragmented message frames)
			// Per RFC 6455 Section 5.4, we must not change the frame sequence of fragmented messages
			if err := backendWriter.writeFrame(frame); err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					loggerWithTrace.Error("Failed to write WebSocket frame to backend",
						logger.NewField("backend", netutil.RedactURL(backend)),
						logger.NewField("path", path),
						logger.NewField("error", err),
						logger.NewField("fin", fin),
						logger.NewField("opcode", opcode))
				}
				return
			}
		}
	}()

	// Backend to client
	go func() {
		defer wg.Done()
		defer closeOnce.Do(closeConns)

		for {
			// Set read deadline for idle timeout
			backendConn.SetReadDeadline(time.Now().Add(p.wsConfig.IdleTimeout))

			frame, err := readWebSocketFrame(backendReader, "backend", permessageDeflate)
			if err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
					loggerWithTrace.Error("Failed to read WebSocket frame from backend",
						logger.NewField("backend", netutil.RedactURL(backend)),
						logger.NewField("path", path),
						logger.NewField("error", err))
				}
				return
			}

			// Clear deadline after successful read
			backendConn.SetReadDeadline(time.Time{})

			// Parse frame header
			b1 := frame[0]
			fin := (b1 & 0x80) != 0
			opcode := b1 & 0x0F

			// Check for close frame
			if opcode == wsOpcodeClose {
				// Send close frame to client
				if err := clientWriter.writeFrame(frame); err != nil {
					loggerWithTrace.Error("Failed to send close frame to client",
						logger.NewField("error", err))
				}
				return
			}

			// Handle ping frame from backend - send pong back to backend AND forward to client
			// Per RFC 6455 Section 5.4, control frames can be inserted in the middle of a fragmented message
			if opcode == wsOpcodePing {
				// Send pong back to backend first (client→server: must mask)
				pongFrame, err := createPongFrameToBackend(frame)
				if err != nil {
					loggerWithTrace.Error("Failed to create pong frame for backend",
						logger.NewField("error", err))
					return
				}
				if err := backendWriter.writeFrame(pongFrame); err != nil {
					loggerWithTrace.Error("Failed to send pong frame to backend",
						logger.NewField("error", err))
					return
				}
				loggerWithTrace.Debug("Sent pong frame to backend")

				// Forward ping frame to client per RFC 6455
				if err := clientWriter.writeFrame(frame); err != nil {
					if !strings.Contains(err.Error(), "use of closed network connection") {
						loggerWithTrace.Error("Failed to forward ping frame to client",
							logger.NewField("backend", netutil.RedactURL(backend)),
							logger.NewField("path", path),
							logger.NewField("error", err))
					}
					return
				}
				loggerWithTrace.Debug("Forwarded ping frame to client")
				continue
			}

			// Handle pong frame from backend - forward to client
			// Per RFC 6455 Section 5.4, control frames can be inserted in the middle of a fragmented message
			if opcode == wsOpcodePong {
				loggerWithTrace.Debug("Received pong frame from backend, forwarding to client")
				if err := clientWriter.writeFrame(frame); err != nil {
					if !strings.Contains(err.Error(), "use of closed network connection") {
						loggerWithTrace.Error("Failed to forward pong frame to client",
							logger.NewField("backend", netutil.RedactURL(backend)),
							logger.NewField("path", path),
							logger.NewField("error", err))
					}
					return
				}
				continue
			}

			// Forward frame to client (includes fragmented message frames)
			// Per RFC 6455 Section 5.4, we must not change the frame sequence of fragmented messages
			if err := clientWriter.writeFrame(frame); err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					loggerWithTrace.Error("Failed to write WebSocket frame to client",
						logger.NewField("backend", netutil.RedactURL(backend)),
						logger.NewField("path", path),
						logger.NewField("error", err),
						logger.NewField("fin", fin),
						logger.NewField("opcode", opcode))
				}
				return
			}
		}
	}()

	// Keepalive goroutine - periodically sends ping frames to both backend and client
	// P2-15: 原来只发后端 ping，纯接收型客户端 5min 后被 IdleTimeout 关闭
	// 现在同时向客户端发送 ping，保持双向连接活跃
	go func() {
		defer wg.Done()

		ticker := time.NewTicker(p.wsConfig.PingInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				pingFrame, err := createPingFrame()
				if err != nil {
					loggerWithTrace.Error("Failed to create keepalive ping frame",
						logger.NewField("backend", netutil.RedactURL(backend)),
						logger.NewField("path", path),
						logger.NewField("error", err))
					closeOnce.Do(closeConns)
					return
				}
				// Send ping to backend
				if err := backendWriter.writeFrame(pingFrame); err != nil {
					if !strings.Contains(err.Error(), "use of closed network connection") {
						loggerWithTrace.Error("Failed to send keepalive ping to backend",
							logger.NewField("backend", netutil.RedactURL(backend)),
							logger.NewField("path", path),
							logger.NewField("error", err))
					}
					closeOnce.Do(closeConns)
					return
				}
				loggerWithTrace.Debug("Sent keepalive ping to backend")

				// P2-15: Also send ping to client (server→client: must NOT mask)
				clientPing, err := createPingFrameToClient()
				if err != nil {
					loggerWithTrace.Error("Failed to create client keepalive ping frame",
						logger.NewField("path", path),
						logger.NewField("error", err))
					closeOnce.Do(closeConns)
					return
				}
				if err := clientWriter.writeFrame(clientPing); err != nil {
					if !strings.Contains(err.Error(), "use of closed network connection") {
						loggerWithTrace.Error("Failed to send keepalive ping to client",
							logger.NewField("path", path),
							logger.NewField("error", err))
					}
					closeOnce.Do(closeConns)
					return
				}
				loggerWithTrace.Debug("Sent keepalive ping to client")
			case <-done:
				return
			case <-p.wsShutdown:
				closeOnce.Do(closeConns)
				return
			}
		}
	}()

	wg.Wait()

	loggerWithTrace.Debug("WebSocket connection closed",
		logger.NewField("backend", netutil.RedactURL(backend)),
		logger.NewField("path", path))
}
