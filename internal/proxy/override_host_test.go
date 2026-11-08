package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// --- v1.2 override_host 二级链路（边缘 gate → mesh gate）测试 ---
//
// 目标模型（内部PRD v1.2）：
// - gateA（边缘，公网域名 host，默认边缘转发语义）配置 override_host=gateB 的 mesh 域名；
// - gateB 收到的 Host = mesh 域名 → 命中 mesh host 条目（forwarded_for=append）；
// - 关键不变式：override_host 只改路由用的 Host 头（proxyReq.Host），X-Forwarded-Host
//   仍由 buildForwardedHeaders 从入站 r.Host 生成/继承 —— 后端最终看到的
//   X-Forwarded-Host 是用户公网域名，不是 mesh 域名。
//
// 覆盖：
// 1. h1 全链路头形态（TestOverrideHostEdgeToMeshChainHeaders）；
// 2. h2 后端下 :authority 携带 override（真 TLS+ALPN 协商 HTTP/2，
//    TestOverrideHostHTTP2AuthorityOnGateToGate）；
// 3. 单跳对照：未配置 override 的 host 不受影响（TestOverrideHostAbsentSingleHopControl）；
// 4. WebSocket 握手 Host 行 / TLS SNI 应用 override（TestOverrideHostWebSocket*）。

const (
	testPublicHost = "app.example.com"            // 用户公网域名（gateA 侧 host）
	testMeshHost   = "mesh-app.node1.example.net" // gateB 的 mesh 域名（override_host 目标）
	testClientIP   = "203.0.113.50"               // 客户端真实 IP（测试用 RemoteAddr 模拟）
)

// gateProxyOptions 汇总 NewProxy 中与 override_host 链路相关的 per-host 参数。
type gateProxyOptions struct {
	backend        string
	trustedProxies []string
	preserveHost   bool
	overrideHost   string
	forwardedFor   string
}

func newGateProxy(t *testing.T, o gateProxyOptions) *Proxy {
	t.Helper()
	return NewProxy(
		[]string{o.backend},
		"/",
		10, 5,
		logger.GetDefaultLogger(),
		nil,
		o.trustedProxies,
		false, // websocketInsecureSkip：wss 测试依赖真实证书校验
		o.preserveHost,
		o.overrideHost,
		"",
		false,
		false,
		false,
		o.forwardedFor,
		defaultWSConfig(),
		UpstreamConfig{},
	)
}

// capturedUpstream 记录链路末端回显后端收到的请求形态。
type capturedUpstream struct {
	Host   string
	Proto  string
	Header http.Header
}

// newCaptureBackend 起一个回显后端（模拟真实业务容器），把收到的 Host/Header
// 经 channel 送回测试侧断言。
func newCaptureBackend(t *testing.T) (*httptest.Server, <-chan capturedUpstream) {
	t.Helper()
	captured := make(chan capturedUpstream, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- capturedUpstream{Host: r.Host, Proto: r.Proto, Header: r.Header.Clone()}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	t.Cleanup(srv.Close)
	return srv, captured
}

// spoofedClientRequest 构造「真实 IP 203.0.113.50 的客户端带伪造转发头打公网域名」
// 的入站请求（伪造 XFF 链 / XFH / XFP / X-Real-IP 都必须被边缘丢弃）。
func spoofedClientRequest(path string) *http.Request {
	req := httptest.NewRequest("GET", "http://"+testPublicHost+path, nil)
	req.RemoteAddr = testClientIP + ":51234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	req.Header.Set("X-Forwarded-Host", "evil.example.net")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Real-IP", "9.9.9.9")
	return req
}

func waitCapture(t *testing.T, ch <-chan capturedUpstream, what string) capturedUpstream {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return capturedUpstream{}
	}
}

// --- 测试 CA / 叶证书（h2 与 wss 链路需要真实 TLS 证书校验） ---

var (
	testLeafCertOnce sync.Once
	testLeafCert     tls.Certificate
	testLeafCertErr  error
)

// backendLeafCert 生成测试用 CA + 叶证书（SAN：localhost、mesh 域名、公网域名、127.0.0.1），
// 并把 CA 写入临时文件经 SSL_CERT_FILE 注入默认根池（gate 的 proxy transport 使用默认
// 根池校验后端证书，无注入点；SSL_CERT_FILE 在进程首次 TLS 握手前设置即生效 —— 本包
// 其余测试均不产生 TLS 握手）。CA/证书进程内只生成一次，跨测试复用同一信任锚。
func backendLeafCert(t *testing.T) tls.Certificate {
	t.Helper()
	testLeafCertOnce.Do(func() {
		caKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			testLeafCertErr = err
			return
		}
		caTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "lite-gate-test-ca"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
		if err != nil {
			testLeafCertErr = err
			return
		}
		caCert, err := x509.ParseCertificate(caDER)
		if err != nil {
			testLeafCertErr = err
			return
		}

		leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			testLeafCertErr = err
			return
		}
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "backend.local"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"localhost", testMeshHost, testPublicHost},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
		if err != nil {
			testLeafCertErr = err
			return
		}
		testLeafCert = tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}

		caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
		dir, err := os.MkdirTemp("", "lite-gate-test-ca")
		if err != nil {
			testLeafCertErr = err
			return
		}
		// 故意不清理：文件需存活到本测试进程内最后一次 TLS 握手
		caPath := filepath.Join(dir, "ca.pem")
		if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
			testLeafCertErr = err
			return
		}
		if err := os.Setenv("SSL_CERT_FILE", caPath); err != nil {
			testLeafCertErr = err
			return
		}
	})
	if testLeafCertErr != nil {
		t.Fatalf("failed to prepare test CA/leaf cert: %v", testLeafCertErr)
	}
	return testLeafCert
}

// --- 场景 1：h1 全链路头形态 ---

// TestOverrideHostEdgeToMeshChainHeaders 进程内串两级 Proxy + 回显后端（全 h1）：
// 客户端(伪造头) → gateA(边缘, override=mesh域名, trusted=空) → gateB(mesh, append,
// trusted 含 gateA 出口 127.0.0.1, preserve host) → 回显后端。
// 断言：Host=mesh域名；XFF=[客户端真实IP, gateA IP]（伪造链被边缘丢弃 + mesh 追加）；
// X-Forwarded-Host=公网域名（override 不污染转发头）；XFP=http（伪造 https 被丢弃）；
// X-Real-IP 不存在；Forwarded/Via 按 PRD 语义重建/逐跳追加。
func TestOverrideHostEdgeToMeshChainHeaders(t *testing.T) {
	echoBackend, echoCh := newCaptureBackend(t)

	// gateB：mesh 域名 host 条目（forwarded_for=append + preserve host + 信任 gateA 出口 IP）
	gateB := newGateProxy(t, gateProxyOptions{
		backend:        echoBackend.URL,
		trustedProxies: []string{"127.0.0.1"},
		preserveHost:   true,
		forwardedFor:   forwardedForAppend,
	})
	gateBFront := httptest.NewServer(http.HandlerFunc(gateB.ServeHTTP))
	t.Cleanup(gateBFront.Close)

	// gateA：公网域名 host（默认边缘语义），override_host = gateB mesh 域名，trusted_proxies 为空
	gateA := newGateProxy(t, gateProxyOptions{
		backend:      gateBFront.URL,
		overrideHost: testMeshHost,
	})

	rec := httptest.NewRecorder()
	gateA.ServeHTTP(rec, spoofedClientRequest("/api/v1/ping"))
	if rec.Code != http.StatusOK {
		t.Fatalf("gateA response status = %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}

	got := waitCapture(t, echoCh, "echo backend capture")

	// Host：override_host 只改路由 Host —— 后端收到 mesh 域名（gateB 按它命中 mesh 条目）
	if got.Host != testMeshHost {
		t.Errorf("upstream Host = %q, want override %q", got.Host, testMeshHost)
	}

	// XFF：边缘单值重建（伪造 1.2.3.4/5.6.7.8 丢弃）→ mesh append 追加 gateA 出口 IP
	if xff := got.Header.Get("X-Forwarded-For"); xff != testClientIP+", 127.0.0.1" {
		t.Errorf("upstream X-Forwarded-For = %q, want %q (client real IP + gateA egress)", xff, testClientIP+", 127.0.0.1")
	}
	if len(got.Header.Values("X-Forwarded-For")) != 1 {
		t.Errorf("upstream X-Forwarded-For lines = %d (%v), want exactly 1", len(got.Header.Values("X-Forwarded-For")), got.Header.Values("X-Forwarded-For"))
	}

	// X-Forwarded-Host：公网域名（从入站 r.Host 生成并由 gateB 继承，绝不是 mesh 域名/伪造值）
	if xfh := got.Header.Get("X-Forwarded-Host"); xfh != testPublicHost {
		t.Errorf("upstream X-Forwarded-Host = %q, want public host %q (override_host must not leak here)", xfh, testPublicHost)
	}

	// XFP：两跳明文 http（客户端伪造的 https 被边缘丢弃，gateB 继承 gateA 重建值）
	if xfp := got.Header.Get("X-Forwarded-Proto"); xfp != "http" {
		t.Errorf("upstream X-Forwarded-Proto = %q, want %q", xfp, "http")
	}
	if xfp := got.Header.Get("X-Forwarded-Port"); xfp != "80" {
		t.Errorf("upstream X-Forwarded-Port = %q, want %q", xfp, "80")
	}

	// X-Real-IP 全链路禁用
	if xr := got.Header.Get("X-Real-IP"); xr != "" {
		t.Errorf("upstream X-Real-IP = %q, want absent", xr)
	}

	// Forwarded：gateB 按解析出的真实客户端 IP 重建（host= 继承公网域名）
	if f := got.Header.Get("Forwarded"); f != "for="+testClientIP+";by=_;proto=http;host="+testPublicHost {
		t.Errorf("upstream Forwarded = %q, want %q", f, "for="+testClientIP+";by=_;proto=http;host="+testPublicHost)
	}

	// Via：两跳逐跳追加
	if via := got.Header.Get("Via"); via != "1.1 lite-gate, 1.1 lite-gate" {
		t.Errorf("upstream Via = %q, want %q", via, "1.1 lite-gate, 1.1 lite-gate")
	}

	// X-Lite-Gate-Forwarded-For：逐跳追加（第二跳为 gateA 出口 RemoteAddr，端口不定）
	if gff := got.Header.Get("X-Lite-Gate-Forwarded-For"); !strings.HasPrefix(gff, testClientIP+":51234, 127.0.0.1:") {
		t.Errorf("upstream X-Lite-Gate-Forwarded-For = %q, want prefix %q", gff, testClientIP+":51234, 127.0.0.1:")
	}
}

// --- 场景 2：h2 后端 :authority 携带 override ---

// TestOverrideHostHTTP2AuthorityOnGateToGate gateA→gateB 走真 TLS+ALPN 协商的 HTTP/2
// （复刻线上 gate→gate 全 h2）。HTTP/2 transport 用 req.Host 生成 :authority、忽略
// Header["Host"]，因此本测试直接证明 override_host 经 proxyReq.Host 在 h2 后端生效：
// gateB 服务端断言 r.ProtoMajor==2（确认真协商成 h2）且 r.Host==mesh 域名（:authority），
// 同时后端侧头形态与 h1 链路一致（XFH 仍是公网域名）。
func TestOverrideHostHTTP2AuthorityOnGateToGate(t *testing.T) {
	leaf := backendLeafCert(t)

	echoBackend, echoCh := newCaptureBackend(t)

	gateB := newGateProxy(t, gateProxyOptions{
		backend:        echoBackend.URL,
		trustedProxies: []string{"127.0.0.1"},
		preserveHost:   true,
		forwardedFor:   forwardedForAppend,
	})

	type gateObservation struct {
		ProtoMajor int
		Host       string
	}
	gateBSeen := make(chan gateObservation, 1)
	gateBFront := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case gateBSeen <- gateObservation{ProtoMajor: r.ProtoMajor, Host: r.Host}:
		default: // 只记录首个请求
		}
		gateB.ServeHTTP(w, r)
	}))
	gateBFront.EnableHTTP2 = true // NextProtos=["h2"]，强制 ALPN 协商 HTTP/2
	gateBFront.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	gateBFront.StartTLS()
	t.Cleanup(gateBFront.Close)

	gateA := newGateProxy(t, gateProxyOptions{
		backend:      gateBFront.URL, // https://127.0.0.1:port（证书含 127.0.0.1 SAN）
		overrideHost: testMeshHost,
	})

	rec := httptest.NewRecorder()
	gateA.ServeHTTP(rec, spoofedClientRequest("/api/v1/ping"))
	if rec.Code != http.StatusOK {
		t.Fatalf("gateA response status = %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}

	var seen gateObservation
	select {
	case seen = <-gateBSeen:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for gateB inbound observation")
	}

	// 前置断言：必须真的协商成 HTTP/2，否则本测试没有覆盖 :authority 通路
	if seen.ProtoMajor != 2 {
		t.Fatalf("gateA→gateB must negotiate HTTP/2 via ALPN, got ProtoMajor=%d", seen.ProtoMajor)
	}
	// h2 :authority = override 的 mesh 域名（h2 服务端把它映射回 r.Host）
	if seen.Host != testMeshHost {
		t.Fatalf("gateB r.Host (:authority) = %q, want override %q — proxyReq.Host 未生效于 h2 transport", seen.Host, testMeshHost)
	}

	got := waitCapture(t, echoCh, "echo backend capture")
	if got.Host != testMeshHost {
		t.Errorf("upstream Host = %q, want override %q (gateB preserves host)", got.Host, testMeshHost)
	}
	if xff := got.Header.Get("X-Forwarded-For"); xff != testClientIP+", 127.0.0.1" {
		t.Errorf("upstream X-Forwarded-For = %q, want %q", xff, testClientIP+", 127.0.0.1")
	}
	if xfh := got.Header.Get("X-Forwarded-Host"); xfh != testPublicHost {
		t.Errorf("upstream X-Forwarded-Host = %q, want public host %q", xfh, testPublicHost)
	}
	if xr := got.Header.Get("X-Real-IP"); xr != "" {
		t.Errorf("upstream X-Real-IP = %q, want absent", xr)
	}
	// Via 第二跳按 h2 入站记录为 2.0
	if via := got.Header.Get("Via"); via != "1.1 lite-gate, 2.0 lite-gate" {
		t.Errorf("upstream Via = %q, want %q", via, "1.1 lite-gate, 2.0 lite-gate")
	}
}

// --- 场景 3：单跳对照（无 override） ---

// TestOverrideHostAbsentSingleHopControl 未配置 override_host 的 host 行为不变：
// Host 头按既有优先级（!preserve → 后端地址 / preserve → 入站 Host），
// XFF 单值重建、XFH=入站 Host、伪造头照删。
func TestOverrideHostAbsentSingleHopControl(t *testing.T) {
	echoBackend, echoCh := newCaptureBackend(t)
	backendHost := strings.TrimPrefix(echoBackend.URL, "http://")

	tests := []struct {
		name         string
		preserveHost bool
		wantHost     string
	}{
		{
			name:         "no override and no preserve rewrites Host to backend address",
			preserveHost: false,
			wantHost:     backendHost,
		},
		{
			name:         "no override with preserve keeps inbound Host",
			preserveHost: true,
			wantHost:     testPublicHost,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newGateProxy(t, gateProxyOptions{
				backend:      echoBackend.URL,
				preserveHost: tt.preserveHost,
			})

			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, spoofedClientRequest("/"))
			if rec.Code != http.StatusOK {
				t.Fatalf("response status = %d, want 200", rec.Code)
			}

			got := waitCapture(t, echoCh, "echo backend capture")
			if got.Host != tt.wantHost {
				t.Errorf("upstream Host = %q, want %q", got.Host, tt.wantHost)
			}
			if xff := got.Header.Get("X-Forwarded-For"); xff != testClientIP {
				t.Errorf("upstream X-Forwarded-For = %q, want single %q (spoofed chain dropped)", xff, testClientIP)
			}
			if xfh := got.Header.Get("X-Forwarded-Host"); xfh != testPublicHost {
				t.Errorf("upstream X-Forwarded-Host = %q, want inbound %q", xfh, testPublicHost)
			}
			if xr := got.Header.Get("X-Real-IP"); xr != "" {
				t.Errorf("upstream X-Real-IP = %q, want absent", xr)
			}
		})
	}
}

// --- 场景 4：WebSocket 握手的 Host 行与 TLS SNI ---

// wsUpgradeRequest 构造公网域名上的 WS 升级请求。
func wsUpgradeRequest() *http.Request {
	req := httptest.NewRequest("GET", "http://"+testPublicHost+"/ws", nil)
	req.RemoteAddr = testClientIP + ":41000"
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Host", "evil.example.net")
	req.Header.Set("X-Real-IP", "9.9.9.9")
	return req
}

// newWSHijackBackend 起一个完成 101 握手的 WS 后端，并捕获收到的 Host 行与请求头
// （注意 HTTP/1.1 服务端的 Host 在 r.Host，不在 r.Header）。
func newWSHijackBackend(t *testing.T) (*httptest.Server, <-chan capturedUpstream) {
	t.Helper()
	captured := make(chan capturedUpstream, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- capturedUpstream{Host: r.Host, Header: r.Header.Clone()}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		accept := generateWebSocketAcceptKey(r.Header.Get("Sec-WebSocket-Key"))
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	}))
	t.Cleanup(srv.Close)
	return srv, captured
}

// TestOverrideHostWebSocketHandshakeHostLine WS 手写握手请求的 Host 行应用 override_host，
// 转发头仍按入站生成：XFH=公网域名、XFF=客户端真实 IP 单值（边缘语义）、X-Real-IP 不出现。
func TestOverrideHostWebSocketHandshakeHostLine(t *testing.T) {
	backend, captured := newWSHijackBackend(t)

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}

	p := newGateProxy(t, gateProxyOptions{
		backend:      backend.URL,
		overrideHost: testMeshHost,
	})

	conn, _, resp, err := p.handleWebSocketUpgrade(wsUpgradeRequest(), backendURL, "trace-ws-ovr")
	if err != nil {
		t.Fatalf("handleWebSocketUpgrade failed: %v", err)
	}
	defer conn.Close()
	defer resp.Body.Close()

	select {
	case got := <-captured:
		if got.Host != testMeshHost {
			t.Errorf("WS handshake Host line = %q, want override %q", got.Host, testMeshHost)
		}
		if xfh := got.Header.Get("X-Forwarded-Host"); xfh != testPublicHost {
			t.Errorf("WS handshake X-Forwarded-Host = %q, want inbound public %q (not override)", xfh, testPublicHost)
		}
		if xff := got.Header.Get("X-Forwarded-For"); xff != testClientIP {
			t.Errorf("WS handshake X-Forwarded-For = %q, want single %q", xff, testClientIP)
		}
		if xr := got.Header.Get("X-Real-IP"); xr != "" {
			t.Errorf("WS handshake X-Real-IP = %q, want absent", xr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for WS backend to capture handshake headers")
	}
}

// TestOverrideHostWebSocketTLSSNIFollowsOverride wss 握手的 TLS SNI 跟随 override_host：
// 拨号地址为 backend（localhost），配置 override 后 SNI 与 Host 行均为 mesh 域名，
// 且证书按 mesh 域名校验通过（websocketInsecureSkip=false）；未配置 override 的
// 对照握手 SNI 仍为 backend 主机名 —— 锁定两条分支。
func TestOverrideHostWebSocketTLSSNIFollowsOverride(t *testing.T) {
	leaf := backendLeafCert(t)

	captured := make(chan capturedUpstream, 2)
	sniCh := make(chan string, 2)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- capturedUpstream{Host: r.Host, Header: r.Header.Clone()}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		accept := generateWebSocketAcceptKey(r.Header.Get("Sec-WebSocket-Key"))
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{leaf},
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case sniCh <- hi.ServerName:
			default:
			}
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// 拨号用 DNS 名 localhost（解析到 127.0.0.1），保证 SNI 不可能来自 IP 拨号地址
	backendTLSURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	backendURL, err := url.Parse(backendTLSURL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}

	// 对照：未配置 override —— SNI 与 Host 行均为 backend 主机名，证书按 localhost 校验
	control := newGateProxy(t, gateProxyOptions{backend: backendTLSURL})
	conn, _, resp, err := control.handleWebSocketUpgrade(wsUpgradeRequest(), backendURL, "trace-ws-ctrl")
	if err != nil {
		t.Fatalf("control wss handshake failed: %v", err)
	}
	conn.Close()
	resp.Body.Close()

	select {
	case sni := <-sniCh:
		if sni != "localhost" {
			t.Errorf("control handshake SNI = %q, want backend hostname %q", sni, "localhost")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for control ClientHello")
	}
	select {
	case h := <-captured:
		if h.Host != backendURL.Host {
			t.Errorf("control handshake Host line = %q, want backend %q", h.Host, backendURL.Host)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for control handshake headers")
	}

	// override：SNI 与 Host 行均为 mesh 域名（证书含 mesh SAN，非跳过校验下握手成功）
	overridden := newGateProxy(t, gateProxyOptions{
		backend:      backendTLSURL,
		overrideHost: testMeshHost,
	})
	conn, _, resp, err = overridden.handleWebSocketUpgrade(wsUpgradeRequest(), backendURL, "trace-ws-ovr")
	if err != nil {
		t.Fatalf("override wss handshake failed (SNI/cert validation against override host?): %v", err)
	}
	conn.Close()
	resp.Body.Close()

	select {
	case sni := <-sniCh:
		if sni != testMeshHost {
			t.Errorf("override handshake SNI = %q, want override %q", sni, testMeshHost)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for override ClientHello")
	}
	select {
	case h := <-captured:
		if h.Host != testMeshHost {
			t.Errorf("override handshake Host line = %q, want %q", h.Host, testMeshHost)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for override handshake headers")
	}
}
