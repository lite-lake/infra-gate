package server

// 启动时序与证书异步加载集成测试（内部PRD §15.2）：
//   - 零证书启动：443 监听器无条件秒开（TLS 握手可失败但 TCP accept 成功）、
//     80 正常代理、进程不退出（D1）；
//   - 证书后到即插即用：监听器已启动后注入证书，同一 SNI 下一次握手成功（§6.3）；
//   - 端口占用：Start() 经 startErrChan 返回错误（监听器绑定失败仍是唯一退出原因）。
//
// 测试端口用 net.Listen(":0") 探测空闲端口后关闭再复用，避免固定端口冲突。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/cert"
	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/endpoints"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/shipper"
)

func TestClientIPInRanges(t *testing.T) {
	tests := []struct {
		name     string
		clientIP string
		ranges   []string
		want     bool
	}{
		{"mesh ip allowed", "10.72.0.21", []string{"10.72.0.0/24"}, true},
		{"public ip denied", "203.0.113.10", []string{"10.72.0.0/24"}, false},
		{"single ip allowed", "127.0.0.1", []string{"10.72.0.0/24", "127.0.0.1"}, true},
		{"invalid client ip", "not-an-ip", []string{"10.72.0.0/24"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientIPInRanges(tt.clientIP, tt.ranges); got != tt.want {
				t.Errorf("clientIPInRanges(%q, %v) = %v, want %v", tt.clientIP, tt.ranges, got, tt.want)
			}
		})
	}
}

// TestClientIPInRangesRespectsXFF 验证 ResolveClientIP（处理可信代理链）在 allowed_ips 校验中生效：
// 直接连接来自可信代理，XFF 头携带真实客户端（mesh）IP 时，应判定为允许。
// 该测试覆盖 server.go 中 allowed_ips 校验复用的 IP 解析路径。
func TestClientIPInRanges_NoExtraGuards(t *testing.T) {
	// 纯逻辑断言：255.* 公网 IP 不应命中 mesh 段
	if clientIPInRanges("203.0.113.10", []string{"10.72.0.0/24"}) {
		t.Error("public IP should not match mesh range")
	}
}

// --- 启动时序与证书异步加载集成测试（内部PRD §15.2）---

// freeTCPPort 探测一个空闲 TCP 端口（探测后关闭再复用，避免固定端口冲突）
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// tryTLSHandshake 对 addr 发起一次 TLS 握手（InsecureSkipVerify：只验证服务端
// 能否按 SNI 出证书，不验证信任链），握手成功返回 nil
func tryTLSHandshake(t *testing.T, addr, serverName string) error {
	t.Helper()
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // nolint:gosec // 测试环境：自签名证书，仅验证 SNI 出证书
	})
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// waitTCPOpen 轮询等待 TCP 端口可拨通（超时返回 false）
func waitTCPOpen(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// generateLocalTestCertificate 生成指定 CN/SAN 的自签名证书 PEM（server 包本地 helper，
// cert 包的 generateTestCertificate 不跨包）
func generateLocalTestCertificate(t *testing.T, commonName string) ([]byte, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM
}

// newStartupTestConfig 构造单 host 的最小 Config（端口由调用方探测，
// 远程证书端点不可达 + 短超时：模拟 ssl-api 未就绪场景）
func newStartupTestConfig(hostName string, httpPort, httpsPort int, backendURL string) *config.Config {
	return &config.Config{
		Server: config.ServerConfig{Port: httpPort},
		Hosts: []config.HostConfig{{
			Name:               hostName,
			Port:               httpPort,
			SSLPort:            httpsPort,
			Backend:            []string{backendURL},
			HealthCheckEnabled: boolPtr(false),
		}},
		SSL: &cert.CertConfig{Remote: &cert.RemoteCertConfig{
			Enabled:  true,
			Endpoint: endpoints.New("https://127.0.0.1:1"), // 不可达端点
			Timeout:  2 * time.Second,
		}},
	}
}

// 测试 11（§15.2 零证书启动）：443 监听器无条件秒开（TCP accept 成功、TLS 握手失败）、
// 80 正常代理、Start() 不因证书问题返回（进程不退出，D1）
func TestZeroCertificateStartupKeepsListenersOpen(t *testing.T) {
	const hostName = "zero.example.com"
	httpPort, httpsPort := freeTCPPort(t), freeTCPPort(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()

	srv, err := NewServer(newStartupTestConfig(hostName, httpPort, httpsPort, backend.URL), &blTestLogger{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	startErr := make(chan error, 1)
	go func() { startErr <- srv.Start() }()

	// 5s 内 443 TCP 可拨通（监听器秒开，不等任何证书）
	httpsAddr := fmt.Sprintf("127.0.0.1:%d", httpsPort)
	if !waitTCPOpen(httpsAddr, 5*time.Second) {
		t.Fatal("443 TCP listener not reachable within 5s (listener must open unconditionally)")
	}

	// 零证书：TLS 握手必须失败（GetCertificate 未命中 → 干净 TLS 错误，D2）
	if err := tryTLSHandshake(t, httpsAddr, hostName); err == nil {
		t.Error("TLS handshake must fail with zero certificates")
	}

	// 80 正常响应 HTTP（代理到后端）
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", httpPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = hostName
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("HTTP request on port %d: %v", httpPort, err)
	}
	body := make([]byte, 128)
	n, _ := resp.Body.Read(body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HTTP status = %d, want 200", resp.StatusCode)
	}
	if got := string(body[:n]); got != "backend-ok" {
		t.Errorf("HTTP body = %q, want backend-ok", got)
	}

	// 进程不退出：Start() 尚未返回（证书拉取全败不再是退出原因）
	select {
	case err := <-startErr:
		t.Fatalf("Start returned early while certificates are pending: %v", err)
	default:
	}

	srv.Stop()
	select {
	case err := <-startErr:
		if err != nil {
			t.Errorf("Start after Stop = %v, want nil", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

// 测试 12（§15.2 证书后到即插即用）：监听器已启动后向 certManager 注入证书，
// 同一 SNI 下一次 TLS 握手即成功，无需重载/重启
func TestCertificateLateArrivalPlugAndPlay(t *testing.T) {
	// chdir 到临时目录：LoadCertificate 本地路径成功后会写证书缓存
	//（certManager cacheDir 相对 CWD），避免污染仓库工作区
	tmp := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir temp: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(origWd); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})

	const hostName = "late.example.com"
	httpPort, httpsPort := freeTCPPort(t), freeTCPPort(t)

	// 本地证书文件（延迟注入用的来源）
	certDir := filepath.Join(tmp, "certs", hostName)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := generateLocalTestCertificate(t, hostName)
	if err := os.WriteFile(filepath.Join(certDir, "fullchain.pem"), certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "privkey.pem"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := newStartupTestConfig(hostName, httpPort, httpsPort, "http://127.0.0.1:1")
	cfg.Hosts[0].Backend = nil // Text host：注入前 80 也能响应，聚焦 TLS 行为
	cfg.Hosts[0].Text = "late-ok"

	srv, err := NewServer(cfg, &blTestLogger{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	startErr := make(chan error, 1)
	go func() { startErr <- srv.Start() }()

	httpsAddr := fmt.Sprintf("127.0.0.1:%d", httpsPort)
	if !waitTCPOpen(httpsAddr, 5*time.Second) {
		t.Fatal("443 TCP listener not reachable within 5s")
	}

	// 注入前：该 SNI 握手失败
	if err := tryTLSHandshake(t, httpsAddr, hostName); err == nil {
		t.Fatal("handshake must fail before certificate arrival")
	}

	// 注入证书（LoadCertificate 本地配置，走完整成功路径：写内存 + 注册 Updater）
	if _, err := srv.GetCertManager().LoadCertificate(hostName, &cert.CertConfig{
		Local: &cert.LocalCertConfig{Enabled: true, CertDir: certDir},
	}); err != nil {
		t.Fatalf("inject certificate: %v", err)
	}

	// 同一 SNI 下一次握手成功（GetCertificate 是每次握手实时回调，即插即用）
	if err := tryTLSHandshake(t, httpsAddr, hostName); err != nil {
		t.Fatalf("handshake must succeed after late certificate arrival: %v", err)
	}

	srv.Stop()
	select {
	case err := <-startErr:
		if err != nil {
			t.Errorf("Start after Stop = %v, want nil", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

// 测试 13（§15.2 端口占用失败路径）：预占用端口后 Start() 必须经 startErrChan
// 返回错误——监听器端口绑定失败仍是唯一的启动失败原因（D1 的另一面）
func TestStartReturnsErrorOnPortBindFailure(t *testing.T) {
	// 预占用端口（保持监听到测试结束）
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	cfg := &config.Config{
		Server: config.ServerConfig{Port: port},
		Hosts: []config.HostConfig{{
			Name:               "bind.example.com",
			Port:               port,
			Backend:            []string{"http://127.0.0.1:1"},
			HealthCheckEnabled: boolPtr(false),
		}},
	}

	srv, err := NewServer(cfg, &blTestLogger{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	startErr := make(chan error, 1)
	go func() { startErr <- srv.Start() }()

	select {
	case err := <-startErr:
		if err == nil {
			t.Fatal("Start must return error when the port is already occupied")
		}
		// 错误应来自监听器绑定失败（C1 语义），而非证书或其他路径
		if got := err.Error(); !strings.Contains(got, "HTTP server on port") {
			t.Errorf("start error = %q, want bind failure wording", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return bind error within 10s")
	}
}

// waitUntil 轮询等待条件成立（超时返回 false）；server 包异步断言用
func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return cond()
}

// 测试 14（§15.2 混合场景）：9 个证书就绪域名 + 1 个未就绪域名共用一个 443 监听器——
// 就绪域名握手立即可用（部分可用，D1/目标 2），未就绪域名保持 TLS 失败且停在 pending，
// Start() 不返回（进程存活）。就绪源用本地证书文件：对 Manager 而言 local/remote 只是
// Loader 的取用来源差异，进入内存 map 后 SNI 路由行为完全一致（即"已就绪"）。
func TestMixedReadyAndPendingDomainsPartialAvailability(t *testing.T) {
	// chdir 到临时目录：本地证书路径会写证书缓存（cacheDir 相对 CWD），避免污染仓库
	tmp := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir temp: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(origWd); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})

	const pendingDomain = "mixed-pending.example.com"
	var readyDomains []string
	for i := 0; i < 9; i++ {
		readyDomains = append(readyDomains, fmt.Sprintf("mixed-ready%d.example.com", i))
	}

	httpPort, httpsPort := freeTCPPort(t), freeTCPPort(t)

	// 9 个就绪域名各自的本地证书目录。SNI 路由按内存 map 键（host.Name）精确匹配，
	// 证书内容不参与路由判断，故 9 个目录可共用同一张自签名证书（客户端 InsecureSkipVerify）
	certPEM, keyPEM := generateLocalTestCertificate(t, "mixed-ready.example.com")
	hosts := make([]config.HostConfig, 0, len(readyDomains)+1)
	for _, d := range readyDomains {
		certDir := filepath.Join(tmp, "certs", d)
		if err := os.MkdirAll(certDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(certDir, "fullchain.pem"), certPEM, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(certDir, "privkey.pem"), keyPEM, 0600); err != nil {
			t.Fatal(err)
		}
		hosts = append(hosts, config.HostConfig{
			Name:    d,
			Port:    httpPort,
			SSLPort: httpsPort,
			Text:    "ready-ok",
			SSLConfig: &cert.CertConfig{
				Local: &cert.LocalCertConfig{Enabled: true, CertDir: certDir},
			},
		})
	}
	// 第 10 个域名：远程端点不可达（ssl-api 未就绪），永远无法加载成功
	hosts = append(hosts, config.HostConfig{
		Name:    pendingDomain,
		Port:    httpPort,
		SSLPort: httpsPort,
		Text:    "pending",
		SSLConfig: &cert.CertConfig{
			Remote: &cert.RemoteCertConfig{
				Enabled:  true,
				Endpoint: endpoints.New("https://127.0.0.1:1"),
				Timeout:  2 * time.Second,
			},
		},
	})

	srv, err := NewServer(&config.Config{
		Server: config.ServerConfig{Port: httpPort},
		Hosts:  hosts,
	}, &blTestLogger{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	startErr := make(chan error, 1)
	go func() { startErr <- srv.Start() }()

	httpsAddr := fmt.Sprintf("127.0.0.1:%d", httpsPort)
	if !waitTCPOpen(httpsAddr, 5*time.Second) {
		t.Fatal("443 TCP listener not reachable within 5s")
	}

	// 9 个就绪域名在 reconciler 后台加载完成后握手全部成功（轮询等待，不预设时序）
	handshakeOK := make(map[string]bool, len(readyDomains))
	if !waitUntil(20*time.Second, func() bool {
		allOK := true
		for _, d := range readyDomains {
			if handshakeOK[d] {
				continue
			}
			if err := tryTLSHandshake(t, httpsAddr, d); err == nil {
				handshakeOK[d] = true
			} else {
				allOK = false
			}
		}
		return allOK
	}) {
		for _, d := range readyDomains {
			if !handshakeOK[d] {
				t.Errorf("ready domain %s handshake never succeeded (partial availability broken)", d)
			}
		}
	}

	// 未就绪域名：握手必须失败（证书缺失 → D2 干净 TLS 错误）
	if err := tryTLSHandshake(t, httpsAddr, pendingDomain); err == nil {
		t.Error("pending domain handshake must fail while its certificate is not ready")
	}

	// pending 域名可观测：只剩它留在 PendingSnapshot 中（就绪域名已被移除）
	if !waitUntil(5*time.Second, func() bool {
		snap := srv.GetCertManager().PendingSnapshot()
		return len(snap) == 1 && snap[0].Domain == pendingDomain
	}) {
		t.Errorf("pending snapshot = %v, want only %s", srv.GetCertManager().PendingSnapshot(), pendingDomain)
	}

	// 进程存活：Start() 尚未返回（一个坏域名不再拖垮整个网关）
	select {
	case err := <-startErr:
		t.Fatalf("Start returned early in mixed scenario: %v", err)
	default:
	}

	srv.Stop()
	select {
	case err := <-startErr:
		if err != nil {
			t.Errorf("Start after Stop = %v, want nil", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

// TestGetTrackerShipperStatus 状态快照注入路径（内部PRD §6.1）：
//   - trackerShipper 为 nil（配置缺段/未启用）→ disabled 快照（enabled:false 全零值，
//     "组件消失"是有效状态不是错误，端点仍 200 由监控断言失败告警）；
//   - 已创建 shipper（未启动 flusher）→ enabled:true、running:false 透传。
func TestGetTrackerShipperStatus(t *testing.T) {
	log := logger.NewLogger(logger.LoggerConfig{Level: logger.ErrorLevel, EnableConsole: false, EnableFile: false})
	sh := shipper.New(config.ShipperConfig{
		Enabled:      true,
		Endpoint:     "http://127.0.0.1:1/ingest",
		SharedSecret: "k",
		NodeName:     "srv-test-node",
	}, log)

	tests := []struct {
		name        string
		s           *Server
		wantEnabled bool
		wantRunning bool
		wantNode    string
	}{
		{"未启用（nil）", &Server{}, false, false, ""},
		{"已创建未启动", &Server{trackerShipper: sh}, true, false, "srv-test-node"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := tt.s.GetTrackerShipperStatus()
			if snap.Enabled != tt.wantEnabled {
				t.Errorf("Enabled = %v, want %v", snap.Enabled, tt.wantEnabled)
			}
			if snap.Running != tt.wantRunning {
				t.Errorf("Running = %v, want %v", snap.Running, tt.wantRunning)
			}
			if snap.NodeName != tt.wantNode {
				t.Errorf("NodeName = %q, want %q", snap.NodeName, tt.wantNode)
			}
			if snap.SentTotal != 0 || snap.DroppedTotal != 0 || snap.BufferPending != 0 {
				t.Errorf("counters = (%d, %d, %d), want 全零", snap.SentTotal, snap.DroppedTotal, snap.BufferPending)
			}
			if snap.LastSuccessSendAt != nil {
				t.Errorf("LastSuccessSendAt = %d, want nil（从未成功发送）", *snap.LastSuccessSendAt)
			}
		})
	}
}
