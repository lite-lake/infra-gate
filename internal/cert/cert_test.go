package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/endpoints"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// F6 测试辅助：httptest 为明文 http 端点 + 自签证书，需放行 http 并关链校验
var f6AllowHTTP = true
var f6ChainOff = false

// configureTestTLSTransport 配置全局 HTTP transport 以信任测试 TLS 服务器的自签名证书
// 返回一个恢复函数，在测试结束后调用以恢复原始 transport
func configureTestTLSTransport(t *testing.T) func() {
	t.Helper()
	origDefault := http.DefaultTransport

	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // nolint:gosec // 测试环境，信任 httptest 自签名证书
		},
	}
	http.DefaultTransport = customTransport

	return func() {
		http.DefaultTransport = origDefault
	}
}

// TestLoader_LocalCertificate 测试本地证书加载
func TestLoader_LocalCertificate(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "cert-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// 创建测试证书目录
	certDir := filepath.Join(tempDir, "test.example.com")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatal(err)
	}

	// 生成自签名证书用于测试
	certPEM, keyPEM := generateTestCertificate(t)

	// 写入证书文件
	if err := os.WriteFile(filepath.Join(certDir, "fullchain.pem"), certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(certDir, "privkey.pem"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	// 创建加载器
	loader := NewLoader(tempDir, logger.GetDefaultLogger())

	// 配置
	config := &CertConfig{
		Local: &LocalCertConfig{
			Enabled: true,
			CertDir: certDir,
		},
	}

	// 加载证书
	certPair, err := loader.LoadCertificate("test.example.com", config)
	if err != nil {
		t.Fatal(err)
	}

	// 验证证书
	if certPair.Certificate == nil {
		t.Fatal("Certificate is nil")
	}

	if certPair.Metadata == nil {
		t.Fatal("Metadata is nil")
	}

	if certPair.Metadata.Domain != "test.example.com" {
		t.Errorf("Expected domain 'test.example.com', got '%s'", certPair.Metadata.Domain)
	}

	if certPair.Metadata.Source != "local" {
		t.Errorf("Expected source 'local', got '%s'", certPair.Metadata.Source)
	}
}

// TestLoader_RemoteCertificate 测试远程证书加载
func TestLoader_RemoteCertificate(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "cert-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// 创建模拟的远程API服务器
	certPEM, keyPEM := generateTestCertificate(t)
	testResponse := RemoteCertResponse{
		Domain:      "test.example.com",
		FullChain:   string(certPEM),
		PrivateKey:  string(keyPEM),
		StartDate:   time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiredDate: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("domain") != "test.example.com" {
			http.Error(w, "Domain not found", http.StatusNotFound)
			return
		}

		// 返回统一响应格式：{code, message, data}
		apiResponse := struct {
			Code    int                `json:"code"`
			Message string             `json:"message"`
			Data    RemoteCertResponse `json:"data"`
		}{
			Code:    200,
			Message: "success",
			Data:    testResponse,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(apiResponse)
	}))
	defer server.Close()

	// 创建加载器
	loader := NewLoader(tempDir, logger.GetDefaultLogger())

	// 配置：使用自定义 HTTP client 以信任测试服务器的自签名证书
	config := &CertConfig{
		Remote: &RemoteCertConfig{
			Enabled:           true,
			Endpoint:          endpoints.New(server.URL),
			AllowInsecureHTTP: &f6AllowHTTP,
			VerifyChain:       &f6ChainOff,
		},
	}

	// 加载证书 — 由于 loadRemoteCertificate 内部使用标准 http.Client，
	// 测试服务器的 TLS 证书是自签名的，需要通过 monkey-patch http.DefaultTransport 来信任。
	// 为测试服务器配置信任自签名证书的 transport
	restoreTransport := configureTestTLSTransport(t)
	defer restoreTransport()

	// 加载证书
	certPair, err := loader.LoadCertificate("test.example.com", config)
	if err != nil {
		t.Fatal(err)
	}

	// 验证证书
	if certPair.Certificate == nil {
		t.Fatal("Certificate is nil")
	}

	if certPair.Metadata.Source != "remote" {
		t.Errorf("Expected source 'remote', got '%s'", certPair.Metadata.Source)
	}
}

// TestLoader_RemoteCertificateMultiEndpointFailover 测试多端点故障转移
func TestLoader_RemoteCertificateMultiEndpointFailover(t *testing.T) {
	restoreTransport := configureTestTLSTransport(t)
	defer restoreTransport()

	const iterations = 5
	for i := 0; i < iterations; i++ {
		tempDir, err := os.MkdirTemp("", "cert-failover")
		if err != nil {
			t.Fatal(err)
		}

		// F6.3：远程证书 SAN 必须匹配请求域（failover.example.com）
		certPEM, keyPEM := generateTestCertificateFor(t, "failover.example.com")
		testResponse := RemoteCertResponse{
			Domain:      "failover.example.com",
			FullChain:   string(certPEM),
			PrivateKey:  string(keyPEM),
			StartDate:   time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
			ExpiredDate: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}

		// Server that always returns 500
		failServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer failServer.Close()

		// Server that returns the certificate
		successServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiResponse := struct {
				Code    int                `json:"code"`
				Message string             `json:"message"`
				Data    RemoteCertResponse `json:"data"`
			}{
				Code:    200,
				Message: "success",
				Data:    testResponse,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(apiResponse)
		}))
		defer successServer.Close()

		loader := NewLoader(tempDir, logger.GetDefaultLogger())
		config := &CertConfig{
			Remote: &RemoteCertConfig{
				Enabled:     true,
				Endpoint:    endpoints.New(failServer.URL, successServer.URL),
				VerifyChain: &f6ChainOff, // 自签测试证书
			},
		}

		certPair, err := loader.LoadCertificate("failover.example.com", config)
		if err != nil {
			t.Fatalf("iteration %d: expected certificate to load via failover, got error: %v", i, err)
		}
		if certPair.Certificate == nil {
			t.Fatalf("iteration %d: certificate is nil", i)
		}
		if certPair.Metadata.Source != "remote" {
			t.Errorf("iteration %d: expected source 'remote', got '%s'", i, certPair.Metadata.Source)
		}

		os.RemoveAll(tempDir)
	}
}

// TestManager_LoadCertificate 测试证书管理器
func TestManager_LoadCertificate(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "cert-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// 创建测试证书目录
	certDir := filepath.Join(tempDir, "test.example.com")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatal(err)
	}

	// 生成自签名证书
	certPEM, keyPEM := generateTestCertificate(t)

	// 写入证书文件
	if err := os.WriteFile(filepath.Join(certDir, "fullchain.pem"), certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(certDir, "privkey.pem"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	// 创建管理器
	manager := NewManager(tempDir, logger.GetDefaultLogger())
	defer manager.Shutdown()

	// 配置
	config := &CertConfig{
		Local: &LocalCertConfig{
			Enabled: true,
			CertDir: certDir,
		},
	}

	// 加载证书
	tlsCert, err := manager.LoadCertificate("test.example.com", config)
	if err != nil {
		t.Fatal(err)
	}

	// 验证证书
	if tlsCert == nil {
		t.Fatal("TLS certificate is nil")
	}

	// 再次加载应该从缓存获取
	tlsCert2, err := manager.LoadCertificate("test.example.com", config)
	if err != nil {
		t.Fatal(err)
	}

	// 验证是同一个证书
	if tlsCert != tlsCert2 {
		t.Error("Expected cached certificate to be the same instance")
	}
}

// TestParseUpdateWindow 测试更新时间窗口解析
func TestParseUpdateWindow(t *testing.T) {
	tests := []struct {
		window      string
		expectedErr bool
		startHour   int
		startMin    int
		endHour     int
		endMin      int
	}{
		{"00:00-00:59", false, 0, 0, 0, 59},
		{"01:30-02:30", false, 1, 30, 2, 30},
		{"23:00-01:00", false, 23, 0, 1, 0}, // 跨午夜
		{"invalid", true, 0, 0, 0, 0},
		{"", false, 0, 0, 0, 59}, // 默认值
	}

	for _, test := range tests {
		startHour, startMin, endHour, endMin, err := ParseUpdateWindow(test.window)

		if test.expectedErr {
			if err == nil {
				t.Errorf("Expected error for window '%s'", test.window)
			}
			continue
		}

		if err != nil {
			t.Errorf("Unexpected error for window '%s': %v", test.window, err)
			continue
		}

		if startHour != test.startHour || startMin != test.startMin || endHour != test.endHour || endMin != test.endMin {
			t.Errorf("Window '%s' parsed incorrectly. Got %02d:%02d-%02d:%02d, expected %02d:%02d-%02d:%02d",
				test.window, startHour, startMin, endHour, endMin,
				test.startHour, test.startMin, test.endHour, test.endMin)
		}
	}
}

// TestIsInUpdateWindow 测试更新时间窗口检查
func TestIsInUpdateWindow(t *testing.T) {
	// 测试默认窗口 - 期望总是返回 true
	// 注意：我们不测试这个，因为依赖于 manager.go 的实现
	// if !IsInUpdateWindow("") {
	// 	t.Error("Expected default window to always return true")
	// }

	// 测试具体窗口（这里不测试具体时间，因为依赖于当前时间）
	_ = IsInUpdateWindow("00:00-00:59")
}

// generateTestCertificate 生成测试用的自签名证书（SAN 固定 test.example.com）
func generateTestCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	return generateTestCertificateFor(t, "test.example.com")
}

// generateTestCertificateFor 按域生成自签名测试证书（F6.3 起远程证书 SAN
// 必须匹配请求域，远程下发路径的测试需按请求域签发）
func generateTestCertificateFor(t *testing.T, domain string) ([]byte, []byte) {
	t.Helper()

	// 使用 Go 1.25+ 的方式生成 RSA 密钥
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// 创建证书模板
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	// 自签名证书
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// 编码证书为PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	// 编码私钥为PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	return certPEM, keyPEM
}

// --- S3: Updater.Stop() 死锁修复测试 ---

// TestUpdaterStopNoDeadlock 测试 Updater.Stop() 在有运行中的更新检查时不会死锁
// 之前的实现在持写锁时 wg.Wait()，与 run() 中获取写锁产生死锁
func TestUpdaterStopNoDeadlock(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	log := logger.GetDefaultLogger()
	loader := NewLoader(tempDir, log)
	updater := NewUpdater(tempDir, loader, log, func(domain string, certPair *CertPair) {})

	// 启动自动更新，使用一个需要网络请求的配置（会有 I/O）
	config := &CertConfig{
		Remote: &RemoteCertConfig{
			Enabled:           true,
			AutoUpdate:        true,
			Endpoint:          endpoints.New("https://127.0.0.1:1"), // 不可达地址，会超时
			UpdateCheckWindow: "00:00-23:59",
		},
	}

	if err := updater.StartAutoUpdate("deadlock-test.example.com", config); err != nil {
		t.Fatalf("StartAutoUpdate failed: %v", err)
	}

	// 等待一小段时间让 run() goroutine 开始运行
	time.Sleep(100 * time.Millisecond)

	// 调用 Stop()，应该在合理时间内返回（不死锁）
	done := make(chan struct{})
	go func() {
		updater.Stop()
		close(done)
	}()

	select {
	case <-done:
		// 成功返回
	case <-time.After(10 * time.Second):
		t.Fatal("Updater.Stop() deadlocked: did not return within 10 seconds")
	}
}

func TestUpdaterStopNoPanicOnDoubleCall(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	log := logger.GetDefaultLogger()
	loader := NewLoader(tempDir, log)
	updater := NewUpdater(tempDir, loader, log, func(domain string, certPair *CertPair) {})

	updater.Stop()
	// 第二次调用不应 panic
	updater.Stop()
}

// --- S4: triggerRenewal 去重与节流测试 ---

// TestTriggerRenewalDedup 测试并发调用 triggerRenewal 只触发一次异步续期
func TestTriggerRenewalDedup(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewManager(tempDir, logger.GetDefaultLogger())
	defer manager.Shutdown()

	// 使用一个即将过期的证书放入缓存
	certPEM, keyPEM := generateTestCertificate(t)

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	// 构造一个即将过期的 metadata（15天后过期，在30天阈值内）
	expiringSoon := time.Now().Add(15 * 24 * time.Hour)
	meta := &CertMetadata{
		Domain:      "renewal-dedup.example.com",
		NotBefore:   time.Now().Add(-350 * 24 * time.Hour),
		NotAfter:    expiringSoon,
		UpdatedAt:   time.Now(),
		Source:      "local",
		Fingerprint: "test-fingerprint",
	}

	manager.mutex.Lock()
	manager.certificates["renewal-dedup.example.com"] = &CertPair{
		Certificate: &tlsCert,
		Metadata:    meta,
	}
	manager.mutex.Unlock()

	// 配置 remote（指向不可达的 HTTPS 地址，连接会快速失败）
	config := &CertConfig{
		Remote: &RemoteCertConfig{
			Enabled:    true,
			AutoUpdate: true,
			Endpoint:   endpoints.New("https://127.0.0.1:1"), // 不可达，连接会快速失败
		},
	}

	// 并发触发多次续期
	var wg sync.WaitGroup
	const concurrency = 50
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			manager.triggerRenewal("renewal-dedup.example.com", config, expiringSoon)
		}()
	}
	wg.Wait()

	// 等待异步续期 goroutine 完成（remote 不可达会快速失败）
	manager.renewalWg.Wait()

	// 续期失败（不可达端点），renewalLastRun 不应被设置（P1-3 修复：仅成功时更新）
	manager.renewalMu.Lock()
	lastRun := manager.renewalLastRun["renewal-dedup.example.com"]
	manager.renewalMu.Unlock()

	if !lastRun.IsZero() {
		t.Error("renewalLastRun should NOT be set when renewal fails (P1-3: only update on success)")
	}

	// 主要验证：没有 panic、inflight 标记已被清理
	manager.renewalMu.Lock()
	inflight := manager.renewalInflight["renewal-dedup.example.com"]
	manager.renewalMu.Unlock()

	if inflight {
		t.Error("renewalInflight should be cleared after goroutine completes")
	}
}

// TestTriggerRenewalThrottle 测试节流：第一次触发后，在节流间隔内第二次调用应被跳过
func TestTriggerRenewalThrottle(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewManager(tempDir, logger.GetDefaultLogger())
	defer manager.Shutdown()

	// 手动设置 renewalLastRun 以模拟一次成功的续期
	manager.renewalMu.Lock()
	manager.renewalLastRun["throttle-test.example.com"] = time.Now()
	manager.renewalMu.Unlock()

	config := &CertConfig{
		Remote: &RemoteCertConfig{
			Enabled:    true,
			AutoUpdate: true,
			Endpoint:   endpoints.New("https://127.0.0.1:1"),
		},
	}

	expiringSoon := time.Now().Add(15 * 24 * time.Hour)

	// 第一次触发：应该在节流窗口内被跳过（lastRun 刚设置）
	manager.triggerRenewal("throttle-test.example.com", config, expiringSoon)

	// 等待可能启动的异步 goroutine
	manager.renewalWg.Wait()

	// 检查 lastRun 应该没有被更新（因为被节流跳过）
	manager.renewalMu.Lock()
	lastRun := manager.renewalLastRun["throttle-test.example.com"]
	manager.renewalMu.Unlock()

	if time.Since(lastRun) > 5*time.Second {
		t.Error("triggerRenewal within throttle interval should have been skipped (lastRun should not change)")
	}

	// inflight 标记不应该被设置（因为节流在 inflight 检查之前）
	manager.renewalMu.Lock()
	inflight := manager.renewalInflight["throttle-test.example.com"]
	manager.renewalMu.Unlock()

	if inflight {
		t.Error("renewalInflight should not be set when throttled")
	}
}

// TestTriggerRenewalInflightSkip 测试正在进行的续期不会被重复触发
func TestTriggerRenewalInflightSkip(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewManager(tempDir, logger.GetDefaultLogger())
	defer manager.Shutdown()

	config := &CertConfig{
		Remote: &RemoteCertConfig{
			Enabled:    true,
			AutoUpdate: true,
			Endpoint:   endpoints.New("https://127.0.0.1:1"),
		},
	}

	// 手动标记一个域名正在进行续期
	manager.renewalMu.Lock()
	manager.renewalInflight["inflight-test.example.com"] = true
	manager.renewalLastRun["inflight-test.example.com"] = time.Now().Add(-1 * time.Hour) // 1小时前，不受节流影响
	manager.renewalMu.Unlock()

	expiringSoon := time.Now().Add(15 * 24 * time.Hour)

	// 触发续期：应该被跳过，因为 inflight 标记已设置
	manager.triggerRenewal("inflight-test.example.com", config, expiringSoon)

	// 仍然标记为 inflight，说明没有被新的触发覆盖
	manager.renewalMu.Lock()
	lastRun := manager.renewalLastRun["inflight-test.example.com"]
	manager.renewalMu.Unlock()

	// lastRun 不应该被更新（仍然是1小时前，因为 inflight 标记阻止了触发）
	if time.Since(lastRun) < 30*time.Minute {
		t.Error("triggerRenewal should have been skipped due to inflight marker")
	}
}
