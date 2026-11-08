package cert

// F6 证书更新通道加固测试（内部PRD §4.6/§11 F6）：
// http 端点拒/allow 过+Warn；SAN 精确/通配符过、父域 SAN 拒、NotBefore 宽限、
// 过期拒；无效证书不落盘（cache 目录断言）；Validate 接线（timeout 越界/同启）；
// 缓存过期以证书本体为准（metadata 篡改拒）。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/endpoints"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// genCertOpts 测试证书参数
type genCertOpts struct {
	dnsNames  []string
	notBefore time.Time
	notAfter  time.Time
}

// genTestCert 生成自签名测试证书（返回 fullchain PEM 与私钥 PEM）
func genTestCert(t *testing.T, opts genCertOpts) (string, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: opts.dnsNames[0]},
		DNSNames:     opts.dnsNames,
		NotBefore:    opts.notBefore,
		NotAfter:     opts.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(priv)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// now 基准时间
var f6now = time.Now()

func validSANOpts() genCertOpts {
	return genCertOpts{
		dnsNames:  []string{"api.example.com"},
		notBefore: f6now.Add(-time.Hour),
		notAfter:  f6now.Add(30 * 24 * time.Hour),
	}
}

// remoteServer 返回签发指定证书的 ssl-api 模拟服务器（?domain= 参数按请求回证书）
func remoteServer(t *testing.T, certs map[string][2]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		pair, ok := certs[domain]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, `{"code":200,"message":"ok","data":{"domain":%q,"fullchain":%q,"privkey":%q,"start_date":%q,"expired_date":%q}}`,
			domain, pair[0], pair[1],
			f6now.Add(-time.Hour).Format(time.RFC3339),
			f6now.Add(30*24*time.Hour).Format(time.RFC3339))
	}))
}

func f6Loader(t *testing.T) *Loader {
	t.Helper()
	return NewLoader(t.TempDir(), logger.GetDefaultLogger())
}

func TestValidateRemoteCertificateSANAndWindow(t *testing.T) {
	l := logger.GetDefaultLogger()

	// SAN 精确匹配 + 窗口合法 → 过（链校验关：自签测试证书无系统根）
	certPEM, _ := genTestCert(t, validSANOpts())
	cert := mustParse(t, certPEM)
	if err := validateRemoteCertificate("api.example.com", cert, []byte(certPEM), false, l); err != nil {
		t.Errorf("valid cert rejected: %v", err)
	}

	// 通配符 SAN 匹配子域 → 过
	wcPEM, _ := genTestCert(t, genCertOpts{
		dnsNames:  []string{"*.example.com"},
		notBefore: f6now.Add(-time.Hour),
		notAfter:  f6now.Add(30 * 24 * time.Hour),
	})
	if err := validateRemoteCertificate("api.example.com", mustParse(t, wcPEM), []byte(wcPEM), false, l); err != nil {
		t.Errorf("wildcard SAN rejected: %v", err)
	}

	// 父域 SAN 错配（请求 api.example.com，证书 SAN 是 other.example.com）→ 拒
	otherPEM, _ := genTestCert(t, genCertOpts{
		dnsNames:  []string{"other.example.com"},
		notBefore: f6now.Add(-time.Hour),
		notAfter:  f6now.Add(30 * 24 * time.Hour),
	})
	if err := validateRemoteCertificate("api.example.com", mustParse(t, otherPEM), []byte(otherPEM), false, l); err == nil {
		t.Error("parent/SAN-mismatched cert must be rejected")
	}

	// NotBefore 未来 10 分钟（24h 宽限内）→ 过
	futurePEM, _ := genTestCert(t, genCertOpts{
		dnsNames:  []string{"api.example.com"},
		notBefore: f6now.Add(10 * time.Minute),
		notAfter:  f6now.Add(30 * 24 * time.Hour),
	})
	if err := validateRemoteCertificate("api.example.com", mustParse(t, futurePEM), []byte(futurePEM), false, l); err != nil {
		t.Errorf("notBefore within grace rejected: %v", err)
	}

	// NotBefore 未来 3 天 → 拒
	farPEM, _ := genTestCert(t, genCertOpts{
		dnsNames:  []string{"api.example.com"},
		notBefore: f6now.Add(72 * time.Hour),
		notAfter:  f6now.Add(90 * 24 * time.Hour),
	})
	if err := validateRemoteCertificate("api.example.com", mustParse(t, farPEM), []byte(farPEM), false, l); err == nil {
		t.Error("notBefore 3d in future must be rejected")
	}

	// 已过期 → 拒
	expPEM, _ := genTestCert(t, genCertOpts{
		dnsNames:  []string{"api.example.com"},
		notBefore: f6now.Add(-90 * 24 * time.Hour),
		notAfter:  f6now.Add(-time.Hour),
	})
	if err := validateRemoteCertificate("api.example.com", mustParse(t, expPEM), []byte(expPEM), false, l); err == nil {
		t.Error("expired cert must be rejected")
	}
}

// TestLoadRemoteRejectsInvalidCertNotCached 无效证书（SAN 错配）→ 拒绝且不落盘
func TestLoadRemoteRejectsInvalidCertNotCached(t *testing.T) {
	l := f6Loader(t)
	certPEM, keyPEM := genTestCert(t, genCertOpts{
		dnsNames:  []string{"other.example.com"}, // SAN 与请求域不匹配
		notBefore: f6now.Add(-time.Hour),
		notAfter:  f6now.Add(30 * 24 * time.Hour),
	})
	srv := remoteServer(t, map[string][2]string{"api.example.com": {certPEM, keyPEM}})
	defer srv.Close()

	cfg := &RemoteCertConfig{
		Enabled:     true,
		Endpoint:    endpoints.New(srv.URL),
		VerifyChain: boolPtrFalse(),
	}
	_, err := l.loadRemoteCertificate("api.example.com", cfg)
	if err == nil {
		t.Fatal("SAN-mismatched remote cert must be rejected")
	}
	// cache 目录断言：不落盘
	entries, _ := os.ReadDir(l.cacheDir)
	if len(entries) != 0 {
		t.Errorf("invalid cert must not be cached, found %d entries", len(entries))
	}
}

// TestLoadRemoteHTTPEndpointRejectedAndAllowed http 端点：未放行拒（含运行期
// 兜底路径）；allow 放行 + 证书有效时加载成功
func TestLoadRemoteHTTPEndpointRejectedAndAllowed(t *testing.T) {
	certPEM, keyPEM := genTestCert(t, validSANOpts())
	srv := remoteServer(t, map[string][2]string{"api.example.com": {certPEM, keyPEM}})
	defer srv.Close()
	httpURL := srv.URL // httptest.NewServer 即 http 端点

	l := f6Loader(t)
	// 未放行 → 运行期兜底拒绝
	cfg := &RemoteCertConfig{Enabled: true, Endpoint: endpoints.New(httpURL), VerifyChain: boolPtrFalse()}
	if _, err := l.loadRemoteCertificate("api.example.com", cfg); err == nil {
		t.Error("plaintext http endpoint without allow_insecure_http must be rejected at runtime")
	}

	// 放行 → 加载成功
	allow := true
	cfg.AllowInsecureHTTP = &allow
	pair, err := l.loadRemoteCertificate("api.example.com", cfg)
	if err != nil {
		t.Fatalf("allowed http endpoint should load: %v", err)
	}
	if pair.Metadata.Domain != "api.example.com" {
		t.Errorf("loaded domain = %q", pair.Metadata.Domain)
	}
	// metadata 有效期取证书本体（F6.4）：响应字段是同样窗口，改证书窗口验证本体优先
	cert := mustParse(t, certPEM)
	if !pair.Metadata.NotAfter.Equal(cert.NotAfter.Truncate(time.Second)) && pair.Metadata.NotAfter.Sub(cert.NotAfter) > time.Second {
		t.Errorf("metadata NotAfter %v should track cert body %v", pair.Metadata.NotAfter, cert.NotAfter)
	}
}

// TestCertConfigValidateF6 CertConfig.Validate：http 端点 / timeout 越界 / 同启
func TestCertConfigValidateF6(t *testing.T) {
	// http 未放行 → 拒
	cfg := &CertConfig{Remote: &RemoteCertConfig{
		Enabled: true, Endpoint: endpoints.New("http://ssl-api.internal:80"),
	}}
	if err := cfg.Validate(); err == nil {
		t.Error("http endpoint without allow must fail Validate")
	}
	// http + allow → 过
	allow := true
	cfg.Remote.AllowInsecureHTTP = &allow
	if err := cfg.Validate(); err != nil {
		t.Errorf("http endpoint with allow should pass: %v", err)
	}
	// timeout 越界 → 拒
	cfg.Remote.Endpoint = endpoints.New("https://ssl-api.internal")
	cfg.Remote.Timeout = 2 * time.Hour
	if err := cfg.Validate(); err == nil {
		t.Error("timeout > 1h must fail Validate")
	}
	cfg.Remote.Timeout = -time.Second
	if err := cfg.Validate(); err == nil {
		t.Error("negative timeout must fail Validate")
	}
	// 同启 → 拒（既有行为回归）
	cfg.Remote.Timeout = 0
	cfg.Local = &LocalCertConfig{Enabled: true, CertDir: "/tmp"}
	if err := cfg.Validate(); err == nil {
		t.Error("local+remote both enabled must fail")
	}
}

// TestLoadFromCacheExpiryFromCertBody F6.4：缓存过期以证书本体为准——
// 篡改 metadata 延长表面有效期，证书本体已过期仍拒
func TestLoadFromCacheExpiryFromCertBody(t *testing.T) {
	l := f6Loader(t)
	// 写入一份「本体已过期」的缓存 + 「未来有效期」的伪造 metadata
	certPEM, keyPEM := genTestCert(t, genCertOpts{
		dnsNames:  []string{"api.example.com"},
		notBefore: f6now.Add(-90 * 24 * time.Hour),
		notAfter:  f6now.Add(-time.Hour), // 已过期
	})
	dir := filepath.Join(l.cacheDir, "api.example.com")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), []byte(certPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "privkey.pem"), []byte(keyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	// 伪造 metadata：NotAfter 写到远未来
	fake := &CertMetadata{
		Domain:    "api.example.com",
		NotBefore: f6now.Add(-time.Hour),
		NotAfter:  f6now.Add(365 * 24 * time.Hour),
		UpdatedAt: f6now,
		Source:    "remote",
	}
	if err := fake.SaveMetadata(l.cacheDir); err != nil {
		t.Fatal(err)
	}

	if _, err := l.loadFromCache("api.example.com"); err == nil {
		t.Error("expired cert body with tampered metadata must be rejected from cache")
	}
}

// TestUpdaterFailureNotificationThrottle F6.5：连续失败限频（首次 + 每 12 次）
func TestUpdaterFailureNotificationThrottle(t *testing.T) {
	u := NewUpdater(t.TempDir(), f6Loader(t), logger.GetDefaultLogger(), nil)
	var notified []int
	u.SetRenewalFailedNotifier(func(domain string, consecutive int, errStr string) {
		notified = append(notified, consecutive)
	})
	for i := 0; i < 25; i++ {
		u.noteRenewalFailure("a.example.com", "boom")
	}
	// 期望通知点：1, 12, 24
	if len(notified) != 3 || notified[0] != 1 || notified[1] != 12 || notified[2] != 24 {
		t.Errorf("notify points = %v, want [1 12 24]", notified)
	}
	// 成功清零后重新从首次开始
	delete(u.failCounts, "a.example.com")
	u.noteRenewalFailure("a.example.com", "boom")
	if len(notified) != 4 || notified[3] != 1 {
		t.Errorf("after reset notify = %v, want consecutive restart at 1", notified)
	}
}

func mustParse(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	cert, err := ParseCertificate([]byte(pemStr))
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func boolPtrFalse() *bool {
	v := false
	return &v
}
