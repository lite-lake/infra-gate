package cert

// GetCertificate SNI 匹配行为测试（内部PRD §15.1）：
// D2 行为反转——未知 SNI 返回 error（defaultDomain 回退已移除），精确/通配符匹配回归不变。

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// injectTestCert 向 Manager 内存 map 直接注入证书（绕过 I/O，专注 SNI 匹配逻辑）
func injectTestCert(t *testing.T, m *Manager, domain string, certPEM, keyPEM []byte) {
	t.Helper()
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair for %s: %v", domain, err)
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.certificates[domain] = &CertPair{
		Certificate: &tlsCert,
		Metadata: &CertMetadata{
			Domain:      domain,
			NotBefore:   time.Now().Add(-time.Hour),
			NotAfter:    time.Now().Add(365 * 24 * time.Hour),
			UpdatedAt:   time.Now(),
			Source:      "local",
			Fingerprint: "sni-test-" + domain,
		},
	}
}

// TestGetCertificateUnknownSNIReturnsError D2：未知 SNI 必须返回 error，
// 不得再回退返回 defaultDomain（第一个成功加载域名）的证书
func TestGetCertificateUnknownSNIReturnsError(t *testing.T) {
	manager := NewManager(t.TempDir(), logger.GetDefaultLogger())
	defer manager.Shutdown()

	certPEM, keyPEM := generateTestCertificate(t)
	injectTestCert(t, manager, "exact.example.com", certPEM, keyPEM)

	if _, err := manager.GetCertificate("unknown.example.com"); err == nil {
		t.Error("unknown SNI must return error (defaultDomain fallback removed, 内部PRD D2)")
	}
}

// TestGetCertificateMatchingRegression 精确匹配、通配符单层匹配、
// 通配符不匹配裸域名/多层子域名——回归不变（PRD §7.3）
func TestGetCertificateMatchingRegression(t *testing.T) {
	manager := NewManager(t.TempDir(), logger.GetDefaultLogger())
	defer manager.Shutdown()

	exactPEM, exactKey := generateTestCertificate(t)
	wildPEM, wildKey := generateTestCertificate(t)
	injectTestCert(t, manager, "exact.example.com", exactPEM, exactKey)
	injectTestCert(t, manager, "*.wild.example.com", wildPEM, wildKey)

	// 精确匹配命中
	if c, err := manager.GetCertificate("exact.example.com"); err != nil || c == nil {
		t.Errorf("exact match should succeed, err=%v", err)
	}

	// 通配符匹配单层子域名
	if c, err := manager.GetCertificate("foo.wild.example.com"); err != nil || c == nil {
		t.Errorf("wildcard single-level match should succeed, err=%v", err)
	}

	// 通配符不匹配裸域名
	if _, err := manager.GetCertificate("wild.example.com"); err == nil {
		t.Error("wildcard must not match bare domain")
	}

	// 通配符不匹配多层子域名
	if _, err := manager.GetCertificate("a.b.wild.example.com"); err == nil {
		t.Error("wildcard must not match multi-level subdomain")
	}

	// 未注入任何匹配项的相邻域名同样 error
	if _, err := manager.GetCertificate("other.example.com"); err == nil {
		t.Error("unrelated SNI must return error")
	}
}
