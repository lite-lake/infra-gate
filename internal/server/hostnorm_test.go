package server

// F3 变体 Host 匹配测试（内部PRD §4.3/§11 F3）：
// 大小写/尾点/带端口/IPv6 literal/尾点+端口变体全部命中正确条目；
// 无通配时未知变体 404（fail-closed 保持）。

import (
	"net/http"
	"testing"

	"github.com/lite-lake/infra-gate/internal/config"
)

// TestVariantHostMatchesCanonicalEntry 变体 Host 命中规范名条目（此前落入
// no-match 404 或通配兜底）
func TestVariantHostMatchesCanonicalEntry(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{rgHost("api.example.com", backend.URL)},
	}
	s := newBLServer(t, cfg)

	variants := []string{
		"api.example.com",     // 规范形态（回归）
		"API.EXAMPLE.COM",     // 大小写变体
		"api.example.com.",    // 尾点变体
		"api.example.com:443", // 带端口变体
		"API.Example.COM.:8443",
	}
	for _, v := range variants {
		w := blDoRequest(s, v, "203.0.113.1", "/", "")
		if w.Code != http.StatusOK {
			t.Errorf("variant host %q status = %d, want 200 (canonical entry)", v, w.Code)
		}
	}
}

// TestUnknownHostStill404FailClosed 无通配条目时，未知 Host（含其变体）仍 404
// （fail-closed 保持；归一化不创造新匹配）
func TestUnknownHostStill404FailClosed(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{rgHost("api.example.com", backend.URL)},
	}
	s := newBLServer(t, cfg)

	for _, v := range []string{"other.example.com", "OTHER.example.com.", "xn--api.example.com", "中文.example.com"} {
		w := blDoRequest(s, v, "203.0.113.1", "/", "")
		if w.Code != http.StatusNotFound {
			t.Errorf("unknown host %q status = %d, want 404 (fail-closed)", v, w.Code)
		}
	}
}
