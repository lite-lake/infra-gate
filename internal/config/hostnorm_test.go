package config

// F3 配置归一化与通配防线测试（内部PRD §4.3）：
// LoadConfig in-place 归一化（大小写/尾点/端口变体 → 规范名 + 警告收集）、
// 变体查重按规范名生效、非 ASCII 名 fail-fast、通配与受保护 host 同后端拒启动。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCfg(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigNormalizesHostNames(t *testing.T) {
	path := writeCfg(t, `
server:
  port: 8080
hosts:
  - name: API.Example.NET.
    port: 80
    backend: ["http://svc-a:80"]
    health_check_enabled: false
    redirect_host: WWW.Example.NET.
  - name: lower.example.net
    port: 80
    text: "static"
    health_check_enabled: false
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Hosts[0].Name != "api.example.net" {
		t.Errorf("host name = %q, want canonical api.example.net", cfg.Hosts[0].Name)
	}
	if cfg.Hosts[0].RedirectHost != "www.example.net" {
		t.Errorf("redirect_host = %q, want www.example.net", cfg.Hosts[0].RedirectHost)
	}
	if len(cfg.NormalizeWarnings) != 2 {
		t.Errorf("normalize warnings = %d, want 2 (name + redirect_host)", len(cfg.NormalizeWarnings))
	}
}

func TestLoadConfigVariantDuplicateRejected(t *testing.T) {
	// 变体写法（仅大小写/尾点不同）归一后同名 → 查重报错
	path := writeCfg(t, `
server:
  port: 8080
hosts:
  - name: api.example.net
    port: 80
    text: "a"
    health_check_enabled: false
  - name: API.Example.NET.
    port: 80
    text: "b"
    health_check_enabled: false
`)
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Errorf("variant duplicate should be rejected after normalization, got %v", err)
	}
}

func TestValidateNonASCIIHostNameRejected(t *testing.T) {
	cfg := &Config{Server: ServerConfig{Port: 8080}, Hosts: []HostConfig{{
		Name: "中文.example.com", Port: 80, Text: "x", HealthCheckEnabled: boolPtrCfg(false),
	}}}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "non-ASCII") {
		t.Errorf("non-ASCII host name should be rejected, got %v", err)
	}
	// 通配与 ASCII 名不受影响
	cfg.Hosts[0].Name = "*"
	if err := cfg.Validate(); err != nil {
		t.Errorf("wildcard name should pass: %v", err)
	}
}

func TestValidateWildcardProtectedBackendIntersection(t *testing.T) {
	base := func(names [2]string, backends [2][]string, auth bool, allowedIPs []string) *Config {
		cfg := &Config{Server: ServerConfig{Port: 8080}}
		for i, n := range names {
			h := HostConfig{Name: n, Port: 80, Backend: backends[i], HealthCheckEnabled: boolPtrCfg(false)}
			if i == 1 && auth {
				h.Auth = &HostAuthConfig{Password: "pw", TTL: time.Hour}
			}
			if i == 1 && allowedIPs != nil {
				h.AllowedIPs = allowedIPs
			}
			cfg.Hosts = append(cfg.Hosts, h)
		}
		return cfg
	}

	// 通配与 auth host 同后端 → 拒绝
	cfg := base([2]string{"*", "a.example.com"}, [2][]string{{"http://svc:80"}, {"http://svc:80"}}, true, nil)
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "wildcard backend overlaps") {
		t.Errorf("wildcard + auth same backend should be rejected, got %v", err)
	}

	// 通配与 allowed_ips host 同后端 → 拒绝
	cfg = base([2]string{"*", "a.example.com"}, [2][]string{{"http://svc:80"}, {"http://svc:80"}}, false, []string{"10.0.0.0/8"})
	if err := cfg.Validate(); err == nil {
		t.Error("wildcard + allowed_ips same backend should be rejected")
	}

	// 不同后端 → 通过（现实常见形态）
	cfg = base([2]string{"*", "a.example.com"}, [2][]string{{"http://wild:80"}, {"http://svc:80"}}, true, nil)
	if err := cfg.Validate(); err != nil {
		t.Errorf("distinct backends should pass, got %v", err)
	}

	// 无保护 host 同后端 → 通过
	cfg = base([2]string{"*", "a.example.com"}, [2][]string{{"http://svc:80"}, {"http://svc:80"}}, false, nil)
	if err := cfg.Validate(); err != nil {
		t.Errorf("unprotected overlap should pass, got %v", err)
	}
}

func TestValidateAllowedContentEncodings(t *testing.T) {
	cfg := &Config{Server: ServerConfig{Port: 8080}, Hosts: []HostConfig{{
		Name: "a.example.com", Port: 80, Text: "x", HealthCheckEnabled: boolPtrCfg(false),
		AllowedContentEncodings: []string{"br", "gzip"},
	}}}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "allowed_content_encodings") {
		t.Errorf("invalid encoding value should be rejected, got %v", err)
	}
	cfg.Hosts[0].AllowedContentEncodings = []string{"br", "zstd"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("br/zstd should pass: %v", err)
	}
}

func TestUpstreamPoolEffectiveValues(t *testing.T) {
	sc := &ServerConfig{}
	if got := sc.GetEffectiveUpstreamMaxConnsPerHost(); got != DefaultUpstreamMaxConnsPerHost {
		t.Errorf("server default conns = %d, want %d", got, DefaultUpstreamMaxConnsPerHost)
	}
	if got := sc.GetEffectiveUpstreamResponseHeaderTimeout(); got != DefaultUpstreamResponseHeaderTimeout {
		t.Errorf("server default timeout = %v, want %v", got, DefaultUpstreamResponseHeaderTimeout)
	}
	h := &HostConfig{}
	if got := h.GetEffectiveUpstreamMaxConnsPerHost(256); got != 256 {
		t.Errorf("host inherit conns = %d, want 256", got)
	}
	ov := 512
	h.UpstreamMaxConnsPerHost = &ov
	if got := h.GetEffectiveUpstreamMaxConnsPerHost(256); got != 512 {
		t.Errorf("host override conns = %d, want 512", got)
	}
	tt := 30 * time.Second
	h2 := &HostConfig{UpstreamResponseHeaderTimeout: &tt}
	if got := h2.GetEffectiveUpstreamResponseHeaderTimeout(1800 * time.Second); got != 30*time.Second {
		t.Errorf("host override timeout = %v, want 30s", got)
	}
	if got := (&HostConfig{}).GetEffectiveMaxDecompressedRequestBody(); got != DefaultMaxDecompressedRequestBody {
		t.Errorf("decompress default = %d, want %d", got, DefaultMaxDecompressedRequestBody)
	}
	if got := (&HostConfig{MaxDecompressedRequestBody: 10 << 20}).GetEffectiveMaxDecompressedRequestBody(); got != 10<<20 {
		t.Errorf("decompress override = %d, want 10MB", got)
	}
}
