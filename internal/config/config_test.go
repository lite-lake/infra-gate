package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/cert"
)

func ptrString(s string) *string { return &s }
func ptrBool(b bool) *bool       { return &b }
func ptrInt(i int) *int          { return &i }

func makeGlobalWAF() WAFConfig {
	return WAFConfig{
		Enabled:     true,
		DefaultMode: WAFModeBlock,
		Whitelist: WAFWhitelistConfig{
			Enabled:  true,
			IPRanges: []string{"10.0.0.0/8"},
		},
		CRS: WAFCRSConfig{
			Enabled: true,
			Version: "v4.0.0",
			Download: WAFCRSDownloadConfig{
				Timeout: 60,
				Proxy: WAFCRSProxyConfig{
					Enabled:  true,
					URL:      "http://proxy.example.com:8080",
					Username: "user",
					Password: "pass",
				},
			},
		},
		Custom: WAFCustomConfig{
			Enabled:   true,
			RulesFile: "./configs/custom-rules.conf",
		},
		Debug: WAFDebugConfig{
			LogLevel: 3,
			LogFile:  "/dev/stdout",
		},
	}
}

// --- GetEffectiveWAFConfig ---

func TestGetEffectiveWAFConfigNilOverride(t *testing.T) {
	host := &HostConfig{}
	effective := host.GetEffectiveWAFConfig(makeGlobalWAF())

	if effective.DefaultMode != WAFModeBlock {
		t.Errorf("DefaultMode = %q, want %q (global)", effective.DefaultMode, WAFModeBlock)
	}
	if !effective.Whitelist.Enabled {
		t.Error("Whitelist.Enabled should be true (from global)")
	}
	if !effective.CRS.Enabled {
		t.Error("CRS.Enabled should be true (from global)")
	}
	if !effective.Custom.Enabled {
		t.Error("Custom.Enabled should be true (from global)")
	}
	if effective.Debug.LogLevel != 3 {
		t.Errorf("Debug.LogLevel = %d, want 3 (from global)", effective.Debug.LogLevel)
	}
}

func TestGetEffectiveWAFConfigEmptyWAFBlock(t *testing.T) {
	host := &HostConfig{
		WAF: &HostWAFOverride{},
	}
	effective := host.GetEffectiveWAFConfig(makeGlobalWAF())

	if effective.DefaultMode != WAFModeBlock {
		t.Errorf("DefaultMode = %q, want %q (global preserved)", effective.DefaultMode, WAFModeBlock)
	}
	if !effective.Whitelist.Enabled {
		t.Error("Whitelist.Enabled should be true (global preserved, zero value must not override)")
	}
	if !effective.CRS.Enabled {
		t.Error("CRS.Enabled should be true (global preserved)")
	}
	if !effective.Custom.Enabled {
		t.Error("Custom.Enabled should be true (global preserved)")
	}
	if effective.Debug.LogLevel != 3 {
		t.Errorf("Debug.LogLevel = %d, want 3 (global preserved)", effective.Debug.LogLevel)
	}
}

func TestGetEffectiveWAFConfigDefaultModeOnly(t *testing.T) {
	host := &HostConfig{
		WAF: &HostWAFOverride{
			DefaultMode: ptrString(WAFModeDetect),
		},
	}
	effective := host.GetEffectiveWAFConfig(makeGlobalWAF())

	if effective.DefaultMode != WAFModeDetect {
		t.Errorf("DefaultMode = %q, want %q (overridden)", effective.DefaultMode, WAFModeDetect)
	}
	if !effective.Whitelist.Enabled {
		t.Error("Whitelist.Enabled should be true (global preserved)")
	}
	if !effective.CRS.Enabled {
		t.Error("CRS.Enabled should be true (global preserved)")
	}
	if !effective.Custom.Enabled {
		t.Error("Custom.Enabled should be true (global preserved)")
	}
	if effective.Debug.LogLevel != 3 {
		t.Errorf("Debug.LogLevel = %d, want 3 (global preserved)", effective.Debug.LogLevel)
	}
}

func TestGetEffectiveWAFConfigDisableCRS(t *testing.T) {
	host := &HostConfig{
		WAF: &HostWAFOverride{
			CRS: &HostWAFCRSOverride{
				Enabled: ptrBool(false),
			},
		},
	}
	effective := host.GetEffectiveWAFConfig(makeGlobalWAF())

	if effective.CRS.Enabled {
		t.Error("CRS.Enabled should be false (explicitly disabled by host)")
	}
	if effective.CRS.Version != "v4.0.0" {
		t.Errorf("CRS.Version = %q, want 'v4.0.0' (global preserved)", effective.CRS.Version)
	}
	if !effective.Whitelist.Enabled {
		t.Error("Whitelist.Enabled should be true (global preserved)")
	}
}

func TestGetEffectiveWAFConfigDisableWhitelist(t *testing.T) {
	host := &HostConfig{
		WAF: &HostWAFOverride{
			Whitelist: &HostWAFWhitelistOverride{
				Enabled: ptrBool(false),
			},
		},
	}
	effective := host.GetEffectiveWAFConfig(makeGlobalWAF())

	if effective.Whitelist.Enabled {
		t.Error("Whitelist.Enabled should be false (explicitly disabled by host)")
	}
	if !effective.CRS.Enabled {
		t.Error("CRS.Enabled should be true (global preserved)")
	}
}

func TestGetEffectiveWAFConfigClearIPRanges(t *testing.T) {
	// per-host sets IPRanges to empty slice (via pointer) — should explicitly clear, not inherit global
	host := &HostConfig{
		WAF: &HostWAFOverride{
			Whitelist: &HostWAFWhitelistOverride{
				IPRanges: &[]string{},
			},
		},
	}
	effective := host.GetEffectiveWAFConfig(makeGlobalWAF())

	if !effective.Whitelist.Enabled {
		t.Error("Whitelist.Enabled should be true (global preserved, not overridden)")
	}
	if len(effective.Whitelist.IPRanges) != 0 {
		t.Errorf("Whitelist.IPRanges should be empty (explicitly cleared), got %v", effective.Whitelist.IPRanges)
	}
}

func TestGetEffectiveWAFConfigDisableCustom(t *testing.T) {
	host := &HostConfig{
		WAF: &HostWAFOverride{
			Custom: &HostWAFCustomOverride{
				Enabled: ptrBool(false),
			},
		},
	}
	effective := host.GetEffectiveWAFConfig(makeGlobalWAF())

	if effective.Custom.Enabled {
		t.Error("Custom.Enabled should be false (explicitly disabled by host)")
	}
	if effective.Custom.RulesFile != "./configs/custom-rules.conf" {
		t.Errorf("Custom.RulesFile = %q, want global value (preserved)", effective.Custom.RulesFile)
	}
}

func TestGetEffectiveWAFConfigOverrideDebug(t *testing.T) {
	host := &HostConfig{
		WAF: &HostWAFOverride{
			Debug: &HostWAFDebugOverride{
				LogLevel: ptrInt(1),
			},
		},
	}
	effective := host.GetEffectiveWAFConfig(makeGlobalWAF())

	if effective.Debug.LogLevel != 1 {
		t.Errorf("Debug.LogLevel = %d, want 1 (overridden)", effective.Debug.LogLevel)
	}
	if effective.Debug.LogFile != "/dev/stdout" {
		t.Errorf("Debug.LogFile = %q, want '/dev/stdout' (global preserved)", effective.Debug.LogFile)
	}
}

func TestGetEffectiveWAFConfigOverrideCRSDownload(t *testing.T) {
	host := &HostConfig{
		WAF: &HostWAFOverride{
			CRS: &HostWAFCRSOverride{
				Download: &HostWAFCRSDownloadOverride{
					Timeout: ptrInt(120),
					Proxy: &HostWAFCRSProxyOverride{
						Enabled: ptrBool(false),
					},
				},
			},
		},
	}
	effective := host.GetEffectiveWAFConfig(makeGlobalWAF())

	if effective.CRS.Download.Timeout != 120 {
		t.Errorf("CRS.Download.Timeout = %d, want 120 (overridden)", effective.CRS.Download.Timeout)
	}
	if effective.CRS.Download.Proxy.Enabled {
		t.Error("CRS.Download.Proxy.Enabled should be false (overridden)")
	}
	if effective.CRS.Download.Proxy.URL != "http://proxy.example.com:8080" {
		t.Errorf("CRS.Download.Proxy.URL = %q, want global value (preserved)", effective.CRS.Download.Proxy.URL)
	}
}

func TestGetEffectiveWAFConfigFullOverride(t *testing.T) {
	host := &HostConfig{
		WAF: &HostWAFOverride{
			DefaultMode: ptrString(WAFModeDetect),
			Whitelist: &HostWAFWhitelistOverride{
				Enabled:  ptrBool(false),
				IPRanges: &[]string{"172.16.0.0/12"},
			},
			CRS: &HostWAFCRSOverride{
				Enabled: ptrBool(false),
				Version: ptrString("v4.1.0"),
			},
			Custom: &HostWAFCustomOverride{
				Enabled:   ptrBool(false),
				RulesFile: ptrString("./custom.conf"),
			},
			Debug: &HostWAFDebugOverride{
				LogLevel: ptrInt(2),
				LogFile:  ptrString("/tmp/waf.log"),
			},
		},
	}
	effective := host.GetEffectiveWAFConfig(makeGlobalWAF())

	if effective.DefaultMode != WAFModeDetect {
		t.Errorf("DefaultMode = %q, want %q", effective.DefaultMode, WAFModeDetect)
	}
	if effective.Whitelist.Enabled {
		t.Error("Whitelist.Enabled should be false")
	}
	if len(effective.Whitelist.IPRanges) != 1 || effective.Whitelist.IPRanges[0] != "172.16.0.0/12" {
		t.Errorf("Whitelist.IPRanges = %v, want [172.16.0.0/12]", effective.Whitelist.IPRanges)
	}
	if effective.CRS.Enabled {
		t.Error("CRS.Enabled should be false")
	}
	if effective.CRS.Version != "v4.1.0" {
		t.Errorf("CRS.Version = %q, want v4.1.0", effective.CRS.Version)
	}
	if effective.Custom.Enabled {
		t.Error("Custom.Enabled should be false")
	}
	if effective.Custom.RulesFile != "./custom.conf" {
		t.Errorf("Custom.RulesFile = %q, want ./custom.conf", effective.Custom.RulesFile)
	}
	if effective.Debug.LogLevel != 2 {
		t.Errorf("Debug.LogLevel = %d, want 2", effective.Debug.LogLevel)
	}
	if effective.Debug.LogFile != "/tmp/waf.log" {
		t.Errorf("Debug.LogFile = %q, want /tmp/waf.log", effective.Debug.LogFile)
	}
}

func TestGetEffectiveWAFConfigDisableRequestBodyAccess(t *testing.T) {
	host := &HostConfig{
		WAF: &HostWAFOverride{
			RequestBodyAccess: ptrBool(false),
		},
	}
	effective := host.GetEffectiveWAFConfig(makeGlobalWAF())

	if effective.GetRequestBodyAccess() {
		t.Error("RequestBodyAccess should be false (explicitly disabled by host)")
	}
	if effective.DefaultMode != WAFModeBlock {
		t.Errorf("DefaultMode = %q, want %q (global preserved)", effective.DefaultMode, WAFModeBlock)
	}
	if !effective.CRS.Enabled {
		t.Error("CRS.Enabled should be true (global preserved)")
	}
}

func TestGetRequestBodyAccessDefaultTrue(t *testing.T) {
	global := makeGlobalWAF()
	// 全局与 host 均未设置时，默认应扫描请求体（保持现有行为）
	host := &HostConfig{}
	effective := host.GetEffectiveWAFConfig(global)
	if !effective.GetRequestBodyAccess() {
		t.Error("RequestBodyAccess should default to true when unset")
	}

	// host 显式开启时生效
	enabled := ptrBool(true)
	host2 := &HostConfig{WAF: &HostWAFOverride{RequestBodyAccess: enabled}}
	if !host2.GetEffectiveWAFConfig(global).GetRequestBodyAccess() {
		t.Error("RequestBodyAccess should be true when explicitly enabled")
	}

	// 全局设置为 false 且 host 未覆盖时，继承全局
	globalNoBody := makeGlobalWAF()
	globalNoBody.RequestBodyAccess = ptrBool(false)
	host3 := &HostConfig{}
	if host3.GetEffectiveWAFConfig(globalNoBody).GetRequestBodyAccess() {
		t.Error("RequestBodyAccess should inherit global=false")
	}
}

// --- Validate ---

func TestValidateValidConfig(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		WAF: WAFConfig{
			Enabled:     true,
			DefaultMode: WAFModeBlock,
		},
		Hosts: []HostConfig{
			{Name: "example.com", Backend: []string{"http://localhost:3000"}, Port: 8080, HealthCheckEnabled: ptrBool(false)},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Valid config should pass validation: %v", err)
	}
}

// H1（内部PRD）：strict_path_check 指针语义——nil = true 默认开，
// 显式 false 为逃生口
func TestGetEffectiveStrictPathCheck(t *testing.T) {
	var c ServerConfig
	if got := c.GetEffectiveStrictPathCheck(); !got {
		t.Errorf("nil StrictPathCheck = %v, want true (default on)", got)
	}
	c.StrictPathCheck = ptrBool(true)
	if got := c.GetEffectiveStrictPathCheck(); !got {
		t.Errorf("explicit true = %v, want true", got)
	}
	c.StrictPathCheck = ptrBool(false)
	if got := c.GetEffectiveStrictPathCheck(); got {
		t.Errorf("explicit false = %v, want false (escape hatch)", got)
	}
}

// L7（内部PRD）：默认 HSTS 值去除 preload——进 preload 列表后回退极慢，
// 默认值不应激进；需要 preload 的域名显式配 hsts 字面值
func TestDefaultHSTSValueDropsPreload(t *testing.T) {
	if DefaultHSTSValue != "max-age=31536000; includeSubDomains" {
		t.Errorf("DefaultHSTSValue = %q, want %q", DefaultHSTSValue, "max-age=31536000; includeSubDomains")
	}
	if strings.Contains(strings.ToLower(DefaultHSTSValue), "preload") {
		t.Errorf("DefaultHSTSValue %q must not contain preload", DefaultHSTSValue)
	}
	if !strings.Contains(strings.ToLower(DefaultHSTSValue), "includesubdomains") {
		t.Errorf("DefaultHSTSValue %q must keep includeSubDomains", DefaultHSTSValue)
	}
	// nil 覆盖 → 默认值
	var h HostConfig
	if got := h.GetEffectiveHSTS(); got != DefaultHSTSValue {
		t.Errorf("nil hsts = %q, want %q", got, DefaultHSTSValue)
	}
}

// L1（内部PRD 出口标准④）：通配 host 配 redirect_https 启动校验直接报错
// （通配 host 无规范名称，301 Location 无法取配置名）；普通 host 合法、
// 通配 host 未配置 redirect_https 合法
func TestValidateWildcardHostRedirectHTTPSRejected(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		redir   *bool
		wantErr bool
	}{
		{"wildcard + redirect_https rejected", "*", ptrBool(true), true},
		{"named host + redirect_https ok", "plain.example.com", ptrBool(true), false},
		{"wildcard without redirect_https ok", "*", nil, false},
		{"named host redirect_https off ok", "plain.example.com", ptrBool(false), false},
	}
	for _, tt := range tests {
		cfg := &Config{
			Server: ServerConfig{Port: 8080},
			Hosts: []HostConfig{
				{Name: tt.host, Port: 8080, Backend: []string{"http://localhost:3000"}, HealthCheckEnabled: ptrBool(false), RedirectHTTPS: tt.redir},
			},
		}
		err := cfg.Validate()
		if tt.wantErr && err == nil {
			t.Errorf("%s: wildcard host + redirect_https must fail validation", tt.name)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("%s: valid config should pass validation: %v", tt.name, err)
		}
	}
}

func TestValidateAllowedIPsCIDR(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		WAF:    WAFConfig{Enabled: true, DefaultMode: WAFModeBlock},
		Hosts: []HostConfig{
			{
				Name:               "mesh.example.com",
				Port:               8080,
				Backend:            []string{"http://localhost:3000"},
				HealthCheckEnabled: ptrBool(false),
				AllowedIPs:         []string{"10.72.0.0/24", "127.0.0.1"},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Valid AllowedIPs (CIDR + IP) should pass validation: %v", err)
	}
}

func TestValidateInvalidAllowedIPs(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		WAF:    WAFConfig{Enabled: true, DefaultMode: WAFModeBlock},
		Hosts: []HostConfig{
			{
				Name:               "mesh.example.com",
				Port:               8080,
				Backend:            []string{"http://localhost:3000"},
				HealthCheckEnabled: ptrBool(false),
				AllowedIPs:         []string{"10.72.0.0/999"},
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Invalid AllowedIPs (bad CIDR) should fail validation")
	}
}

func TestGetEffectiveAllowedIPs(t *testing.T) {
	var h HostConfig
	if got := h.GetEffectiveAllowedIPs(); len(got) != 0 {
		t.Errorf("GetEffectiveAllowedIPs() with nil should return empty, got %v", got)
	}
	h.AllowedIPs = []string{"10.72.0.0/24"}
	if got := h.GetEffectiveAllowedIPs(); len(got) != 1 || got[0] != "10.72.0.0/24" {
		t.Errorf("GetEffectiveAllowedIPs() mismatch, got %v", got)
	}
}

func TestValidateInvalidDefaultMode(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		WAF: WAFConfig{
			Enabled:     true,
			DefaultMode: "invalid",
		},
		Hosts: []HostConfig{
			{Name: "example.com", Backend: []string{"http://localhost:3000"}, Port: 8080, HealthCheckEnabled: ptrBool(false)},
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Error("Invalid DefaultMode should fail validation")
	}
}

func TestValidatePerHostInvalidDefaultMode(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		WAF:    WAFConfig{Enabled: true, DefaultMode: WAFModeBlock},
		Hosts: []HostConfig{
			{
				Name:               "example.com",
				Port:               8080,
				Backend:            []string{"http://localhost:3000"},
				HealthCheckEnabled: ptrBool(false),
				WAF:                &HostWAFOverride{DefaultMode: ptrString("invalid")},
			},
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Error("Invalid per-host DefaultMode should fail validation")
	}
}

func TestValidateValidPerHostModes(t *testing.T) {
	modes := []string{WAFModeBlock, WAFModeDetect, WAFModeDisabled, ""}

	for _, mode := range modes {
		cfg := &Config{
			Server: ServerConfig{Port: 8080},
			WAF:    WAFConfig{Enabled: true, DefaultMode: WAFModeBlock},
			Hosts: []HostConfig{
				{
					Name:               "example.com",
					Port:               8080,
					Backend:            []string{"http://localhost:3000"},
					HealthCheckEnabled: ptrBool(false),
					WAF:                &HostWAFOverride{DefaultMode: ptrString(mode)},
				},
			},
		}

		if err := cfg.Validate(); err != nil {
			t.Errorf("Valid per-host mode %q should pass validation: %v", mode, err)
		}
	}
}

func TestValidatePortRange(t *testing.T) {
	tests := []struct {
		port int
		ok   bool
	}{
		{1, true},
		{80, true},
		{65535, true},
		{65536, false},
		{0, false},
		{-1, false},
	}

	for _, tt := range tests {
		cfg := &Config{
			Server: ServerConfig{Port: tt.port},
			Hosts: []HostConfig{
				{Name: "example.com", Backend: []string{"http://localhost:3000"}, Port: 8080, HealthCheckEnabled: ptrBool(false)},
			},
		}

		err := cfg.Validate()
		if tt.ok && err != nil {
			t.Errorf("Port %d should be valid: %v", tt.port, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("Port %d should be invalid", tt.port)
		}
	}
}

func TestValidateDuplicateHostNames(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Hosts: []HostConfig{
			{Name: "example.com", Backend: []string{"http://localhost:3000"}, Port: 8080, HealthCheckEnabled: ptrBool(false)},
			{Name: "example.com", Backend: []string{"http://localhost:3001"}, Port: 8080, HealthCheckEnabled: ptrBool(false)},
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Error("Duplicate host names should fail validation")
	}
}

func TestValidateHostWithoutBackendOrText(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Hosts: []HostConfig{
			{Name: "example.com", Port: 8080, HealthCheckEnabled: ptrBool(false)},
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Error("Host without backend or text should fail validation")
	}
}

// --- LoadConfig with legacy mode field ---

func TestLoadConfigLegacyModeField(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server.yml")

	yamlContent := `
server:
  port: 8080
waf:
  enabled: true
  mode: block
hosts:
  - name: example.com
    port: 8080
    backend:
      - http://localhost:3000
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Error("LoadConfig should fail when legacy 'mode' field is present")
	}
}

func TestLoadConfigValidYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server.yml")

	yamlContent := `
server:
  port: 8080
waf:
  enabled: true
  default_mode: block
hosts:
  - name: example.com
    port: 8080
    backend:
      - http://localhost:3000
    health_check_enabled: false
    waf:
      default_mode: detect
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.WAF.DefaultMode != WAFModeBlock {
		t.Errorf("Global DefaultMode = %q, want %q", cfg.WAF.DefaultMode, WAFModeBlock)
	}
	if len(cfg.Hosts) != 1 {
		t.Fatalf("Expected 1 host, got %d", len(cfg.Hosts))
	}
	if cfg.Hosts[0].WAF == nil || cfg.Hosts[0].WAF.DefaultMode == nil {
		t.Fatal("Host WAF override should not be nil")
	}
	if *cfg.Hosts[0].WAF.DefaultMode != WAFModeDetect {
		t.Errorf("Host DefaultMode = %q, want %q", *cfg.Hosts[0].WAF.DefaultMode, WAFModeDetect)
	}
}

func TestLoadConfigRobotsDenyAll(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server.yml")

	yamlContent := `
server:
  port: 8080
waf:
  enabled: true
  default_mode: block
hosts:
  - name: example.com
    port: 8080
    backend:
      - http://localhost:3000
    health_check_enabled: false
    robots_deny_all: true
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Hosts[0].RobotsDenyAll == nil || !*cfg.Hosts[0].RobotsDenyAll {
		t.Fatal("RobotsDenyAll should parse to *true")
	}
	if !cfg.Hosts[0].GetEffectiveRobotsDenyAll() {
		t.Error("GetEffectiveRobotsDenyAll() should be true")
	}
}

// --- Other HostConfig effective methods ---

func TestGetEffectiveGZipEnabled(t *testing.T) {
	host := &HostConfig{}
	if host.GetEffectiveGZipEnabled(true) != true {
		t.Error("Nil GZipEnabled should inherit server config")
	}

	gzip := false
	host.GZipEnabled = &gzip
	if host.GetEffectiveGZipEnabled(true) != false {
		t.Error("Explicit GZipEnabled should override server config")
	}
}

func TestGetEffectiveHealthCheckEnabled(t *testing.T) {
	host := &HostConfig{}
	if !host.GetEffectiveHealthCheckEnabled() {
		t.Error("Nil HealthCheckEnabled should default to true")
	}

	enabled := false
	host.HealthCheckEnabled = &enabled
	if host.GetEffectiveHealthCheckEnabled() {
		t.Error("Explicit HealthCheckEnabled=false should be respected")
	}
}

func TestGetEffectiveRobotsDenyAll(t *testing.T) {
	host := &HostConfig{}
	if host.GetEffectiveRobotsDenyAll() {
		t.Error("Nil RobotsDenyAll should default to false")
	}

	deny := false
	host.RobotsDenyAll = &deny
	if host.GetEffectiveRobotsDenyAll() {
		t.Error("Explicit RobotsDenyAll=false should be respected")
	}

	deny = true
	host.RobotsDenyAll = &deny
	if !host.GetEffectiveRobotsDenyAll() {
		t.Error("Explicit RobotsDenyAll=true should be respected")
	}
}

func TestGetEffectiveSSLConfig(t *testing.T) {
	globalSSL := &cert.CertConfig{}
	host := &HostConfig{}

	result := host.GetEffectiveSSLConfig(globalSSL)
	if result != globalSSL {
		t.Error("Nil SSLConfig should return global config")
	}

	hostSSL := &cert.CertConfig{}
	host.SSLConfig = hostSSL
	result = host.GetEffectiveSSLConfig(globalSSL)
	if result != hostSSL {
		t.Error("Explicit SSLConfig should override global config")
	}
}

func TestGetEffectiveHealthCheckValidation(t *testing.T) {
	enabled := true
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Hosts: []HostConfig{
			{
				Name:                "example.com",
				Port:                8080,
				Backend:             []string{"http://localhost:3000"},
				HealthCheckEnabled:  &enabled,
				HealthCheckInterval: 5 * time.Second,
				HealthCheckTimeout:  10 * time.Second,
			},
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Error("Should fail: timeout >= interval")
	}
}

// --- IP 黑名单配置 ---

// newConfigForBlacklist 构建可通过校验的基础配置骨架
func newConfigForBlacklist() *Config {
	return &Config{
		Server: ServerConfig{Port: 8080},
		Hosts: []HostConfig{
			{Name: "example.com", Port: 8080, Backend: []string{"http://localhost:3000"}, HealthCheckEnabled: ptrBool(false)},
		},
	}
}

func makeBlacklistConfig() BlacklistConfig {
	return BlacklistConfig{
		Enabled: true,
		Sources: []BlacklistSourceConfig{
			{Name: "ustc", URL: "https://blackip.ustc.edu.cn/list.php?txt"},
		},
	}
}

func TestValidateBlacklistValid(t *testing.T) {
	modes := []string{BlacklistModeBlock, BlacklistModeDetect, BlacklistModeDisabled, ""}
	intervals := []time.Duration{0, 30 * time.Minute, time.Hour, 6 * time.Hour}
	timeouts := []time.Duration{0, time.Second, 60 * time.Second, 5 * time.Minute}

	for _, mode := range modes {
		for _, iv := range intervals {
			for _, to := range timeouts {
				cfg := newConfigForBlacklist()
				bl := makeBlacklistConfig()
				bl.DefaultMode = mode
				bl.UpdateInterval = iv
				bl.Timeout = to
				cfg.Blacklist = bl

				if err := cfg.Validate(); err != nil {
					t.Errorf("mode=%q interval=%v timeout=%v should pass validation: %v", mode, iv, to, err)
				}
			}
		}
	}
}

func TestValidateBlacklistDisabledSkipsChecks(t *testing.T) {
	cfg := newConfigForBlacklist()
	cfg.Blacklist = BlacklistConfig{
		Enabled:        false,
		DefaultMode:    "not-checked",
		UpdateInterval: time.Minute, // 不合法，但 enabled=false 不校验
		Timeout:        -time.Second,
		Sources:        nil,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled blacklist config should skip validation: %v", err)
	}
}

func TestValidateBlacklistSourcesRequired(t *testing.T) {
	cfg := newConfigForBlacklist()
	bl := makeBlacklistConfig()
	bl.Sources = nil
	cfg.Blacklist = bl

	if err := cfg.Validate(); err == nil {
		t.Error("enabled blacklist without sources should fail validation")
	} else if !strings.Contains(err.Error(), "blacklist.sources") {
		t.Errorf("error should mention blacklist.sources, got: %v", err)
	}
}

func TestValidateBlacklistSourceName(t *testing.T) {
	// 空 name
	cfg := newConfigForBlacklist()
	bl := makeBlacklistConfig()
	bl.Sources = []BlacklistSourceConfig{{Name: "", URL: "https://example.com/list.txt"}}
	cfg.Blacklist = bl
	if err := cfg.Validate(); err == nil {
		t.Error("empty source name should fail validation")
	}

	// 重复 name
	cfg = newConfigForBlacklist()
	bl = makeBlacklistConfig()
	bl.Sources = []BlacklistSourceConfig{
		{Name: "ustc", URL: "https://a.example.com/list.txt"},
		{Name: "ustc", URL: "https://b.example.com/list.txt"},
	}
	cfg.Blacklist = bl
	if err := cfg.Validate(); err == nil {
		t.Error("duplicated source name should fail validation")
	}
}

func TestValidateBlacklistSourceURL(t *testing.T) {
	// L6（内部PRD）：明文 http 源默认拒绝（fail-fast），显式
	// allow_http_source: true 受控放行（D6）；https 与非法 URL 判定不受该开关影响
	tests := []struct {
		url       string
		allowHTTP bool
		ok        bool
	}{
		{"https://blackip.ustc.edu.cn/list.php?txt", false, true},
		{"http://mirror.internal/list.txt", false, false}, // 明文 http 未放行 → 启动校验失败
		{"http://mirror.internal/list.txt", true, true},   // 显式放行 → 通过
		{"", false, false},
		{"ftp://example.com/list.txt", false, false},
		{"example.com/list.txt", false, false},     // 无 scheme
		{"http://bad host/list.txt", false, false}, // 含空格不可解析
	}

	for _, tt := range tests {
		cfg := newConfigForBlacklist()
		bl := makeBlacklistConfig()
		bl.Sources = []BlacklistSourceConfig{{Name: "ustc", URL: tt.url}}
		bl.AllowHTTPSource = ptrBool(tt.allowHTTP)
		cfg.Blacklist = bl

		err := cfg.Validate()
		if tt.ok && err != nil {
			t.Errorf("url %q (allow_http_source=%v) should be valid: %v", tt.url, tt.allowHTTP, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("url %q (allow_http_source=%v) should be invalid", tt.url, tt.allowHTTP)
		}
	}
}

func TestValidateBlacklistDefaultMode(t *testing.T) {
	cfg := newConfigForBlacklist()
	bl := makeBlacklistConfig()
	bl.DefaultMode = "invalid"
	cfg.Blacklist = bl

	err := cfg.Validate()
	if err == nil {
		t.Fatal("invalid blacklist.default_mode should fail validation")
	}
	if !strings.Contains(err.Error(), "blacklist.default_mode") {
		t.Errorf("error should mention blacklist.default_mode, got: %v", err)
	}
}

func TestValidateBlacklistUpdateInterval(t *testing.T) {
	tests := []struct {
		interval time.Duration
		ok       bool
	}{
		{0, true},                 // 0 = 默认 1h
		{30 * time.Minute, true},  // 下限
		{29 * time.Minute, false}, // 低于下限
		{29*time.Minute + 59*time.Second, false},
		{-time.Hour, false}, // 负值
		{time.Hour, true},
	}

	for _, tt := range tests {
		cfg := newConfigForBlacklist()
		bl := makeBlacklistConfig()
		bl.UpdateInterval = tt.interval
		cfg.Blacklist = bl

		err := cfg.Validate()
		if tt.ok && err != nil {
			t.Errorf("update_interval %v should be valid: %v", tt.interval, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("update_interval %v should be invalid", tt.interval)
		}
	}
}

func TestValidateBlacklistTimeout(t *testing.T) {
	tests := []struct {
		timeout time.Duration
		ok      bool
	}{
		{0, true}, // 0 = 默认 60s
		{time.Second, true},
		{60 * time.Second, true},
		{5 * time.Minute, true}, // 上限
		{5*time.Minute + time.Second, false},
		{-time.Second, false},
	}

	for _, tt := range tests {
		cfg := newConfigForBlacklist()
		bl := makeBlacklistConfig()
		bl.Timeout = tt.timeout
		cfg.Blacklist = bl

		err := cfg.Validate()
		if tt.ok && err != nil {
			t.Errorf("timeout %v should be valid: %v", tt.timeout, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("timeout %v should be invalid", tt.timeout)
		}
	}
}

func TestValidateBlacklistHostDefaultMode(t *testing.T) {
	// host 显式设置的非法模式 + 全局启用 → 报错
	cfg := newConfigForBlacklist()
	cfg.Blacklist = makeBlacklistConfig()
	cfg.Hosts[0].Blacklist = &HostBlacklistOverride{DefaultMode: ptrString("invalid")}
	if err := cfg.Validate(); err == nil {
		t.Error("invalid per-host blacklist.default_mode should fail validation")
	}

	// 合法值（含空字符串=未设置）→ 通过
	for _, mode := range []string{BlacklistModeBlock, BlacklistModeDetect, BlacklistModeDisabled, ""} {
		cfg := newConfigForBlacklist()
		cfg.Blacklist = makeBlacklistConfig()
		cfg.Hosts[0].Blacklist = &HostBlacklistOverride{DefaultMode: ptrString(mode)}
		if err := cfg.Validate(); err != nil {
			t.Errorf("per-host blacklist mode %q should pass validation: %v", mode, err)
		}
	}

	// 全局关闭时 host 覆盖不生效，不校验
	cfg = newConfigForBlacklist()
	cfg.Blacklist = BlacklistConfig{Enabled: false}
	cfg.Hosts[0].Blacklist = &HostBlacklistOverride{DefaultMode: ptrString("invalid")}
	if err := cfg.Validate(); err != nil {
		t.Errorf("per-host blacklist mode should not be validated when blacklist disabled: %v", err)
	}
}

func TestGetEffectiveBlacklistMode(t *testing.T) {
	tests := []struct {
		name         string
		hostMode     *string
		globalMode   string
		expectedMode string
	}{
		{"nil host override inherits global", nil, BlacklistModeDetect, BlacklistModeDetect},
		{"nil host + empty global falls back to block", nil, "", BlacklistModeBlock},
		{"host override wins", ptrString(BlacklistModeDisabled), BlacklistModeDetect, BlacklistModeDisabled},
		{"empty host mode treated as unset", ptrString(""), BlacklistModeDetect, BlacklistModeDetect},
		{"empty host + empty global falls back to block", ptrString(""), "", BlacklistModeBlock},
		{"host override wins even with empty global", ptrString(BlacklistModeBlock), "", BlacklistModeBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := &HostConfig{}
			if tt.hostMode != nil {
				host.Blacklist = &HostBlacklistOverride{DefaultMode: tt.hostMode}
			}
			global := BlacklistConfig{DefaultMode: tt.globalMode}

			if got := host.GetEffectiveBlacklistMode(global); got != tt.expectedMode {
				t.Errorf("GetEffectiveBlacklistMode() = %q, want %q", got, tt.expectedMode)
			}
		})
	}
}

func TestGetIgnorePrivateIPs(t *testing.T) {
	var cfg BlacklistConfig
	if !cfg.GetIgnorePrivateIPs() {
		t.Error("nil IgnorePrivateIPs should default to true")
	}

	cfg.IgnorePrivateIPs = ptrBool(false)
	if cfg.GetIgnorePrivateIPs() {
		t.Error("explicit false should be respected")
	}

	cfg.IgnorePrivateIPs = ptrBool(true)
	if !cfg.GetIgnorePrivateIPs() {
		t.Error("explicit true should be respected")
	}
}

func TestLoadConfigBlacklistYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server.yml")

	yamlContent := `
server:
  port: 8080
blacklist:
  enabled: true
  default_mode: detect
  sources:
    - name: ustc
      url: "https://blackip.ustc.edu.cn/list.php?txt"
  update_interval: 2h
  timeout: 30s
  proxy:
    enabled: false
    url: ""
    username: ""
    password: ""
  whitelist:
    - "203.0.113.10"
  ignore_private_ips: true
hosts:
  - name: app.example.com
    port: 8080
    backend:
      - http://localhost:3000
    health_check_enabled: false
    blacklist:
      default_mode: disabled
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	bl := cfg.Blacklist
	if !bl.Enabled {
		t.Error("blacklist.enabled should be true")
	}
	if bl.DefaultMode != BlacklistModeDetect {
		t.Errorf("DefaultMode = %q, want detect", bl.DefaultMode)
	}
	if len(bl.Sources) != 1 || bl.Sources[0].Name != "ustc" || bl.Sources[0].URL != "https://blackip.ustc.edu.cn/list.php?txt" {
		t.Errorf("Sources = %+v", bl.Sources)
	}
	if bl.UpdateInterval != 2*time.Hour {
		t.Errorf("UpdateInterval = %v, want 2h", bl.UpdateInterval)
	}
	if bl.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", bl.Timeout)
	}
	if len(bl.Whitelist) != 1 || bl.Whitelist[0] != "203.0.113.10" {
		t.Errorf("Whitelist = %v", bl.Whitelist)
	}
	if !bl.GetIgnorePrivateIPs() {
		t.Error("GetIgnorePrivateIPs should be true")
	}

	if cfg.Hosts[0].Blacklist == nil || cfg.Hosts[0].Blacklist.DefaultMode == nil {
		t.Fatal("host blacklist override should not be nil")
	}
	if *cfg.Hosts[0].Blacklist.DefaultMode != BlacklistModeDisabled {
		t.Errorf("host DefaultMode = %q, want disabled", *cfg.Hosts[0].Blacklist.DefaultMode)
	}
	if got := cfg.Hosts[0].GetEffectiveBlacklistMode(cfg.Blacklist); got != BlacklistModeDisabled {
		t.Errorf("GetEffectiveBlacklistMode() = %q, want disabled", got)
	}
}

func TestLoadConfigBlacklistWhitelistInvalidNotFatal(t *testing.T) {
	// whitelist 非法条目不在 Validate 报错（由 server 初始化时预解析 Warn+跳过），不应阻断启动
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server.yml")

	yamlContent := `
server:
  port: 8080
blacklist:
  enabled: true
  sources:
    - name: ustc
      url: "https://blackip.ustc.edu.cn/list.php?txt"
  whitelist:
    - "not-an-ip"
hosts:
  - name: app.example.com
    port: 8080
    backend:
      - http://localhost:3000
    health_check_enabled: false
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("invalid whitelist entry must not block startup: %v", err)
	}
	if len(cfg.Blacklist.Whitelist) != 1 {
		t.Errorf("Whitelist = %v, want raw parse", cfg.Blacklist.Whitelist)
	}
}

// --- Validate: server.trusted_proxies（内部PRD §5.4 fail-fast） ---

func TestValidateTrustedProxies(t *testing.T) {
	newCfg := func(entries []string) *Config {
		return &Config{
			Server: ServerConfig{Port: 8080, TrustedProxies: entries},
			WAF:    WAFConfig{Enabled: true, DefaultMode: WAFModeBlock},
			Hosts: []HostConfig{
				{Name: "example.com", Port: 8080, Backend: []string{"http://localhost:3000"}, HealthCheckEnabled: ptrBool(false)},
			},
		}
	}

	tests := []struct {
		name      string
		entries   []string
		wantErr   bool
		errSubstr string // 非空时断言错误信息包含该子串
	}{
		{
			name:    "empty list passes (public edge gate)",
			entries: nil,
			wantErr: false,
		},
		{
			name:    "valid CIDR, bare IPv4 and IPv6 mix passes",
			entries: []string{"10.72.0.0/24", "127.0.0.1", "::1"},
			wantErr: false,
		},
		{
			name:      "invalid format fails",
			entries:   []string{"10.72.0.0/24", "not-an-ip"},
			wantErr:   true,
			errSubstr: "trusted_proxies",
		},
		{
			name:      "invalid CIDR mask fails",
			entries:   []string{"10.0.0.0/99"},
			wantErr:   true,
			errSubstr: "trusted_proxies",
		},
		{
			name:      "empty entry fails",
			entries:   []string{""},
			wantErr:   true,
			errSubstr: "trusted_proxies",
		},
		{
			name:      "IPv4 trust-all default route fails",
			entries:   []string{"10.72.0.0/24", "0.0.0.0/0"},
			wantErr:   true,
			errSubstr: "trust-all",
		},
		{
			name:      "IPv6 trust-all default route fails",
			entries:   []string{"::/0"},
			wantErr:   true,
			errSubstr: "trust-all",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newCfg(tt.entries).Validate()
			if tt.wantErr && err == nil {
				t.Errorf("TrustedProxies %v should fail validation", tt.entries)
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("TrustedProxies %v should pass validation, got: %v", tt.entries, err)
				return
			}
			if tt.wantErr && tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("validation error = %q, want containing %q", err.Error(), tt.errSubstr)
			}
		})
	}
}

// --- forwarded_for 校验（v1.1 per-host 转发策略） ---

// makeForwardedForCfg 构造仅 forwarded_for 不同的单 host 配置
func makeForwardedForCfg(forwardedFor string) *Config {
	return &Config{
		Server: ServerConfig{Port: 8080},
		WAF:    WAFConfig{Enabled: true, DefaultMode: WAFModeBlock},
		Hosts: []HostConfig{
			{
				Name:               "mesh.example.com",
				Port:               8080,
				Backend:            []string{"http://localhost:3000"},
				HealthCheckEnabled: ptrBool(false),
				ForwardedFor:       forwardedFor,
			},
		},
	}
}

func TestValidateForwardedForValidValues(t *testing.T) {
	// 仅允许 ""（缺省=边缘语义）与 "append"（mesh 追加语义）
	for _, ff := range []string{"", ForwardedForAppend} {
		if err := makeForwardedForCfg(ff).Validate(); err != nil {
			t.Errorf("forwarded_for=%q should pass validation, got: %v", ff, err)
		}
	}
}

func TestValidateForwardedForInvalidValue(t *testing.T) {
	for _, ff := range []string{"edge", "APPEND", "append ", "single", "rebuild"} {
		err := makeForwardedForCfg(ff).Validate()
		if err == nil {
			t.Errorf("forwarded_for=%q should fail validation", ff)
			continue
		}
		if !strings.Contains(err.Error(), "forwarded_for") {
			t.Errorf("validation error = %q, want containing %q", err.Error(), "forwarded_for")
		}
	}
}

// ===== 密码门（auth）配置校验（内部PRD §5.2/§13） =====

func makeAuthCfg(auth *HostAuthConfig) *Config {
	return &Config{
		Server: ServerConfig{Port: 8080},
		Hosts: []HostConfig{
			{
				Name:               "auth.example.com",
				Port:               8080,
				Backend:            []string{"http://localhost:3000"},
				HealthCheckEnabled: ptrBool(false),
				Auth:               auth,
			},
		},
	}
}

func TestValidateAuthPasswordRequired(t *testing.T) {
	// 启用 auth 但 password 为空 → 报错
	err := makeAuthCfg(&HostAuthConfig{Password: ""}).Validate()
	if err == nil {
		t.Fatalf("auth.password empty should fail validation")
	}
	if !strings.Contains(err.Error(), "auth.password is required") {
		t.Errorf("validation error = %q, want containing %q", err.Error(), "auth.password is required")
	}

	// password 非空 → 通过
	if err := makeAuthCfg(&HostAuthConfig{Password: "x"}).Validate(); err != nil {
		t.Errorf("valid auth config should pass, got: %v", err)
	}

	// Auth == nil（未启用）→ 通过
	if err := makeAuthCfg(nil).Validate(); err != nil {
		t.Errorf("nil auth should pass, got: %v", err)
	}
}

func TestValidateAuthPublicPathsPrefix(t *testing.T) {
	if err := makeAuthCfg(&HostAuthConfig{Password: "x", PublicPaths: []string{"/healthz", "/metrics"}}).Validate(); err != nil {
		t.Errorf("valid public_paths should pass, got: %v", err)
	}
	for _, bad := range []string{"healthz", "*", "http://x"} {
		err := makeAuthCfg(&HostAuthConfig{Password: "x", PublicPaths: []string{bad}}).Validate()
		if err == nil {
			t.Errorf("public_paths entry %q should fail validation", bad)
			continue
		}
		if !strings.Contains(err.Error(), "must start with /") {
			t.Errorf("validation error = %q, want containing %q", err.Error(), "must start with /")
		}
	}
}

func TestGetEffectiveAuthTTLDefault24h(t *testing.T) {
	// TTL 未设置 / 负值 → 默认 24h（决策 D2）
	for _, ttl := range []time.Duration{0, -1 * time.Hour} {
		a := &HostAuthConfig{Password: "x", TTL: ttl}
		if got := a.GetEffectiveAuthTTL(); got != DefaultAuthTTL {
			t.Errorf("GetEffectiveAuthTTL(TTL=%v) = %v, want %v", ttl, got, DefaultAuthTTL)
		}
	}
	// 显式 TTL 生效
	a := &HostAuthConfig{Password: "x", TTL: 2 * time.Hour}
	if got := a.GetEffectiveAuthTTL(); got != 2*time.Hour {
		t.Errorf("GetEffectiveAuthTTL = %v, want 2h", got)
	}
}

func TestLoadConfigAuthYAML(t *testing.T) {
	yamlBytes := []byte(`
server:
  port: 8080
hosts:
  - name: gated.example.com
    port: 8080
    backend: ["http://localhost:3000"]
    health_check_enabled: false
    auth:
      password: "topsecret"
      ttl: 12h
      public_paths:
        - /healthz
        - /metrics
`)
	f := filepath.Join(t.TempDir(), "gate.yml")
	if err := os.WriteFile(f, yamlBytes, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(f)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	h := cfg.Hosts[0]
	if h.Auth == nil {
		t.Fatalf("auth section not parsed")
	}
	if h.Auth.Password != "topsecret" {
		t.Errorf("auth.password = %q", h.Auth.Password)
	}
	if h.Auth.TTL != 12*time.Hour {
		t.Errorf("auth.ttl = %v, want 12h", h.Auth.TTL)
	}
	if len(h.Auth.PublicPaths) != 2 || h.Auth.PublicPaths[0] != "/healthz" {
		t.Errorf("auth.public_paths = %v", h.Auth.PublicPaths)
	}
}

// ===== 逐条目 http→https 301 + www/别名域收敛 + HSTS per-host（内部总体方案 W3-2 / D8） =====

func TestGetEffectiveRedirectHTTPS(t *testing.T) {
	host := &HostConfig{}
	if host.GetEffectiveRedirectHTTPS() {
		t.Error("nil RedirectHTTPS should default to false (现状语义，全局 80 行为不变)")
	}

	host.RedirectHTTPS = ptrBool(false)
	if host.GetEffectiveRedirectHTTPS() {
		t.Error("Explicit RedirectHTTPS=false should be respected")
	}

	host.RedirectHTTPS = ptrBool(true)
	if !host.GetEffectiveRedirectHTTPS() {
		t.Error("Explicit RedirectHTTPS=true should be respected")
	}
}

func TestGetEffectiveRedirectHost(t *testing.T) {
	host := &HostConfig{}
	if got := host.GetEffectiveRedirectHost(); got != "" {
		t.Errorf("GetEffectiveRedirectHost() = %q, want empty (未配置 = 不启用收敛)", got)
	}

	host.RedirectHost = "example.com"
	if got := host.GetEffectiveRedirectHost(); got != "example.com" {
		t.Errorf("GetEffectiveRedirectHost() = %q, want example.com", got)
	}
}

// GetEffectiveHSTS 三态：nil → 默认常量（现状）；"off"（大小写不敏感）/"" → 空串（不下发）；
// 其他 → 字面值
func TestGetEffectiveHSTS(t *testing.T) {
	tests := []struct {
		name string
		hsts *string
		want string
	}{
		{"nil keeps current default", nil, DefaultHSTSValue},
		{"lowercase off disables", ptrString("off"), ""},
		{"uppercase OFF disables (case-insensitive)", ptrString("OFF"), ""},
		{"mixed case Off disables (case-insensitive)", ptrString("Off"), ""},
		{"empty string disables", ptrString(""), ""},
		{"custom literal max-age only", ptrString("max-age=60"), "max-age=60"},
		{"custom literal preserved verbatim", ptrString("max-age=63072000; includeSubDomains"), "max-age=63072000; includeSubDomains"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := &HostConfig{HSTS: tt.hsts}
			if got := host.GetEffectiveHSTS(); got != tt.want {
				t.Errorf("GetEffectiveHSTS() = %q, want %q", got, tt.want)
			}
		})
	}
}

// 三个新字段经 yaml 解析进 HostConfig（tag 名与 omitempty 语义核对）
func TestLoadConfigRedirectAndHSTSYAML(t *testing.T) {
	yamlBytes := []byte(`
server:
  port: 8080
hosts:
  - name: www.example.com
    port: 8080
    backend: ["http://localhost:3000"]
    health_check_enabled: false
    redirect_https: true
    redirect_host: example.com
    hsts: "off"
`)
	f := filepath.Join(t.TempDir(), "gate.yml")
	if err := os.WriteFile(f, yamlBytes, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(f)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	h := cfg.Hosts[0]
	if h.RedirectHTTPS == nil || !*h.RedirectHTTPS {
		t.Errorf("RedirectHTTPS = %v, want *true", h.RedirectHTTPS)
	}
	if !h.GetEffectiveRedirectHTTPS() {
		t.Error("GetEffectiveRedirectHTTPS() should be true")
	}
	if got := h.GetEffectiveRedirectHost(); got != "example.com" {
		t.Errorf("GetEffectiveRedirectHost() = %q, want example.com", got)
	}
	if got := h.GetEffectiveHSTS(); got != "" {
		t.Errorf("GetEffectiveHSTS() = %q, want empty (hsts: off)", got)
	}
}

func boolPtrTrueCfg() *bool { v := true; return &v }
