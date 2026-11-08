package config

import (
	"strings"
	"testing"

	"github.com/lite-lake/infra-gate/internal/infrastructs/endpoints"

	"github.com/goccy/go-yaml"
)

// ── 内部PRD：WAF/CRS 自愈新配置（failure_policy / golden_dir / retry_count）──

// newSelfHealTestConfig 构造通过基础校验的最小配置
func newSelfHealTestConfig() *Config {
	return &Config{
		Server: ServerConfig{Port: 8080},
		WAF:    WAFConfig{Enabled: true, DefaultMode: WAFModeBlock},
		Hosts: []HostConfig{
			{Name: "example.com", Backend: []string{"http://localhost:3000"}, Port: 8080, HealthCheckEnabled: ptrBool(false)},
		},
	}
}

func TestValidateCRSFailurePolicy(t *testing.T) {
	tests := []struct {
		policy string
		valid  bool
	}{
		{"", true}, // 空 = 默认 fail
		{"degrade", true},
		{"fail", true},
		{"DEGRADE", false}, // 大小写敏感，防误配
		{"bogus", false},
		{"fail ", false},
	}
	for _, tt := range tests {
		cfg := newSelfHealTestConfig()
		cfg.WAF.CRS.FailurePolicy = tt.policy
		// F11.2：degrade 用例默认带 ack（双钥匙本身另行专测）
		if tt.policy == WAFFailurePolicyDegrade {
			cfg.WAF.CRS.DegradedAcknowledged = ptrBool(true)
		}
		err := cfg.Validate()
		if tt.valid && err != nil {
			t.Errorf("failure_policy %q should pass, got: %v", tt.policy, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("failure_policy %q should fail validation", tt.policy)
		}
	}
}

func TestValidatePerHostCRSFailurePolicy(t *testing.T) {
	cfg := newSelfHealTestConfig()
	cfg.Hosts[0].WAF = &HostWAFOverride{
		CRS: &HostWAFCRSOverride{FailurePolicy: ptrString("sometimes")},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("invalid per-host failure_policy should fail validation")
	}

	ok := newSelfHealTestConfig()
	ok.Hosts[0].WAF = &HostWAFOverride{
		// F11.2 双钥匙：per-host degrade 必须同时显式配该 host 的 ack
		CRS: &HostWAFCRSOverride{FailurePolicy: ptrString(WAFFailurePolicyDegrade), DegradedAcknowledged: ptrBool(true)},
	}
	if err := ok.Validate(); err != nil {
		t.Errorf("per-host failure_policy=degrade should pass: %v", err)
	}
}

// TestValidateCRSDegradeDoubleKey F11.2（内部PRD §4.11.2）：双钥匙——
// failure_policy=degrade（全局与 per-host）未同时显式配 degrade_acknowledged: true
// 一律拒绝启动；ack 不继承（两把钥匙各自独立）
func TestValidateCRSDegradeDoubleKey(t *testing.T) {
	cfg := newSelfHealTestConfig()
	cfg.WAF.CRS.FailurePolicy = WAFFailurePolicyDegrade
	if err := cfg.Validate(); err == nil {
		t.Error("global degrade without degrade_acknowledged must fail")
	}
	cfg.WAF.CRS.DegradedAcknowledged = ptrBool(true)
	if err := cfg.Validate(); err != nil {
		t.Errorf("global degrade with ack should pass: %v", err)
	}

	cfg2 := newSelfHealTestConfig()
	cfg2.WAF.CRS.DegradedAcknowledged = ptrBool(true)
	cfg2.Hosts[0].WAF = &HostWAFOverride{
		CRS: &HostWAFCRSOverride{FailurePolicy: ptrString(WAFFailurePolicyDegrade)},
	}
	if err := cfg2.Validate(); err == nil {
		t.Error("per-host degrade without host-level ack must fail (ack not inherited)")
	}
	cfg2.Hosts[0].WAF.CRS.DegradedAcknowledged = ptrBool(true)
	if err := cfg2.Validate(); err != nil {
		t.Errorf("per-host degrade with host ack should pass: %v", err)
	}
}

func TestValidateCRSDownloadRetryCount(t *testing.T) {
	cfg := newSelfHealTestConfig()
	cfg.WAF.CRS.Download.RetryCount = -1
	if err := cfg.Validate(); err == nil {
		t.Error("negative retry_count should fail validation")
	}

	ok := newSelfHealTestConfig()
	ok.WAF.CRS.Download.RetryCount = 3
	if err := ok.Validate(); err != nil {
		t.Errorf("retry_count=3 should pass: %v", err)
	}

	okGlobal := newSelfHealTestConfig()
	okGlobal.Hosts[0].WAF = &HostWAFOverride{
		CRS: &HostWAFCRSOverride{Download: &HostWAFCRSDownloadOverride{RetryCount: ptrInt(-2)}},
	}
	if err := okGlobal.Validate(); err == nil {
		t.Error("negative per-host retry_count should fail validation")
	}
}

func TestGetEffectiveWAFConfigCRSSelfHealFields(t *testing.T) {
	global := makeGlobalWAF()
	global.CRS.FailurePolicy = WAFFailurePolicyFail
	global.CRS.Download.RetryCount = 1
	global.CRS.GoldenDir = nil // 全局未配置 → 默认 /app/crs

	// 无覆盖：继承全局
	host := &HostConfig{}
	effective := host.GetEffectiveWAFConfig(global)
	if effective.CRS.FailurePolicy != WAFFailurePolicyFail {
		t.Errorf("failure_policy = %q, want fail (global)", effective.CRS.FailurePolicy)
	}
	if effective.CRS.Download.RetryCount != 1 {
		t.Errorf("retry_count = %d, want 1 (global)", effective.CRS.Download.RetryCount)
	}
	if dir, enabled := effective.CRS.GetEffectiveGoldenDir(); !enabled || dir != DefaultCRSGoldenDir {
		t.Errorf("golden dir = %q enabled=%v, want default enabled", dir, enabled)
	}

	// per-host 覆盖全部生效
	hostOverride := &HostConfig{
		WAF: &HostWAFOverride{
			CRS: &HostWAFCRSOverride{
				FailurePolicy: ptrString(WAFFailurePolicyDegrade),
				GoldenDir:     ptrString(""), // 显式禁用金副本
				Download:      &HostWAFCRSDownloadOverride{RetryCount: ptrInt(4)},
			},
		},
	}
	effective = hostOverride.GetEffectiveWAFConfig(global)
	if effective.CRS.FailurePolicy != WAFFailurePolicyDegrade {
		t.Errorf("failure_policy = %q, want degrade (host override)", effective.CRS.FailurePolicy)
	}
	if effective.CRS.Download.RetryCount != 4 {
		t.Errorf("retry_count = %d, want 4 (host override)", effective.CRS.Download.RetryCount)
	}
	if _, enabled := effective.CRS.GetEffectiveGoldenDir(); enabled {
		t.Error("golden dir should be disabled by explicit per-host empty override")
	}
}

func TestLoadConfigCRSSelfHealYAML(t *testing.T) {
	data := `
server:
  port: 8080
waf:
  enabled: true
  default_mode: block
  crs:
    enabled: true
    version: "v4.19.0"
    failure_policy: degrade
    degrade_acknowledged: true
    golden_dir: "/data/golden-crs"
    download:
      timeout: 45
      retry_count: 3
hosts:
  - name: example.com
    port: 8080
    backend: ["http://localhost:3000"]
    health_check_enabled: false
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(data), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.WAF.CRS.FailurePolicy != WAFFailurePolicyDegrade {
		t.Errorf("failure_policy = %q, want degrade", cfg.WAF.CRS.FailurePolicy)
	}
	if cfg.WAF.CRS.GoldenDir == nil || *cfg.WAF.CRS.GoldenDir != "/data/golden-crs" {
		t.Errorf("golden_dir = %v, want /data/golden-crs", cfg.WAF.CRS.GoldenDir)
	}
	if cfg.WAF.CRS.Download.RetryCount != 3 {
		t.Errorf("retry_count = %d, want 3", cfg.WAF.CRS.Download.RetryCount)
	}
	if cfg.WAF.CRS.DegradedAcknowledged == nil || !*cfg.WAF.CRS.DegradedAcknowledged {
		t.Errorf("degrade_acknowledged = %v, want true", cfg.WAF.CRS.DegradedAcknowledged)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("validate: %v", err)
	}
}

// ── H2（内部PRD §7.3/§7.4）：pinned_sha256 / mirror_allow_insecure_http ──

// TestValidateMirrorURLScheme 镜像 https 强制：明文 http 未显式放行 → 启动校验失败；
// mirror_allow_insecure_http=true 受控放行；per-host 镜像覆盖同样受全局开关约束
func TestValidateMirrorURLScheme(t *testing.T) {
	ep := func(urls ...string) *endpoints.Config {
		c := endpoints.New(urls...)
		return &c
	}

	tests := []struct {
		name       string
		mirror     []string
		allowHTTP  *bool // nil = 未配置（缺省仅 https）
		hostMirror []string
		wantErr    bool
	}{
		{"no mirror configured", nil, nil, nil, false},
		{"https mirror", []string{"https://crsmirror.example.com"}, nil, nil, false},
		{"http mirror not allowed", []string{"http://crsmirror.example.com"}, nil, nil, true},
		{"http mirror explicitly false", []string{"http://crsmirror.example.com"}, ptrBool(false), nil, true},
		{"http mirror explicitly allowed", []string{"http://crsmirror.internal"}, ptrBool(true), nil, false},
		{"multi-endpoint with one http", []string{"https://a.example.com", "http://b.example.com"}, nil, nil, true},
		{"multi-endpoint all https", []string{"https://a.example.com", "https://b.example.com"}, nil, nil, false},
		{"per-host http override not allowed", nil, nil, []string{"http://h.example.com"}, true},
		{"per-host https override", nil, nil, []string{"https://h.example.com"}, false},
		{"per-host http allowed via global flag", nil, ptrBool(true), []string{"http://h.example.com"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newSelfHealTestConfig()
			if tt.mirror != nil {
				cfg.WAF.CRS.Download.MirrorURL = endpoints.New(tt.mirror...)
			}
			cfg.WAF.CRS.Download.MirrorAllowInsecureHTTP = tt.allowHTTP
			if tt.hostMirror != nil {
				cfg.Hosts[0].WAF = &HostWAFOverride{
					CRS: &HostWAFCRSOverride{
						Download: &HostWAFCRSDownloadOverride{MirrorURL: ep(tt.hostMirror...)},
					},
				}
			}

			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected validation failure for plaintext http mirror without explicit allow")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), "mirror_allow_insecure_http") {
				t.Errorf("error should mention the escape-hatch flag, got: %v", err)
			}
		})
	}
}

// TestLoadConfigCRSPinAndInsecureMirrorYAML 新字段 YAML 反序列化 + 缺省语义
func TestLoadConfigCRSPinAndInsecureMirrorYAML(t *testing.T) {
	data := `
server:
  port: 8080
waf:
  enabled: true
  default_mode: block
  crs:
    enabled: true
    version: "v4.19.0"
    download:
      mirror_url: "https://crsmirror.example.com"
      pinned_sha256: "d50377c6eb7ead1da83ad428ba941f6c768234fb139679cb0a26663a767326f4"
      mirror_allow_insecure_http: true
hosts:
  - name: example.com
    port: 8080
    backend: ["http://localhost:3000"]
    health_check_enabled: false
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(data), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.WAF.CRS.Download.PinnedSHA256 != "d50377c6eb7ead1da83ad428ba941f6c768234fb139679cb0a26663a767326f4" {
		t.Errorf("pinned_sha256 = %q", cfg.WAF.CRS.Download.PinnedSHA256)
	}
	if cfg.WAF.CRS.Download.MirrorAllowInsecureHTTP == nil || !*cfg.WAF.CRS.Download.MirrorAllowInsecureHTTP {
		t.Errorf("mirror_allow_insecure_http = %v, want true", cfg.WAF.CRS.Download.MirrorAllowInsecureHTTP)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("validate: %v", err)
	}

	// 缺省语义：未配置 → nil（false，仅 https）
	var def Config
	if err := yaml.Unmarshal([]byte("server:\n  port: 8080\n"), &def); err != nil {
		t.Fatalf("unmarshal default: %v", err)
	}
	if def.WAF.CRS.Download.GetEffectiveMirrorAllowInsecureHTTP() {
		t.Error("default mirror_allow_insecure_http must be false")
	}
	if def.WAF.CRS.Download.PinnedSHA256 != "" {
		t.Errorf("default pinned_sha256 = %q, want empty", def.WAF.CRS.Download.PinnedSHA256)
	}
}

// TestGetEffectivePinnedSHA256Normalization pin 归一化（H2）：去空白、容忍可选
// `sha256:` 前缀（与 GitHub Release digest 同款形态）、大小写归一；空值归一为空串
func TestGetEffectivePinnedSHA256Normalization(t *testing.T) {
	hex := strings.Repeat("d5", 32) // 64 位十六进制（小写）
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "", ""},
		{"whitespace only", "   \t ", ""},
		{"plain lowercase", hex, hex},
		{"plain uppercase normalized", strings.ToUpper(hex), hex},
		{"padded whitespace trimmed", "  " + hex + "\n", hex},
		{"sha256 prefix lower", "sha256:" + hex, hex},
		{"sha256 prefix upper normalized", "SHA256:" + strings.ToUpper(hex), hex},
		{"sha256 prefix with padding", "  sha256: " + hex + "  ", hex},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := WAFCRSDownloadConfig{PinnedSHA256: tt.raw}
			if got := d.GetEffectivePinnedSHA256(); got != tt.want {
				t.Errorf("GetEffectivePinnedSHA256(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// TestValidatePinnedSHA256FailFast pin 格式启动校验（H2）：合法形态（含前缀/大小写/
// 空白）与空值放行；非 64 位十六进制（过短/过长/含非 hex 字符）启动即拒绝且错误信息
// 指明配置路径——畸形 pin 若放行会在每次刷新的完整性校验处反复失败并耗尽下载预算
func TestValidatePinnedSHA256FailFast(t *testing.T) {
	hex := strings.Repeat("ab", 32)
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"empty ok", "", false},
		{"plain hex ok", hex, false},
		{"uppercase ok", strings.ToUpper(hex), false},
		{"sha256 prefix ok", "sha256:" + hex, false},
		{"padded ok", "  " + hex + " ", false},
		{"too short", strings.Repeat("ab", 31), true},
		{"too long", strings.Repeat("ab", 33), true},
		{"non-hex chars", strings.Repeat("zz", 32), true},
		{"prefix only", "sha256:", true},
		{"garbage", "not-a-hash", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePinnedSHA256(tt.raw)
			if tt.wantErr && err == nil {
				t.Errorf("validatePinnedSHA256(%q) should fail", tt.raw)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validatePinnedSHA256(%q) unexpected error: %v", tt.raw, err)
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), "pinned_sha256") {
				t.Errorf("error should mention the config path, got: %v", err)
			}
		})
	}

	// 端到端：畸形 pin 使 Config.Validate 整体失败
	cfg := newSelfHealTestConfig()
	cfg.WAF.CRS.Download.PinnedSHA256 = "digest-pasted-by-mistake"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "pinned_sha256") {
		t.Errorf("Config.Validate should reject malformed pin, got: %v", err)
	}
}
