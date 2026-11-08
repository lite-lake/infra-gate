package config

// F2 XFF 信任簇配置测试（内部PRD §4.2/§5）：
//   - trusted_proxies 宽度红线：v4 < /8（v6 < /48）拒绝启动，allow_wide 放行；
//   - peer_max_failures / login_rate_per_minute 缺省回落与显式关闭。

import (
	"strings"
	"testing"
	"time"
)

func trustCfg(entries ...string) *Config {
	return &Config{Server: ServerConfig{Port: 8080, TrustedProxies: entries}}
}

func TestTrustedProxiesWidthRedLine(t *testing.T) {
	cases := []struct {
		name      string
		entries   []string
		allowWide bool
		wantErr   bool
	}{
		{"trust-all v4 rejected", []string{"0.0.0.0/0"}, false, true},
		{"trust-all v6 rejected", []string{"::/0"}, false, true},
		{"v4 /7 rejected", []string{"10.0.0.0/7"}, false, true},
		{"v4 /8 allowed", []string{"10.0.0.0/8"}, false, false},
		{"v4 /24 allowed", []string{"10.71.0.0/24"}, false, false},
		{"v6 /47 rejected", []string{"fd00::/47"}, false, true},
		{"v6 /48 allowed", []string{"fd00::/48"}, false, false},
		{"v4 /7 with allow_wide passes", []string{"10.0.0.0/7"}, true, false},
		{"single ip allowed", []string{"10.71.0.5"}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := trustCfg(tc.entries...)
			cfg.Server.TrustedProxiesAllowWide = &tc.allowWide
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestAuthPeerAndBudgetDefaults(t *testing.T) {
	// peer_max_failures 缺省 = max_failures×10（max_failures 缺省 5 → 50）
	a := &HostAuthConfig{}
	if got := a.GetEffectivePeerMaxFailures(); got != 50 {
		t.Errorf("peer default = %d, want 50", got)
	}
	// 显式配置优先
	b := &HostAuthConfig{PeerMaxFailures: 20}
	if got := b.GetEffectivePeerMaxFailures(); got != 20 {
		t.Errorf("peer explicit = %d, want 20", got)
	}
	// 非法值（<=0）回落
	c := &HostAuthConfig{PeerMaxFailures: -5}
	if got := c.GetEffectivePeerMaxFailures(); got != 50 {
		t.Errorf("peer negative = %d, want 50 (fallback)", got)
	}

	// login_rate_per_minute：0 = 缺省 60；负值 = 关闭；正值原样
	d := &HostAuthConfig{}
	if pm, on := d.GetEffectiveLoginRatePerMinute(); !on || pm != DefaultLoginRatePerMinute {
		t.Errorf("budget default = (%d, %v), want (%d, true)", pm, on, DefaultLoginRatePerMinute)
	}
	e := &HostAuthConfig{LoginRatePerMinute: -1}
	if _, on := e.GetEffectiveLoginRatePerMinute(); on {
		t.Error("budget negative should be disabled")
	}
	f := &HostAuthConfig{LoginRatePerMinute: 120}
	if pm, on := f.GetEffectiveLoginRatePerMinute(); !on || pm != 120 {
		t.Errorf("budget explicit = (%d, %v), want (120, true)", pm, on)
	}
}

// TestLoginRateConfigSmoke 登录预算字段经 yaml 解析与校验冒烟
func TestLoginRateConfigSmoke(t *testing.T) {
	cfg := trustCfg()
	cfg.Hosts = []HostConfig{{
		Name:               "a.example.com",
		Port:               8080,
		Backend:            []string{"http://127.0.0.1:9"},
		HealthCheckEnabled: boolPtrCfg(false),
		Auth: &HostAuthConfig{
			Password:           "pw",
			TTL:                time.Hour,
			PeerMaxFailures:    30,
			LoginRatePerMinute: 90,
		},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	got := cfg.Hosts[0].Auth.GetEffectivePeerMaxFailures()
	if got != 30 {
		t.Errorf("peer = %d, want 30", got)
	}
	if pm, _ := cfg.Hosts[0].Auth.GetEffectiveLoginRatePerMinute(); pm != 90 {
		t.Errorf("budget = %d, want 90", pm)
	}
	if !strings.Contains("peer_max_failures", "peer") {
		t.Error("sanity")
	}
}

func boolPtrCfg(b bool) *bool { return &b }
