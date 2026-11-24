package server

import (
	"slices"
	"testing"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/middleware"
)

// TestBuildDecompressPolicy 覆盖 415 事故修复的三条分支：
// WAF 未生效 → 未知编码透传；WAF 生效 + 关闭正文扫描 → aws-chunked 透传；
// 其余保持 F5 fail-close。
func TestBuildDecompressPolicy(t *testing.T) {
	tests := []struct {
		name            string
		host            *config.HostConfig
		globalWAF       config.WAFConfig
		wafActive       bool
		wantPassthrough bool
		wantAllowed     []string
	}{
		{
			name:            "waf inactive passes unknown encodings through",
			host:            &config.HostConfig{Name: "sc.litelake.cn"},
			globalWAF:       config.WAFConfig{Enabled: false},
			wafActive:       false,
			wantPassthrough: true,
		},
		{
			name:            "waf active + host body access disabled appends aws-chunked",
			host:            &config.HostConfig{Name: "sc.litelake.cn", WAF: &config.HostWAFOverride{RequestBodyAccess: boolPtr(false)}},
			globalWAF:       config.WAFConfig{Enabled: true},
			wafActive:       true,
			wantPassthrough: false,
			wantAllowed:     []string{middleware.ContentEncodingAWSChunked},
		},
		{
			name:            "waf active + global body access disabled appends aws-chunked",
			host:            &config.HostConfig{Name: "sc.litelake.cn"},
			globalWAF:       config.WAFConfig{Enabled: true, RequestBodyAccess: boolPtr(false)},
			wafActive:       true,
			wantPassthrough: false,
			wantAllowed:     []string{middleware.ContentEncodingAWSChunked},
		},
		{
			name:            "waf active + default body access keeps fail-close",
			host:            &config.HostConfig{Name: "app.example.com"},
			globalWAF:       config.WAFConfig{Enabled: true},
			wafActive:       true,
			wantPassthrough: false,
		},
		{
			name:            "waf active + host body access true overrides global false",
			host:            &config.HostConfig{Name: "app.example.com", WAF: &config.HostWAFOverride{RequestBodyAccess: boolPtr(true)}},
			globalWAF:       config.WAFConfig{Enabled: true, RequestBodyAccess: boolPtr(false)},
			wafActive:       true,
			wantPassthrough: false,
		},
		{
			name:            "existing allowlist preserved and extended",
			host:            &config.HostConfig{Name: "sc.litelake.cn", AllowedContentEncodings: []string{"br"}, WAF: &config.HostWAFOverride{RequestBodyAccess: boolPtr(false)}},
			globalWAF:       config.WAFConfig{Enabled: true},
			wafActive:       true,
			wantPassthrough: false,
			wantAllowed:     []string{"br", middleware.ContentEncodingAWSChunked},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildDecompressPolicy(tt.host, tt.globalWAF, tt.wafActive)
			if got.PassthroughUnknown != tt.wantPassthrough {
				t.Errorf("PassthroughUnknown = %v, want %v", got.PassthroughUnknown, tt.wantPassthrough)
			}
			if !slices.Equal(got.AllowedContentEncodings, tt.wantAllowed) {
				t.Errorf("AllowedContentEncodings = %v, want %v", got.AllowedContentEncodings, tt.wantAllowed)
			}
		})
	}
}
