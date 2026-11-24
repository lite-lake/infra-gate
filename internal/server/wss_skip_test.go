package server

// L3 websocket_insecure_skip per-host 化启动告警单测（内部PRD §7.1，
// 出口标准④）：全局字段非零启动 Warn（Deprecated + 全局 WSS 校验关闭）；
// per-host 显式 true 启动 Warn；per-host 显式 false（即便全局 true）不 Warn。
// 合并取值语义由 config.GetEffectiveWebSocketInsecureSkip 表驱动单测覆盖。

import (
	"strings"
	"testing"

	"github.com/lite-lake/infra-gate/internal/config"
)

// warnMsgContains 判断是否存在消息含指定子串的 Warn 日志
func warnMsgContains(r *blRecordLogger, sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rec := range r.records {
		if rec.level == "warn" && strings.Contains(rec.msg, sub) {
			return true
		}
	}
	return false
}

func wssWarnTestHost(name, backendURL string, perHost *bool) config.HostConfig {
	h := config.HostConfig{
		Name:               name,
		Port:               8080,
		Backend:            []string{backendURL},
		HealthCheckEnabled: boolPtr(false),
	}
	h.WebSocketInsecureSkip = perHost
	return h
}

// 全局 websocket_insecure_skip 非零：启动 Warn 一条（Deprecated + 全局生效提示），
// 未显式配置的 host 不产生 per-host Warn；显式 false 的 host 即便全局 true 也无 Warn
func TestWSSInsecureSkipGlobalWarn(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080, WebSocketInsecureSkip: true},
		Hosts: []config.HostConfig{
			wssWarnTestHost("inherit.test", backend.URL, nil),
			wssWarnTestHost("off.test", backend.URL, boolPtr(false)),
		},
	}
	rec := &blRecordLogger{}
	newBLServerWithLogger(t, cfg, rec)

	if !warnMsgContains(rec, "websocket_insecure_skip is DEPRECATED and ENABLED") {
		t.Errorf("global websocket_insecure_skip=true must produce a deprecation+enabled Warn at startup")
	}
	if rec.hasWarnWithField("host", "inherit.test") {
		t.Errorf("host without per-host override must not produce its own Warn (covered by global warn)")
	}
	if rec.hasWarnWithField("host", "off.test") {
		t.Errorf("per-host explicit false must not Warn (host has verification ON)")
	}
}

// per-host 显式 true：无论全局开没开，该 host 启动 Warn 一条
func TestWSSInsecureSkipPerHostWarn(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)

	tests := []struct {
		name   string
		global bool
	}{
		{"global off", false},
		{"global on", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				Server: config.ServerConfig{Port: 8080, WebSocketInsecureSkip: tc.global},
				Hosts: []config.HostConfig{
					wssWarnTestHost("on.test", backend.URL, boolPtr(true)),
					wssWarnTestHost("clean.test", backend.URL, nil),
				},
			}
			rec := &blRecordLogger{}
			newBLServerWithLogger(t, cfg, rec)

			if !rec.hasWarnWithField("host", "on.test") {
				t.Errorf("per-host web_socket_insecure_skip=true must produce a per-host Warn (global=%v)", tc.global)
			}
			if rec.hasWarnWithField("host", "clean.test") {
				t.Errorf("host without skip must not Warn")
			}
			if !tc.global && warnMsgContains(rec, "DEPRECATED") {
				t.Errorf("global field is false: no global deprecation Warn expected")
			}
		})
	}
}

// 全部关闭：零 Warn（缺省安全基线，无噪音）
func TestWSSInsecureSkipNoWarnWhenDisabled(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts: []config.HostConfig{
			wssWarnTestHost("plain.test", backend.URL, nil),
		},
	}
	rec := &blRecordLogger{}
	newBLServerWithLogger(t, cfg, rec)

	if warnMsgContains(rec, "websocket_insecure_skip") {
		t.Errorf("no WSS warn expected when global off and no per-host override")
	}
}
