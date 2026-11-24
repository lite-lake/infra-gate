package config

// M3/L3 配置 getter 单测（内部PRD §5/§7.1，出口标准③④）：
// max_failures / lock_duration 的 <=0 缺省回落；per-host web_socket_insecure_skip 的
// nil 继承全局、显式配置优先。

import (
	"testing"
	"time"
)

// max_failures / lock_duration：<=0（零值未配置或负值）回落缺省 5 次 / 15 分钟，
// 正值原样生效
func TestGetEffectiveMaxFailuresAndLockDuration(t *testing.T) {
	tests := []struct {
		name        string
		maxFailures int
		lock        time.Duration
		wantMax     int
		wantLock    time.Duration
	}{
		{"zero values fall back to defaults", 0, 0, DefaultAuthMaxFailures, DefaultAuthLockDuration},
		{"negative values fall back to defaults", -1, -time.Hour, DefaultAuthMaxFailures, DefaultAuthLockDuration},
		{"custom values pass through", 10, time.Hour, 10, time.Hour},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := &HostAuthConfig{Password: "x", MaxFailures: tc.maxFailures, LockDuration: tc.lock}
			if got := a.GetEffectiveMaxFailures(); got != tc.wantMax {
				t.Errorf("GetEffectiveMaxFailures(%d) = %d, want %d", tc.maxFailures, got, tc.wantMax)
			}
			if got := a.GetEffectiveLockDuration(); got != tc.wantLock {
				t.Errorf("GetEffectiveLockDuration(%v) = %v, want %v", tc.lock, got, tc.wantLock)
			}
		})
	}
	if DefaultAuthMaxFailures != 5 {
		t.Errorf("DefaultAuthMaxFailures = %d, want 5 (与既有现值一致，PRD §5)", DefaultAuthMaxFailures)
	}
	if DefaultAuthLockDuration != 15*time.Minute {
		t.Errorf("DefaultAuthLockDuration = %v, want 15m", DefaultAuthLockDuration)
	}
}

// per-host web_socket_insecure_skip 合并语义（L3）：nil 继承全局；显式配置优先于全局
// （两处同配 per-host 赢）
func TestGetEffectiveWebSocketInsecureSkip(t *testing.T) {
	per := func(v bool) *bool { return &v }
	tests := []struct {
		name    string
		perHost *bool
		global  bool
		want    bool
	}{
		{"nil inherits global false", nil, false, false},
		{"nil inherits global true", nil, true, true},
		{"explicit true overrides global false", per(true), false, true},
		{"explicit false overrides global true", per(false), true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &HostConfig{Name: "a.test", WebSocketInsecureSkip: tc.perHost}
			if got := h.GetEffectiveWebSocketInsecureSkip(tc.global); got != tc.want {
				t.Errorf("GetEffectiveWebSocketInsecureSkip(perHost=%v, global=%v) = %v, want %v",
					tc.perHost, tc.global, got, tc.want)
			}
		})
	}
}
