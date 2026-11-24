package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeShipperCfg 构造仅 tracker_shipper 不同的单 host 配置骨架
func makeShipperCfg(sh ShipperConfig) *Config {
	return &Config{
		Server:         ServerConfig{Port: 8080},
		Hosts:          []HostConfig{{Name: "example.com", Port: 8080, Backend: []string{"http://localhost:3000"}, HealthCheckEnabled: ptrBool(false)}},
		TrackerShipper: sh,
	}
}

func makeEnabledShipper() ShipperConfig {
	return ShipperConfig{
		Enabled:      true,
		Endpoint:     "https://app-tc-api.node1.v-dev.mesh.example.net/api/internal/gateway-ingest",
		SharedSecret: "s3cret",
		NodeName:     "yo-dev-gateway-node1",
	}
}

// --- Validate：enabled=true 时必填 fail-fast（内部PRD §7.1） ---

func TestValidateShipperEnabledRequiresFields(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(sh *ShipperConfig)
		errSubstr string
	}{
		{"missing endpoint", func(sh *ShipperConfig) { sh.Endpoint = "" }, "tracker_shipper.endpoint"},
		{"missing shared_secret", func(sh *ShipperConfig) { sh.SharedSecret = "" }, "tracker_shipper.shared_secret"},
		{"missing node_name", func(sh *ShipperConfig) { sh.NodeName = "" }, "tracker_shipper.node_name"},
		{"bad endpoint URL", func(sh *ShipperConfig) { sh.Endpoint = "not-a-url" }, "tracker_shipper.endpoint"},
		{"endpoint without scheme", func(sh *ShipperConfig) { sh.Endpoint = "app-tc-api.internal/api" }, "tracker_shipper.endpoint"},
		{"ratio above 1", func(sh *ShipperConfig) { sh.FailureSampleLogRatio = 1.5 }, "failure_sample_log_ratio"},
		{"ratio negative", func(sh *ShipperConfig) { sh.FailureSampleLogRatio = -0.1 }, "failure_sample_log_ratio"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sh := makeEnabledShipper()
			tt.mutate(&sh)
			err := makeShipperCfg(sh).Validate()
			if err == nil {
				t.Fatalf("enabled shipper with %s should fail validation", tt.name)
			}
			if !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("validation error = %q, want containing %q", err.Error(), tt.errSubstr)
			}
		})
	}
}

// TestValidateShipperDisabledZeroImpact 未配置/未启用时零影响（旧配置零变更）
func TestValidateShipperDisabledZeroImpact(t *testing.T) {
	// 零值段（旧配置文件无 tracker_shipper 段的等价形态）：全空也能过校验
	if err := makeShipperCfg(ShipperConfig{}).Validate(); err != nil {
		t.Errorf("zero-value tracker_shipper should pass validation, got: %v", err)
	}
	// enabled=false 但填了不合法值：不校验、不报错
	sh := ShipperConfig{Enabled: false, Endpoint: "not-a-url", FailureSampleLogRatio: 9}
	if err := makeShipperCfg(sh).Validate(); err != nil {
		t.Errorf("disabled shipper should skip validation, got: %v", err)
	}
}

// TestValidateShipperEnabledValid 合法 enabled 配置通过
func TestValidateShipperEnabledValid(t *testing.T) {
	if err := makeShipperCfg(makeEnabledShipper()).Validate(); err != nil {
		t.Errorf("valid enabled shipper should pass, got: %v", err)
	}
}

// --- WithDefaults：零值合并缺省（BufferSize 10000 / BatchSize 500 / 1s / 0.01） ---

func TestShipperWithDefaultsZeroValue(t *testing.T) {
	got := ShipperConfig{}.WithDefaults()
	if got.BufferSize != DefaultShipperBufferSize {
		t.Errorf("BufferSize = %d, want %d", got.BufferSize, DefaultShipperBufferSize)
	}
	if got.BatchSize != DefaultShipperBatchSize {
		t.Errorf("BatchSize = %d, want %d", got.BatchSize, DefaultShipperBatchSize)
	}
	if got.FlushInterval != DefaultShipperFlushInterval {
		t.Errorf("FlushInterval = %v, want %v", got.FlushInterval, DefaultShipperFlushInterval)
	}
	if got.FailureSampleLogRatio != DefaultShipperFailureSampleLogRatio {
		t.Errorf("FailureSampleLogRatio = %v, want %v", got.FailureSampleLogRatio, DefaultShipperFailureSampleLogRatio)
	}
	if got.Enabled {
		t.Error("WithDefaults must not flip Enabled")
	}
}

func TestShipperWithDefaultsPreservesExplicit(t *testing.T) {
	in := ShipperConfig{
		BufferSize:            20,
		BatchSize:             7,
		FlushInterval:         3 * time.Second,
		FailureSampleLogRatio: 0.5,
	}
	got := in.WithDefaults()
	if got.BufferSize != 20 || got.BatchSize != 7 || got.FlushInterval != 3*time.Second || got.FailureSampleLogRatio != 0.5 {
		t.Errorf("WithDefaults should preserve explicit values, got %+v", got)
	}
}

func TestShipperWithDefaultsNegativeFallback(t *testing.T) {
	got := ShipperConfig{BufferSize: -1, BatchSize: -5, FlushInterval: -time.Second, FailureSampleLogRatio: -1}.WithDefaults()
	if got.BufferSize != DefaultShipperBufferSize ||
		got.BatchSize != DefaultShipperBatchSize ||
		got.FlushInterval != DefaultShipperFlushInterval ||
		got.FailureSampleLogRatio != DefaultShipperFailureSampleLogRatio {
		t.Errorf("negative values should fall back to defaults, got %+v", got)
	}
}

// --- LoadConfig：tracker_shipper 段解析 + 旧配置零影响 ---

func TestLoadConfigTrackerShipperYAML(t *testing.T) {
	yamlContent := `
server:
  port: 8080
tracker_shipper:
  enabled: true
  endpoint: "https://app-tc-api.node1.v-dev.mesh.example.net/api/internal/gateway-ingest"
  shared_secret: "${TC_GATEWAY_INGEST_SECRET}"
  node_name: "yo-dev-gateway-node1"
  buffer_size: 2048
  batch_size: 100
  flush_interval: 2s
  failure_sample_log_ratio: 0.05
hosts:
  - name: example.com
    port: 8080
    backend:
      - http://localhost:3000
    health_check_enabled: false
`
	f := filepath.Join(t.TempDir(), "server.yml")
	if err := os.WriteFile(f, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(f)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	sh := cfg.TrackerShipper
	if !sh.Enabled {
		t.Error("tracker_shipper.enabled should be true")
	}
	if sh.Endpoint != "https://app-tc-api.node1.v-dev.mesh.example.net/api/internal/gateway-ingest" {
		t.Errorf("endpoint = %q", sh.Endpoint)
	}
	if sh.SharedSecret != "${TC_GATEWAY_INGEST_SECRET}" {
		t.Errorf("shared_secret = %q", sh.SharedSecret)
	}
	if sh.NodeName != "yo-dev-gateway-node1" {
		t.Errorf("node_name = %q", sh.NodeName)
	}
	if sh.BufferSize != 2048 {
		t.Errorf("buffer_size = %d, want 2048", sh.BufferSize)
	}
	if sh.BatchSize != 100 {
		t.Errorf("batch_size = %d, want 100", sh.BatchSize)
	}
	if sh.FlushInterval != 2*time.Second {
		t.Errorf("flush_interval = %v, want 2s", sh.FlushInterval)
	}
	if sh.FailureSampleLogRatio != 0.05 {
		t.Errorf("failure_sample_log_ratio = %v, want 0.05", sh.FailureSampleLogRatio)
	}
}

func TestLoadConfigWithoutTrackerShipperLegacyConfig(t *testing.T) {
	// 旧配置（无 tracker_shipper 段）：零值兼容，等价 enabled=false，加载/校验零影响
	yamlContent := `
server:
  port: 8080
hosts:
  - name: example.com
    port: 8080
    backend:
      - http://localhost:3000
    health_check_enabled: false
`
	f := filepath.Join(t.TempDir(), "server.yml")
	if err := os.WriteFile(f, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(f)
	if err != nil {
		t.Fatalf("legacy config must load unchanged: %v", err)
	}
	if cfg.TrackerShipper.Enabled {
		t.Error("legacy config should yield enabled=false")
	}
	if cfg.TrackerShipper != (ShipperConfig{}) {
		t.Errorf("legacy config should yield zero-value shipper config, got %+v", cfg.TrackerShipper)
	}
}

func TestLoadConfigTrackerShipperMissingRequiredFailsFast(t *testing.T) {
	// enabled=true 但缺必填 → LoadConfig 报错（fail-fast 仅作用于启用节点）
	yamlContent := `
server:
  port: 8080
tracker_shipper:
  enabled: true
hosts:
  - name: example.com
    port: 8080
    backend:
      - http://localhost:3000
    health_check_enabled: false
`
	f := filepath.Join(t.TempDir(), "server.yml")
	if err := os.WriteFile(f, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := LoadConfig(f)
	if err == nil {
		t.Fatal("enabled shipper without endpoint/secret/node_name should fail fast")
	}
	if !strings.Contains(err.Error(), "tracker_shipper") {
		t.Errorf("error should mention tracker_shipper, got: %v", err)
	}
}
