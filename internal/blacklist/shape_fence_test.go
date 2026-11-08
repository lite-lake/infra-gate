package blacklist

// F9 黑名单形态围栏测试（内部PRD §4.9/§11 F9）：
// /12 收录、/11 跳过计数；聚合覆盖率（1.0.0.0/8 拒表保旧、重叠只算一次）；
// v6 条目超限拒；v6 区间二分 Lookup 回归；min_entries 可配；缓存 mtime 判龄。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

func TestContentPolicyPrefixFence(t *testing.T) {
	// /12 收录、/11 跳过计数（实测 USTC feed 含 3 条 /12 合法条目）
	data := SourceData{Name: "fence", Data: []byte(strings.Join([]string{
		"1.0.0.0/12",  // 合法最粗档：收录
		"1.32.0.0/11", // 超限：跳过 + 计数
		"1.64.0.0/10", // 超限：跳过 + 计数
		"9.9.9.9",     // 单 IP 不受围栏
	}, "\n"))}
	s := NewStoreWithPolicy([]SourceData{data}, false, time.Now(), DefaultContentPolicy())
	if len(s.v4Ranges) != 1 {
		t.Errorf("v4Ranges = %d, want 1 (only /12 kept)", len(s.v4Ranges))
	}
	if got := s.meta.Sources[0].OversizedLines; got != 2 {
		t.Errorf("OversizedLines = %d, want 2", got)
	}
	if s.meta.OversizedLinesTotal != 2 {
		t.Errorf("OversizedLinesTotal = %d, want 2", s.meta.OversizedLinesTotal)
	}
	// 单 IP 正常收录
	if _, ok := s.v4Exact[0x09090909]; !ok {
		t.Error("single IP should be kept")
	}
}

func TestV4CoverageCountedOnce(t *testing.T) {
	// 重叠 CIDR 覆盖只算一次：1.0.0.0/12 与 1.0.0.0/14 完全内含
	data := SourceData{Name: "overlap", Data: []byte("1.0.0.0/12\n1.0.0.0/14\n1.0.64.0/18\n")}
	s := NewStoreWithPolicy([]SourceData{data}, false, time.Now(), DefaultContentPolicy())
	// 1.0.0.0/12 覆盖 [1.0.0.0, 1.15.255.255]；/14 与 /18 均在内 → 合并为 1 个区间
	want := uint64(0x1_0f_ffff - 0x1_00_0000 + 1) // 1.0.0.0 ~ 1.15.255.255
	if s.meta.CoveredV4Addrs != want {
		t.Errorf("CoveredV4Addrs = %d, want %d (overlap counted once)", s.meta.CoveredV4Addrs, want)
	}
	if len(s.v4Ranges) != 1 {
		t.Errorf("v4Ranges = %d, want 1 (merged)", len(s.v4Ranges))
	}
}

func TestRefreshRejectsCoveragePoisoning(t *testing.T) {
	// 投毒 1.0.0.0/8（coverage ≈ 0.39%... 用 /1 达 50%）→ 拒表保旧
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 1 {
			// 首刷：正常表（min_entries=10，去重口径需 ≥10 个独立 IP）
			lines := make([]string, 0, 12)
			for i := 0; i < 11; i++ {
				lines = append(lines, "2.3.4."+itoa10(i))
			}
			w.Write([]byte(strings.Join(lines, "\n")))
			return
		}
		// 第二轮：投毒 /1（覆盖 50%）
		w.Write([]byte("0.0.0.0/1\n2.3.4.4\n2.3.4.5\n"))
	}))
	defer srv.Close()

	m := NewManager(config.BlacklistConfig{
		Enabled: true,
		Sources: []config.BlacklistSourceConfig{{Name: "poison", URL: srv.URL}},
		// F9.5：min_entries 可配（小 feed 测试）
		MinEntries: intPtrYaml(10),
	}, logger.GetDefaultLogger())
	m.cacheDir = t.TempDir()

	m.refresh()
	if got := m.currentDistinctEntries(); got < 2 {
		t.Fatalf("first refresh entries = %d, want >= 2", got)
	}
	prev := m.currentDistinctEntries()

	m.refresh() // 投毒轮
	if got := m.currentDistinctEntries(); got != prev {
		t.Errorf("poisoned refresh must be rejected (entries %d -> %d)", prev, got)
	}
	if hit, _ := m.Lookup("2.3.4.4"); !hit {
		t.Error("old table must still serve after rejection")
	}
}

func TestRefreshRejectsV6Flood(t *testing.T) {
	// v6 CIDR 洪泛（> max_v6_cidr_entries）→ 拒表
	var round int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		round++
		if round == 1 {
			w.Write([]byte("2606:4700:1::/48\n2606:4700:aa::/48\n2.3.4.4\n"))
			return
		}
		lines := make([]string, 0, 1200)
		for i := 0; i < 1100; i++ {
			lines = append(lines, "2606:4700:"+toHex(i)+"::/48")
		}
		lines = append(lines, "2.3.4.4")
		w.Write([]byte(strings.Join(lines, "\n")))
	}))
	defer srv.Close()

	m := NewManager(config.BlacklistConfig{
		Enabled:    true,
		Sources:    []config.BlacklistSourceConfig{{Name: "v6flood", URL: srv.URL}},
		MinEntries: intPtrYaml(3),
	}, logger.GetDefaultLogger())
	m.cacheDir = t.TempDir()

	m.refresh()
	prev := m.currentDistinctEntries()
	if prev == 0 {
		t.Fatal("first refresh should succeed")
	}
	m.refresh()
	if got := m.currentDistinctEntries(); got != prev {
		t.Errorf("v6 flood refresh must be rejected (entries %d -> %d)", prev, got)
	}
	if hit, _ := m.Lookup("2606:4700:1::1"); !hit {
		t.Error("old table v6 lookup must still work")
	}
}

func TestV6RangeLookupBinarySearch(t *testing.T) {
	// v6 区间二分回归：跨区间命中/未命中/区间边界
	data := SourceData{Name: "v6", Data: []byte(strings.Join([]string{
		"2606:4700:1::/48",
		"2606:4700:2::/48",
		"2606:4700:3::/48",
		"2606:4700:aa::/48",
	}, "\n"))}
	s := NewStoreWithPolicy([]SourceData{data}, false, time.Now(), DefaultContentPolicy())
	// 1/2/3 三个 /48 相邻 → 合一；aa 独立 → 共 2 个区间（合并语义）
	if len(s.v6Ranges) != 2 {
		t.Fatalf("v6Ranges = %d, want 2 (adjacent /48s merged)", len(s.v6Ranges))
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"2606:4700:1::1", true},
		{"2606:4700:1:ffff:ffff:ffff:ffff:ffff", true}, // /48 边界内
		{"2606:4700:2::dead", true},
		{"2606:4700:aa::", true},
		{"2606:4700:4::", false}, // 空洞
		{"2606:4700:0::", false},
		{"2606:4700:ab::", false},
	}
	for _, c := range cases {
		if hit, _ := s.Lookup(c.ip); hit != c.want {
			t.Errorf("Lookup(%s) = %v, want %v", c.ip, hit, c.want)
		}
	}
}

func TestCacheTTLByMtime(t *testing.T) {
	// 缓存 mtime 超龄 → 忽略 + 不发布
	dir := t.TempDir()
	m := NewManager(config.BlacklistConfig{
		Enabled:    true,
		Sources:    []config.BlacklistSourceConfig{{Name: "stale", URL: "https://feed.example.com/list"}},
		MinEntries: intPtrYaml(3),
	}, logger.GetDefaultLogger())
	m.cacheDir = dir

	// 手工写一份「超龄」缓存
	payload := []byte(cacheURLHeader("https://feed.example.com/list") + "1.2.3.4\n1.2.3.5\n1.2.3.6\n")
	path := filepath.Join(dir, cacheFileName("stale"))
	if err := os.WriteFile(path, payload, 0644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-73 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	m.loadCache()
	if m.currentDistinctEntries() != 0 {
		t.Error("cache older than cache_ttl (72h default) must be ignored")
	}

	// 对照：新鲜缓存被接受
	fresh := time.Now()
	if err := os.Chtimes(path, fresh, fresh); err != nil {
		t.Fatal(err)
	}
	m.loadCache()
	if m.currentDistinctEntries() != 3 {
		t.Errorf("fresh cache entries = %d, want 3", m.currentDistinctEntries())
	}
}

func TestMinEntriesExplicitZeroDisables(t *testing.T) {
	// 显式 0 = 禁用下限：3 条小 feed 被接受
	var round int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		round++
		w.Write([]byte("3.3.3.3\n3.3.3.4\n"))
	}))
	defer srv.Close()
	m := NewManager(config.BlacklistConfig{
		Enabled:    true,
		Sources:    []config.BlacklistSourceConfig{{Name: "small", URL: srv.URL}},
		MinEntries: intPtrYaml(0),
	}, logger.GetDefaultLogger())
	m.cacheDir = t.TempDir()
	m.refresh()
	if got := m.currentDistinctEntries(); got != 2 {
		t.Errorf("small feed with min_entries=0: entries = %d, want 2", got)
	}
	_ = round
}

func TestBlacklistF9ConfigDefaults(t *testing.T) {
	// YAML 解析 + 缺省回落
	var c config.BlacklistConfig
	yaml.Unmarshal([]byte(`
min_entries: 0
cidr_min_prefix_v4: 10
cidr_min_prefix_v6: 20
max_v4_coverage_percent: 5.0
max_v6_cidr_entries: 500
cache_ttl: 24h
staleness_threshold: 3h
`), &c)
	if min, enabled := c.GetEffectiveMinEntries(); enabled || min != 0 {
		t.Errorf("explicit 0 should disable, got (%d, %v)", min, enabled)
	}
	if c.GetEffectiveCIDRMinPrefixV4() != 10 || c.GetEffectiveCIDRMinPrefixV6() != 20 {
		t.Errorf("prefix overrides not applied")
	}
	if c.GetEffectiveMaxV4CoveragePercent() != 5.0 {
		t.Errorf("coverage override not applied")
	}
	if c.GetEffectiveMaxV6CIDREntries() != 500 {
		t.Errorf("v6 entries override not applied")
	}
	if c.GetEffectiveCacheTTL() != 24*time.Hour || c.GetEffectiveStalenessThreshold() != 3*time.Hour {
		t.Errorf("duration overrides not applied")
	}

	// 零值 → 缺省
	var zero config.BlacklistConfig
	if v := zero.GetEffectiveCIDRMinPrefixV4(); v != 12 {
		t.Errorf("default prefix v4 = %d, want 12", v)
	}
	if v := zero.GetEffectiveCIDRMinPrefixV6(); v != 24 {
		t.Errorf("default prefix v6 = %d, want 24", v)
	}
	if v := zero.GetEffectiveMaxV4CoveragePercent(); v != 2.0 {
		t.Errorf("default coverage = %v, want 2.0", v)
	}
	if v := zero.GetEffectiveMaxV6CIDREntries(); v != 1000 {
		t.Errorf("default v6 entries = %d, want 1000", v)
	}
	if v := zero.GetEffectiveCacheTTL(); v != 72*time.Hour {
		t.Errorf("default cache ttl = %v, want 72h", v)
	}
	if v := zero.GetEffectiveStalenessThreshold(); v != 6*time.Hour {
		t.Errorf("default staleness = %v, want 6h", v)
	}
	if min, enabled := zero.GetEffectiveMinEntries(); !enabled || min != 1000 {
		t.Errorf("nil min_entries = (%d, %v), want (1000, true)", min, enabled)
	}
}

func intPtrYaml(v int) *int { return &v }

func toHex(i int) string {
	const hexdigits = "0123456789abcdef"
	if i < 16 {
		return string(hexdigits[i])
	}
	return toHex(i/16) + string(hexdigits[i%16])
}
func itoa10(i int) string {
	return strconv.Itoa(i)
}
