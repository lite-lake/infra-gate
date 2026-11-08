package blacklist

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// buildStoreFromText 便捷构建单源 Store（builtAt 交给 NewStore 补默认值）
func buildStoreFromText(name, content string, ignorePrivateIPs bool) *Store {
	// F9 适配：单条前缀围栏（缺省 /12、/24）会使 /12 以上的宽 CIDR 被跳过，
	// 本辅助服务于合并/保留段过滤等结构性测试，用宽容策略（围栏行为在
	// shape_fence_test.go 专测）
	return NewStoreWithPolicy([]SourceData{{Name: name, Data: []byte(content)}}, ignorePrivateIPs, time.Time{}, ContentPolicy{MinPrefixV4: 0, MinPrefixV6: 0})
}

func TestParseEntry(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		valid   bool
		isV4    bool
		isRange bool
	}{
		{"IPv4 single", "8.8.8.8", true, true, false},
		{"IPv4 single with spaces", "  8.8.8.8  ", true, true, false},
		{"IPv4 CIDR", "12.12.0.0/16", true, true, true},
		{"IPv6 single", "2001:4860:4860::8888", true, false, false},
		{"IPv6 CIDR", "2a00:1450:4001::/48", true, false, true},
		{"v4-mapped IPv6 single", "::ffff:8.8.8.8", true, true, false},
		{"v4-mapped IPv6 CIDR", "::ffff:12.12.0.0/112", true, true, true},
		{"empty", "", false, false, false},
		{"comment hash", "# comment", false, false, false},
		{"comment semicolon", "; comment", false, false, false},
		{"garbage", "not-an-ip", false, false, false},
		{"bad octet", "999.1.1.1", false, false, false},
		{"truncated", "1.2.3", false, false, false},
		{"bad prefix", "1.2.3.4/33", false, false, false},
		{"missing mask", "1.2.3.4/", false, false, false},
		{"html tag", "<html>error</html>", false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, ok := parseEntry(strings.TrimSpace(tt.line))
			if ok != tt.valid {
				t.Fatalf("parseEntry(%q) ok = %v, want %v", tt.line, ok, tt.valid)
			}
			if !ok {
				return
			}
			if entry.isV4 != tt.isV4 {
				t.Errorf("parseEntry(%q) isV4 = %v, want %v", tt.line, entry.isV4, tt.isV4)
			}
			if entry.isRange != tt.isRange {
				t.Errorf("parseEntry(%q) isRange = %v, want %v", tt.line, entry.isRange, tt.isRange)
			}
		})
	}
}

func TestNewStoreParsingAndCounting(t *testing.T) {
	content := `
# comment line
8.8.8.8
12.12.0.0/16
2001:4860:4860::8888
2a00:1450:4001::/48

not-an-ip
1.2.3.4/33
; another comment
45.60.1.2
`
	store := buildStoreFromText("test", content, false)

	if len(store.meta.Sources) != 1 {
		t.Fatalf("meta.Sources len = %d, want 1", len(store.meta.Sources))
	}
	sc := store.meta.Sources[0]
	if sc.Name != "test" {
		t.Errorf("source name = %q, want test", sc.Name)
	}
	if sc.Entries != 5 {
		t.Errorf("entries = %d, want 5 (2 v4 singles + 1 v4 CIDR + 1 v6 single + 1 v6 CIDR)", sc.Entries)
	}
	if sc.InvalidLines != 2 {
		t.Errorf("invalid_lines = %d, want 2", sc.InvalidLines)
	}
	if store.meta.TotalEntries != 5 {
		t.Errorf("total_entries = %d, want 5", store.meta.TotalEntries)
	}
	if store.meta.BuiltAt.IsZero() {
		t.Error("built_at should not be zero")
	}
	if len(store.v4Exact) != 2 {
		t.Errorf("v4Exact len = %d, want 2", len(store.v4Exact))
	}
	if len(store.v4Ranges) != 1 {
		t.Errorf("v4Ranges len = %d, want 1", len(store.v4Ranges))
	}
	if len(store.v6Exact) != 1 {
		t.Errorf("v6Exact len = %d, want 1", len(store.v6Exact))
	}
	if len(store.v6Ranges) != 1 {
		t.Errorf("v6Ranges len = %d, want 1", len(store.v6Ranges))
	}
}

func TestLookupV4SingleIP(t *testing.T) {
	store := buildStoreFromText("t", "8.8.8.8\n45.60.1.2\n", false)

	hit, matched := store.Lookup("8.8.8.8")
	if !hit || matched != "8.8.8.8" {
		t.Errorf("Lookup(8.8.8.8) = (%v, %q), want (true, \"8.8.8.8\")", hit, matched)
	}
	hit, matched = store.Lookup("8.8.8.9")
	if hit || matched != "" {
		t.Errorf("Lookup(8.8.8.9) = (%v, %q), want (false, \"\")", hit, matched)
	}
}

func TestLookupV4CIDRBorders(t *testing.T) {
	store := buildStoreFromText("t", "12.12.0.0/16\n", false)

	tests := []struct {
		ip   string
		hit  bool
		want string
	}{
		{"12.12.0.0", true, "12.12.0.0/16"},     // 网络地址（区间首）
		{"12.12.255.255", true, "12.12.0.0/16"}, // 广播地址（区间尾）
		{"12.12.5.5", true, "12.12.0.0/16"},
		{"12.11.255.255", false, ""}, // 区间前一个地址
		{"12.13.0.0", false, ""},     // 区间后一个地址
	}
	for _, tt := range tests {
		hit, matched := store.Lookup(tt.ip)
		if hit != tt.hit || matched != tt.want {
			t.Errorf("Lookup(%s) = (%v, %q), want (%v, %q)", tt.ip, hit, matched, tt.hit, tt.want)
		}
	}
}

func TestLookupV6(t *testing.T) {
	store := buildStoreFromText("t", "2001:4860:4860::8888\n2a00:1450:4001::/48\n", false)

	hit, matched := store.Lookup("2001:4860:4860::8888")
	if !hit || matched != "2001:4860:4860::8888" {
		t.Errorf("Lookup v6 single = (%v, %q), want (true, itself)", hit, matched)
	}

	tests := []struct {
		ip   string
		hit  bool
		want string
	}{
		{"2a00:1450:4001::", true, "2a00:1450:4001::/48"},      // 网络地址
		{"2a00:1450:4001:ffff::", true, "2a00:1450:4001::/48"}, // 段内末地址
		{"2a00:1450:4001::1", true, "2a00:1450:4001::/48"},
		{"2a00:1450:4002::1", false, ""}, // 段外
		{"2a00:1450:4000::", false, ""},
	}
	for _, tt := range tests {
		hit, matched := store.Lookup(tt.ip)
		if hit != tt.hit || matched != tt.want {
			t.Errorf("Lookup(%s) = (%v, %q), want (%v, %q)", tt.ip, hit, matched, tt.hit, tt.want)
		}
	}
}

func TestLookupV4MappedIPv6(t *testing.T) {
	store := buildStoreFromText("t", "8.8.8.8\n12.12.0.0/16\n", false)

	// v4-mapped IPv6 归一化后应命中 v4 结构
	hit, matched := store.Lookup("::ffff:8.8.8.8")
	if !hit {
		t.Error("Lookup(::ffff:8.8.8.8) should hit after To4 normalization")
	}
	if matched != "::ffff:8.8.8.8" {
		t.Errorf("matched = %q, want the queried IP string", matched)
	}
	hit, _ = store.Lookup("::ffff:12.12.5.5")
	if !hit {
		t.Error("Lookup(::ffff:12.12.5.5) should hit v4 CIDR range")
	}
	hit, _ = store.Lookup("::ffff:12.13.0.0")
	if hit {
		t.Error("Lookup(::ffff:12.13.0.0) should miss")
	}
}

func TestLookupInvalidAndMiss(t *testing.T) {
	store := buildStoreFromText("t", "8.8.8.0/24\n", false)

	for _, ip := range []string{"not-an-ip", "", "8.8.8", "9.9.9.9", "2001:db8::1"} {
		hit, matched := store.Lookup(ip)
		if hit || matched != "" {
			t.Errorf("Lookup(%q) = (%v, %q), want (false, \"\")", ip, hit, matched)
		}
	}
}

func TestRangeMerging(t *testing.T) {
	// 50.0.0.0/8、50.64.0.0/10（重叠）、51.0.0.0/8（相邻）应合并为单个区间
	// [50.0.0.0, 51.255.255.255]，且 source 保留第一个成分
	store := buildStoreFromText("t", "50.64.0.0/10\n50.0.0.0/8\n51.0.0.0/8\n91.0.0.0/8\n", false)

	if len(store.v4Ranges) != 2 {
		t.Fatalf("v4Ranges len = %d, want 2 (merged 50/51 + separate 91)", len(store.v4Ranges))
	}
	first := store.v4Ranges[0]
	if first.start != 50<<24 || first.end != (51<<24|0xFFFFFF) {
		t.Errorf("merged range = [%d, %d], want [50.0.0.0, 51.255.255.255]", first.start, first.end)
	}
	if first.source != "50.0.0.0/8" {
		// 排序后 50.0.0.0/8 的 start 最小，是合并簇的第一个成分
		t.Errorf("merged range source = %q, want first constituent 50.0.0.0/8", first.source)
	}

	// 不变量：区间两两不相交且 start 递增
	for i := 1; i < len(store.v4Ranges); i++ {
		prev, cur := store.v4Ranges[i-1], store.v4Ranges[i]
		if prev.start >= cur.start || prev.end >= cur.start {
			t.Errorf("range invariant violated: [%d,%d] then [%d,%d]", prev.start, prev.end, cur.start, cur.end)
		}
	}

	// 合并区间内的任意地址均可命中，且 matched 为第一个成分 CIDR
	hit, matched := store.Lookup("50.64.1.1")
	if !hit || matched != first.source {
		t.Errorf("Lookup(50.64.1.1) = (%v, %q), want (true, %q)", hit, matched, first.source)
	}
	hit, matched = store.Lookup("51.200.1.1")
	if !hit || matched != first.source {
		t.Errorf("Lookup(51.200.1.1) = (%v, %q), want (true, %q)", hit, matched, first.source)
	}
	hit, matched = store.Lookup("52.0.0.1")
	if hit {
		t.Errorf("Lookup(52.0.0.1) should miss, got matched %q", matched)
	}
	hit, _ = store.Lookup("91.1.1.1")
	if !hit {
		t.Error("Lookup(91.1.1.1) should hit 91.0.0.0/8")
	}
}

func TestReservedFiltering(t *testing.T) {
	content := strings.Join([]string{
		// 保留网段：应被过滤（不进表、不计非法行）
		"169.254.1.1", "10.1.2.3", "127.0.0.1", "100.64.0.1", "100.127.255.254",
		"192.168.1.1", "172.16.5.5", "0.0.0.1", "198.18.0.1", "203.0.113.9",
		"224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
		"169.254.0.0/16", "10.0.0.0/8", "100.64.0.0/10", "192.0.2.0/24",
		"::", "::1", "fe80::1", "fc00::1", "fd12::1", "ff02::1",
		"fc00::/7", "2001:db8::/32", "fe80::/10",
		// 公网条目：应保留
		"8.8.8.0/24", "45.60.1.2", "2a00:1450:4001::/48", "2001:4860:4860::8888",
	}, "\n")

	store := NewStore([]SourceData{{Name: "t", Data: []byte(content)}}, true, time.Time{})

	// 保留网段不进表
	for _, ip := range []string{
		"169.254.1.1", "10.1.2.3", "127.0.0.1", "100.64.0.1",
		"192.168.1.1", "0.0.0.1", "198.18.0.1", "203.0.113.9",
		"224.0.0.1", "255.255.255.255",
		"::", "::1", "fe80::1", "fc00::1", "ff02::1", "2001:db8::5",
	} {
		if hit, _ := store.Lookup(ip); hit {
			t.Errorf("Lookup(%s) should miss (reserved, filtered)", ip)
		}
	}
	// 保留 CIDR 整条丢弃：其内部任意地址不命中
	for _, ip := range []string{"169.254.100.1", "10.200.1.1", "100.100.1.1", "fd99::1"} {
		if hit, _ := store.Lookup(ip); hit {
			t.Errorf("Lookup(%s) should miss (reserved CIDR dropped)", ip)
		}
	}

	// 公网条目保留
	if hit, matched := store.Lookup("8.8.8.8"); !hit || matched != "8.8.8.0/24" {
		t.Errorf("Lookup(8.8.8.8) = (%v, %q), want (true, \"8.8.8.0/24\")", hit, matched)
	}
	if hit, _ := store.Lookup("45.60.1.2"); !hit {
		t.Error("Lookup(45.60.1.2) should hit")
	}
	if hit, matched := store.Lookup("2a00:1450:4001::9"); !hit || matched != "2a00:1450:4001::/48" {
		t.Errorf("Lookup(2a00:1450:4001::9) = (%v, %q), want hit with CIDR source", hit, matched)
	}
	if hit, _ := store.Lookup("2001:4860:4860::8888"); !hit {
		t.Error("Lookup(2001:4860:4860::8888) should hit")
	}

	// 保留条目被过滤而非计为非法行
	sc := store.meta.Sources[0]
	if sc.InvalidLines != 0 {
		t.Errorf("invalid_lines = %d, want 0 (reserved entries are filtered, not invalid)", sc.InvalidLines)
	}
	if sc.Entries != 4 {
		t.Errorf("entries = %d, want 4 (public entries only)", sc.Entries)
	}
}

func TestReservedFilteringPartialCIDRKept(t *testing.T) {
	// 部分跨界 CIDR：10.0.0.0/7 的 start（10.0.0.0）在保留段而 end（11.255.255.255）
	// 覆盖公网 11.0.0.0/8，按设计整条保守保留
	store := buildStoreFromText("t", "10.0.0.0/7\n", true)

	if hit, _ := store.Lookup("11.1.2.3"); !hit {
		t.Error("Lookup(11.1.2.3) should hit (partially-reserved CIDR kept)")
	}
	if hit, _ := store.Lookup("9.9.9.9"); hit {
		t.Error("Lookup(9.9.9.9) should miss")
	}
	// 保守保留的副作用：区间内的保留地址（10.x）同样命中——文档化行为
	if hit, _ := store.Lookup("10.5.5.5"); !hit {
		t.Error("Lookup(10.5.5.5) should hit (whole kept range is effective)")
	}
}

func TestMultiSourceMerge(t *testing.T) {
	store := NewStore([]SourceData{
		{Name: "a", Data: []byte("8.8.8.8\n8.8.8.8\n")}, // 重复行去重后计 2 条
		{Name: "b", Data: []byte("12.12.0.0/16\nnot-an-ip\n")},
	}, false, time.Time{})

	if len(store.meta.Sources) != 2 {
		t.Fatalf("meta.Sources len = %d, want 2", len(store.meta.Sources))
	}
	if store.meta.Sources[0].Entries != 2 {
		t.Errorf("source a entries = %d, want 2", store.meta.Sources[0].Entries)
	}
	if store.meta.Sources[1].Entries != 1 || store.meta.Sources[1].InvalidLines != 1 {
		t.Errorf("source b = (entries %d, invalid %d), want (1, 1)", store.meta.Sources[1].Entries, store.meta.Sources[1].InvalidLines)
	}
	if store.meta.TotalEntries != 3 {
		t.Errorf("total_entries = %d, want 3", store.meta.TotalEntries)
	}
	// 去重口径：源内重复的 8.8.8.8 只算 1 条（v4Exact 1 + v4Ranges 1）
	if store.meta.DistinctEntries != 2 {
		t.Errorf("distinct_entries = %d, want 2 (deduplicated store size)", store.meta.DistinctEntries)
	}
}

// TestDistinctEntriesCountsDeduplicated 大量重复行时 TotalEntries（行数口径）与
// DistinctEntries（去重口径）必须显著区分：防污染判定基于后者，行数口径仅用于展示。
func TestDistinctEntriesCountsDeduplicated(t *testing.T) {
	store := buildStoreFromText("t", strings.Repeat("8.8.8.8\n9.9.9.9\n", 1000), false)

	if store.meta.TotalEntries != 2000 {
		t.Errorf("total_entries = %d, want 2000 (line-count semantics)", store.meta.TotalEntries)
	}
	if store.meta.DistinctEntries != 2 {
		t.Errorf("distinct_entries = %d, want 2 (deduplicated semantics)", store.meta.DistinctEntries)
	}
}

// TestBinarySearchAgainstLinearScan 随机生成区间（含重叠）与随机查询点，
// Lookup 结果必须与逐条 net.IPNet.Contains 线性扫描全等（多个随机种子）。
func TestBinarySearchAgainstLinearScan(t *testing.T) {
	for _, seed := range []int64{1, 7, 42, 20260909} {
		rng := rand.New(rand.NewSource(seed))

		var lines []string
		var nets []*net.IPNet
		var singles []net.IP

		// 随机 CIDR（前缀 8..32，随机起点天然产生大量重叠）
		for i := 0; i < 300; i++ {
			prefix := 8 + rng.Intn(25)
			start := rng.Uint32()
			mask := net.CIDRMask(prefix, 32)
			ip := net.IPv4(byte(start>>24), byte(start>>16), byte(start>>8), byte(start)).Mask(mask)
			cidr := ip.String() + "/" + strconv.Itoa(prefix)
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatalf("generated CIDR %q invalid: %v", cidr, err)
			}
			lines = append(lines, cidr)
			nets = append(nets, ipnet)
		}
		// 随机单 IP
		for i := 0; i < 200; i++ {
			v := rng.Uint32()
			ip := net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
			lines = append(lines, ip.String())
			singles = append(singles, ip)
		}

		// F9 适配：随机生成含宽前缀 CIDR，用宽容策略构建（结构性对照测试)
		store := NewStoreWithPolicy([]SourceData{{Name: "rand", Data: []byte(strings.Join(lines, "\n"))}}, false, time.Time{}, ContentPolicy{})

		check := func(query string) {
			qip := net.ParseIP(query)
			if qip == nil {
				t.Fatalf("query %q is not an IP", query)
			}
			expected := false
			for _, s := range singles {
				if s.Equal(qip) {
					expected = true
					break
				}
			}
			if !expected {
				for _, n := range nets {
					if n.Contains(qip) {
						expected = true
						break
					}
				}
			}
			got, matched := store.Lookup(query)
			if got != expected {
				t.Fatalf("seed %d: Lookup(%s) = %v, want %v (linear scan)", seed, query, got, expected)
			}
			if got && matched == "" {
				t.Fatalf("seed %d: Lookup(%s) hit but matched is empty", seed, query)
			}
		}

		// 随机查询点
		for i := 0; i < 2000; i++ {
			v := rng.Uint32()
			check(net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String())
		}
		// 区间边界查询（网络地址/广播地址/前后邻地址）
		for i := 0; i < len(nets) && i < 50; i++ {
			n := nets[i]
			base := uint32(n.IP[0])<<24 | uint32(n.IP[1])<<16 | uint32(n.IP[2])<<8 | uint32(n.IP[3])
			mask := uint32(n.Mask[0])<<24 | uint32(n.Mask[1])<<16 | uint32(n.Mask[2])<<8 | uint32(n.Mask[3])
			end := base | ^mask
			for _, v := range []uint32{base, end} {
				check(u32ToIPString(v))
			}
			if base > 0 {
				check(u32ToIPString(base - 1))
			}
			if end < 0xFFFFFFFF {
				check(u32ToIPString(end + 1))
			}
		}
		// v4-mapped 归一化抽查
		for i := 0; i < 20; i++ {
			v := rng.Uint32()
			check(fmt.Sprintf("::ffff:%s", u32ToIPString(v)))
		}
	}
}

func u32ToIPString(v uint32) string {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
}
