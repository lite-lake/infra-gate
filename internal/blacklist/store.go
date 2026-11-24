// Package blacklist 提供基于外部威胁情报（如 USTC blackip）的 IP 黑名单能力：
// 定时同步全量列表到本地内存，请求热路径上做微秒级本地查询，不引入任何按请求的第三方调用。
//
// 并发模式：Store 一经构建不可变，读侧无锁；写侧由 fetcher 单 goroutine 通过
// atomic.Pointer 整体换新，禁止原地修改（PRD §9/§16.2）。
package blacklist

import (
	"encoding/binary"
	"math"
	"net"
	"sort"
	"strings"
	"time"
)

// ipv4Range 表示一个 IPv4 地址区间 [start, end]（闭区间，uint32 网络字节序）。
// source 为构建该区间的来源 CIDR 字符串（用于命中回报）；区间合并后保留第一个成分的 source。
type ipv4Range struct {
	start  uint32
	end    uint32
	source string
}

// ipv6Range IPv6 CIDR 展开的 128 位闭区间 [lo, hi]（大端 [2]uint64）。
// F9.3（内部PRD §4.9.3，D9）：v6 CIDR 由线性扫描 []ipv6Net 升级为
// 排序区间数组 + 二分（复用 v4 merge + 二分模式，Lookup O(log n)；
// 不引入基数树外部依赖）。source 为构建该区间的来源 CIDR 字符串。
type ipv6Range struct {
	lo, hi [2]uint64
	source string
}

// v6RangeCompare 128 位字典序比较（先高 64 位后低 64 位）
func v6RangeCompare(a, b [2]uint64) int {
	if a[0] != b[0] {
		if a[0] < b[0] {
			return -1
		}
		return 1
	}
	if a[1] != b[1] {
		if a[1] < b[1] {
			return -1
		}
		return 1
	}
	return 0
}

// v6RangeAdd1 128 位加一
func v6RangeAdd1(v [2]uint64) [2]uint64 {
	if v[1] == math.MaxUint64 {
		return [2]uint64{v[0] + 1, 0}
	}
	return [2]uint64{v[0], v[1] + 1}
}

// mergeV6Ranges 按 lo 排序并合并重叠/相邻区间（结果两两不相交且 hi 递增）
func mergeV6Ranges(ranges []ipv6Range) []ipv6Range {
	if len(ranges) == 0 {
		return nil
	}
	sort.SliceStable(ranges, func(i, j int) bool { return v6RangeCompare(ranges[i].lo, ranges[j].lo) < 0 })
	merged := make([]ipv6Range, 0, len(ranges))
	for _, r := range ranges {
		if n := len(merged); n > 0 {
			last := &merged[n-1]
			// 重叠（r.lo <= last.hi）或相邻（r.lo == last.hi+1）
			if v6RangeCompare(r.lo, last.hi) <= 0 || (v6RangeCompare(r.lo, v6RangeAdd1(last.hi)) == 0) {
				if v6RangeCompare(r.hi, last.hi) > 0 {
					last.hi = r.hi
				}
				continue
			}
		}
		merged = append(merged, r)
	}
	return merged
}

// findV6Range 二分查找 key 所在区间（候选为 lo <= key 的最大区间）
func findV6Range(ranges []ipv6Range, key [2]uint64) *ipv6Range {
	lo, hi := 0, len(ranges)-1
	idx := -1
	for lo <= hi {
		mid := int(uint(lo+hi) >> 1)
		if v6RangeCompare(ranges[mid].lo, key) <= 0 {
			idx = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if idx >= 0 && v6RangeCompare(key, ranges[idx].hi) <= 0 {
		return &ranges[idx]
	}
	return nil
}

// ContentPolicy F9 形态围栏（内部PRD §4.9.1）：单条 CIDR 前缀下限。
// 超限跳过 + OversizedLines 计数（不拒整表——实测合法 feed 含 3 条 /12，
// 更严会当天误杀；单条 /12 独立伤害上限 0.024%，兜底交给聚合覆盖率阈值）
type ContentPolicy struct {
	MinPrefixV4 int
	MinPrefixV6 int
}

// DefaultContentPolicy 缺省围栏（/12、/24）
func DefaultContentPolicy() ContentPolicy {
	return ContentPolicy{MinPrefixV4: 12, MinPrefixV6: 24}
}

// SourceCount 单个数据源在 Store 中的条目统计
type SourceCount struct {
	Name           string `json:"name"`
	Entries        int    `json:"entries"`         // 有效条目数（保留网段过滤后）
	InvalidLines   int    `json:"invalid_lines"`   // 无法解析的行数
	OversizedLines int    `json:"oversized_lines"` // F9.1：单条前缀超限被跳过的行数
}

// StoreMeta Store 元信息
type StoreMeta struct {
	Sources []SourceCount `json:"sources"`
	// TotalEntries 各来源有效条目（解析成功行数）之和，含重复行。对外展示口径
	// （PRD §11.1 示例 14255 语义），不用于防污染判定。
	TotalEntries int `json:"total_entries"`
	// DistinctEntries Store 去重后的条目数（len(v4Exact)+len(v4Ranges)+len(v6Exact)+len(v6Nets)）。
	// 防污染（minEntries/shrinkRatio）判定口径：上游返回大量重复行时行数口径会虚高，
	// 无法反映真实表规模。
	DistinctEntries int `json:"distinct_entries"`
	// CoveredV4Addrs F9.2：合并后 v4Ranges 覆盖的 IPv4 地址总数（重叠只算一次，
	// 防「多条小段拼大段」绕过覆盖率阈值）；V4CoveragePercent = 占 2^32 比例
	CoveredV4Addrs      uint64    `json:"covered_v4_addrs"`
	V4CoveragePercent   float64   `json:"v4_coverage_percent"`
	V6CIDREntries       int       `json:"v6_cidr_entries"` // 合并后 v6 区间数
	OversizedLinesTotal int       `json:"oversized_lines_total"`
	BuiltAt             time.Time `json:"built_at"`

	// 以下为运行期状态元信息：由 Manager 在发布 Store 前填充（NewStore 不设置），
	// 随 Store 一起原子换新；GetStats 从同一次原子加载的 Store 读取，保证快照一致。
	LastAttemptAt   time.Time `json:"last_attempt_at,omitempty"`   // 最近一次刷新尝试时间
	LastSuccessAt   time.Time `json:"last_success_at,omitempty"`   // 最近一次成功刷新时间
	LoadedFromCache bool      `json:"loaded_from_cache,omitempty"` // 当前表是否来自磁盘缓存
}

// Store 不可变内存黑名单存储（性能关键：热路径上每个正常请求都是未命中）。
// IPv4 单 IP 走 map O(1)；IPv4 CIDR 合并为排序区间数组后二分 O(log n)；
// IPv6 单 IP 走 [16]byte map O(1)；IPv6 CIDR 数量极少，线性扫描。
type Store struct {
	v4Exact  map[uint32]struct{} // IPv4 单 IP：O(1) 哈希
	v4Ranges []ipv4Range         // IPv4 CIDR → uint32 [start,end] 排序且两两不相交的区间数组
	v6Exact  map[[16]byte]struct{}
	v6Ranges []ipv6Range // F9.3：v6 CIDR → 128 位排序区间数组（二分 O(log n)）
	meta     StoreMeta
}

// SourceData 一个数据源的原始文本内容（纯文本，每行一条 IP 或 CIDR）
type SourceData struct {
	Name string
	Data []byte
}

// parsedEntry 一行文本解析出的条目
type parsedEntry struct {
	isV4     bool
	isRange  bool
	v4       uint32    // IPv4 单 IP
	v4r      ipv4Range // IPv4 CIDR 区间
	v6       [16]byte  // IPv6 单 IP
	v6r      ipv6Range // IPv6 CIDR 128 位区间
	prefixV4 int       // F9.1：CIDR 前缀位数（单 IP 为 32/128）
	prefixV6 int
}

// 保留网段列表（IgnorePrivateIPs=true 时构建期过滤）。
// v4 覆盖：0.0.0.0/8、10/8、100.64/10（CGNAT）、127/8、169.254/16、172.16/12、
// 192.0.0/24、192.0.2/24、192.168/16、198.18/15、198.51.100/24、203.0.113/24、
// 224/4（组播）、240/4（含 255.255.255.255）。
// v6 覆盖：::、::1、fc00::/7、fe80::/10、ff00::/8、2001:db8::/32。
var (
	reservedV4Ranges []ipv4Range
	reservedV6Nets   []*net.IPNet
)

func init() {
	for _, cidr := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4",
	} {
		if r := parseV4CIDRRange(cidr); r != nil {
			reservedV4Ranges = append(reservedV4Ranges, *r)
		}
	}
	sort.Slice(reservedV4Ranges, func(i, j int) bool {
		return reservedV4Ranges[i].start < reservedV4Ranges[j].start
	})

	for _, cidr := range []string{
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
	} {
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
			reservedV6Nets = append(reservedV6Nets, ipnet)
		}
	}
}

// NewStore 从多个数据源的原始文本构建不可变 Store，多源合并为单份。
// 解析规则：每行 TrimSpace；跳过空行与 # / ; 开头的注释行；含 "/" 的行按 CIDR
// 解析，否则按单 IP 解析；非法行跳过并按来源计数。
// ignorePrivateIPs=true 时在构建期过滤保留网段：单 IP 命中保留段即丢弃；
// CIDR 当 start 与 end 均属保留段时整条丢弃（部分跨界的 CIDR 保守保留，
// 例如 10.0.0.0/7 会因覆盖 11.0.0.0/8 公网段而整体保留）。
func NewStore(sources []SourceData, ignorePrivateIPs bool, builtAt time.Time) *Store {
	return NewStoreWithPolicy(sources, ignorePrivateIPs, builtAt, DefaultContentPolicy())
}

// NewStoreWithPolicy F9：带形态围栏构建（单条前缀超限跳过+计数；覆盖率/v6
// 条目数为 meta 透出，由 fetcher 的拒表判定消费）
func NewStoreWithPolicy(sources []SourceData, ignorePrivateIPs bool, builtAt time.Time, policy ContentPolicy) *Store {
	s := &Store{
		v4Exact: make(map[uint32]struct{}),
		v6Exact: make(map[[16]byte]struct{}),
	}
	if builtAt.IsZero() {
		builtAt = time.Now()
	}

	var v4ranges []ipv4Range
	var v6ranges []ipv6Range
	s.meta.Sources = make([]SourceCount, 0, len(sources))

	for _, src := range sources {
		count := SourceCount{Name: src.Name}
		for _, raw := range strings.Split(string(src.Data), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}

			entry, ok := parseEntry(line)
			if !ok {
				count.InvalidLines++
				continue
			}

			// F9.1：单条 CIDR 前缀围栏（跳过+计数，不拒表）
			if entry.isRange {
				if entry.isV4 && entry.prefixV4 < policy.MinPrefixV4 {
					count.OversizedLines++
					continue
				}
				if !entry.isV4 && entry.prefixV6 < policy.MinPrefixV6 {
					count.OversizedLines++
					continue
				}
			}

			switch {
			case entry.isV4 && !entry.isRange:
				if ignorePrivateIPs && isReservedV4(entry.v4) {
					continue // 保留网段过滤：静默丢弃，不计入非法行
				}
				s.v4Exact[entry.v4] = struct{}{}
			case entry.isV4 && entry.isRange:
				if ignorePrivateIPs && isReservedV4(entry.v4r.start) && isReservedV4(entry.v4r.end) {
					continue
				}
				v4ranges = append(v4ranges, entry.v4r)
			case !entry.isV4 && !entry.isRange:
				if ignorePrivateIPs && isReservedV6(entry.v6) {
					continue
				}
				s.v6Exact[entry.v6] = struct{}{}
			default:
				if ignorePrivateIPs && netFullyReservedV6Range(entry.v6r) {
					continue
				}
				v6ranges = append(v6ranges, entry.v6r)
			}
			count.Entries++
		}
		s.meta.Sources = append(s.meta.Sources, count)
		s.meta.TotalEntries += count.Entries
		s.meta.OversizedLinesTotal += count.OversizedLines
	}

	s.v4Ranges = mergeV4Ranges(v4ranges)
	s.v6Ranges = mergeV6Ranges(v6ranges)
	// F9.2：合并后区间两两不相交 → 直接累加即「重叠只算一次」的覆盖地址数
	var covered uint64
	for _, r := range s.v4Ranges {
		covered += uint64(r.end-r.start) + 1
	}
	s.meta.CoveredV4Addrs = covered
	s.meta.V4CoveragePercent = float64(covered) / float64(math.MaxUint32+1) * 100
	s.meta.V6CIDREntries = len(s.v6Ranges)
	s.meta.DistinctEntries = len(s.v4Exact) + len(s.v4Ranges) + len(s.v6Exact) + len(s.v6Ranges)
	s.meta.BuiltAt = builtAt
	return s
}

// parseEntry 解析单行文本为 IP 或 CIDR 条目。
// v4-mapped IPv6（如 ::ffff:1.2.3.4、::ffff:12.12.0.0/112）经 To4() 归一化后按 IPv4 处理。
func parseEntry(line string) (parsedEntry, bool) {
	if strings.Contains(line, "/") {
		ip, ipnet, err := net.ParseCIDR(line)
		if err != nil {
			return parsedEntry{}, false
		}
		ones, _ := ipnet.Mask.Size()
		if ip.To4() != nil {
			r := v4CIDRToRange(ip, ipnet, line)
			if r == nil {
				return parsedEntry{}, false
			}
			return parsedEntry{isV4: true, isRange: true, v4r: *r, prefixV4: ones, prefixV6: ones + 96}, true
		}
		lo, hi, ok := v6NetToRange(ipnet, line)
		if !ok {
			return parsedEntry{}, false
		}
		return parsedEntry{isV4: false, isRange: true, v6r: ipv6Range{lo: lo, hi: hi, source: line}, prefixV6: ones}, true
	}

	ip := net.ParseIP(line)
	if ip == nil {
		return parsedEntry{}, false
	}
	if v4 := ip.To4(); v4 != nil {
		return parsedEntry{isV4: true, v4: binary.BigEndian.Uint32(v4)}, true
	}
	var key [16]byte
	copy(key[:], ip.To16())
	return parsedEntry{isV4: false, v6: key}, true
}

// v4CIDRToRange 将解析出的 IPv4 CIDR（含 v4-mapped IPv6 形式）展开为 uint32 区间。
// v4-mapped CIDR（如 ::ffff:12.12.0.0/112）按 ones-96 转为等价 IPv4 前缀。
// 非法族（如 IPv6 地址配 4 字节掩码之外的组合）返回 nil，调用方按非法行处理。
func v4CIDRToRange(ip net.IP, ipnet *net.IPNet, source string) *ipv4Range {
	if len(ipnet.Mask) == 4 {
		return v4NetToRange(ipnet, source)
	}
	if ones, bits := ipnet.Mask.Size(); bits == 128 && ones >= 96 {
		mask4 := net.CIDRMask(ones-96, 32)
		ipnet4 := &net.IPNet{IP: ip.To4().Mask(mask4), Mask: mask4}
		return v4NetToRange(ipnet4, source)
	}
	return nil
}

// v4NetToRange 将 IPv4 网段展开为 uint32 闭区间 [start, end]
func v4NetToRange(ipnet *net.IPNet, source string) *ipv4Range {
	if len(ipnet.Mask) != 4 {
		return nil // 非 IPv4 掩码，调用方应忽略
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return nil // 非 IPv4 地址（防御：当前调用路径已保证 v4）
	}
	start := binary.BigEndian.Uint32(ip4)
	mask := binary.BigEndian.Uint32(ipnet.Mask)
	return &ipv4Range{start: start, end: start | ^mask, source: source}
}

// parseV4CIDRRange 解析 IPv4 CIDR 字符串为区间，非 IPv4 CIDR 返回 nil
func parseV4CIDRRange(cidr string) *ipv4Range {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil || len(ipnet.Mask) != 4 {
		return nil
	}
	return v4NetToRange(ipnet, cidr)
}

// mergeV4Ranges 将区间按 start 排序并合并重叠/相邻区间，
// 保证结果两两不相交且 end 递增，从而 Lookup 可用纯二分。
// 合并后的区间保留其第一个成分 CIDR 的 source 字符串。
func mergeV4Ranges(ranges []ipv4Range) []ipv4Range {
	if len(ranges) == 0 {
		return nil
	}
	sort.SliceStable(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })

	merged := make([]ipv4Range, 0, len(ranges))
	for _, r := range ranges {
		if n := len(merged); n > 0 {
			last := &merged[n-1]
			// 重叠（r.start <= last.end）或相邻（r.start == last.end+1）时合并。
			// last.end == math.MaxUint32 时任何 r.start 都满足重叠条件，无溢出问题。
			if r.start <= last.end || (last.end != math.MaxUint32 && r.start == last.end+1) {
				if r.end > last.end {
					last.end = r.end
				}
				continue
			}
		}
		merged = append(merged, r)
	}
	return merged
}

// isReservedV4 判断 IPv4（uint32）是否属于保留网段
func isReservedV4(v uint32) bool {
	for _, r := range reservedV4Ranges {
		if v >= r.start && v <= r.end {
			return true
		}
	}
	return false
}

// isReservedV6 判断 IPv6 单 IP（[16]byte）是否属于保留网段
func isReservedV6(ip [16]byte) bool {
	netIP := net.IP(ip[:])
	for _, n := range reservedV6Nets {
		if n.Contains(netIP) {
			return true
		}
	}
	return false
}

// netFullyReservedV6Range 判断 IPv6 区间的首末地址是否均属保留网段（与 v4 同构的整条丢弃规则）
func netFullyReservedV6Range(r ipv6Range) bool {
	var f, l [16]byte
	binary.BigEndian.PutUint64(f[:8], r.lo[0])
	binary.BigEndian.PutUint64(f[8:], r.lo[1])
	binary.BigEndian.PutUint64(l[:8], r.hi[0])
	binary.BigEndian.PutUint64(l[8:], r.hi[1])
	return isReservedV6(f) && isReservedV6(l)
}

// v6NetToRange 将 IPv6 CIDR 展开为 128 位闭区间 [lo, hi]
func v6NetToRange(ipnet *net.IPNet, source string) (lo, hi [2]uint64, ok bool) {
	ip16 := ipnet.IP.To16()
	if ip16 == nil || len(ipnet.Mask) != 16 {
		return lo, hi, false
	}
	first := make(net.IP, 16)
	copy(first, ip16)
	for i := range first {
		first[i] &= ipnet.Mask[i]
	}
	last := make(net.IP, 16)
	copy(last, ip16)
	for i := range last {
		last[i] |= ^ipnet.Mask[i]
	}
	copyLo := [16]byte(first)
	copyHi := [16]byte(last)
	lo = [2]uint64{binary.BigEndian.Uint64(copyLo[:8]), binary.BigEndian.Uint64(copyLo[8:])}
	hi = [2]uint64{binary.BigEndian.Uint64(copyHi[:8]), binary.BigEndian.Uint64(copyHi[8:])}
	return lo, hi, true
}

// Lookup 查询 IP 是否命中黑名单，返回是否命中及命中的条目
// （单 IP 命中返回该 IP 字符串，CIDR 命中返回对应来源 CIDR 字符串）。
// v4-mapped IPv6（::ffff:1.2.3.4）先经 To4() 归一化，防变形绕过。
func (s *Store) Lookup(ipStr string) (bool, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, ""
	}

	if v4 := ip.To4(); v4 != nil {
		key := binary.BigEndian.Uint32(v4)
		if _, ok := s.v4Exact[key]; ok {
			return true, ipStr
		}
		if r := findV4Range(s.v4Ranges, key); r != nil {
			return true, r.source
		}
		return false, ""
	}

	var key16 [16]byte
	copy(key16[:], ip.To16())
	if _, ok := s.v6Exact[key16]; ok {
		return true, ipStr
	}
	// F9.3：v6 CIDR 二分查找（O(log n)）
	key := [2]uint64{binary.BigEndian.Uint64(key16[:8]), binary.BigEndian.Uint64(key16[8:])}
	if r := findV6Range(s.v6Ranges, key); r != nil {
		return true, r.source
	}
	return false, ""
}

// findV4Range 在排序且两两不相交的区间数组中二分查找 key。
// 候选为 start <= key 的最大区间，仅需检查该区间的 end。
func findV4Range(ranges []ipv4Range, key uint32) *ipv4Range {
	lo, hi := 0, len(ranges)-1
	idx := -1
	for lo <= hi {
		mid := int(uint(lo+hi) >> 1)
		if ranges[mid].start <= key {
			idx = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if idx >= 0 && ranges[idx].end >= key {
		return &ranges[idx]
	}
	return nil
}
