package blacklist

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/constants"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

const (
	// minEntries 防污染下限：解析结果少于此值拒绝替换（对齐 crs 的 minCRSTarballSize 思路）。
	// 判定口径为 Store 去重后条目数（DistinctEntries），非行数
	minEntries = 1000
	// shrinkRatio 防污染：低于上次去重条目数的 50% 拒绝替换
	shrinkRatio = 0.5
	// maxJitter 刷新间隔随机抖动上限（多节点错峰）
	maxJitter = 5 * time.Minute
	// defaultUpdateInterval 默认刷新间隔（update_interval 未配置或为 0 时）
	defaultUpdateInterval = 1 * time.Hour
	// defaultTimeout 默认单次拉取超时（timeout 未配置或为 0 时）
	defaultTimeout = 60 * time.Second
	// defaultCacheDir 磁盘缓存目录（对齐 CRS/证书的 ./cache 用法，Docker 已挂载该卷）
	defaultCacheDir = "./cache/blacklist"
	// maxDownloadSize 单源响应体大小上限，防御异常超大响应
	maxDownloadSize = 64 * 1024 * 1024
	// maxRedirects 重定向跟随次数上限
	maxRedirects = 3
	// tempFilePrefix 原子写临时文件前缀（与 atomicWriteFile 中 os.CreateTemp 的模式一致）
	tempFilePrefix = ".tmp-"
)

// redirectPolicy 拉取客户端的重定向约束：最多跟随 maxRedirects 次（via 含初始请求，
// 故判定为 len(via) > maxRedirects 时拒绝）；禁止 https→http 降级（返回错误使
// http.Client.Do 终止并报错，等价 http.ErrAbortRedirect 的拦截效果）
func redirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme == "http" {
		return fmt.Errorf("redirect downgrade from https to http is not allowed")
	}
	return nil
}

// blacklistUserAgent 可识别 UA（version 为空时用 dev）
var blacklistUserAgent = func() string {
	ver := constants.Version
	if ver == "" {
		ver = "dev"
	}
	return fmt.Sprintf("infra-gate/%s (+https://github.com/litelake)", ver)
}()

// Manager IP 黑名单管理器：定时拉取、容错解析、防污染、磁盘缓存、代理回退、统计与事件。
// 生命周期：NewManager → Start（加载磁盘缓存 + 异步首刷 + 定时循环）→ Stop。
// 运行期元信息（lastAttemptAt/lastSuccessAt/loadedFromCache）保存在 Store.meta 中，
// 随 Store 一起原子换新，GetStats 从单次原子加载的 Store 取得一致快照。
type Manager struct {
	cfg        config.BlacklistConfig
	log        logger.ILogger
	httpClient *http.Client
	proxyURL   *url.URL // 仅 Proxy.Enabled 时由 getProxyClient 解析

	store atomic.Pointer[Store]
	stats *statsTracker

	// refreshMu 串行化刷新（循环 goroutine 与测试直接调用互斥）
	refreshMu sync.Mutex

	stopOnce   sync.Once
	stopChan   chan struct{}
	stopCtx    context.Context    // 由 Stop 派生取消：绑定每个拉取请求，Stop 时在途请求立即中止
	stopCancel context.CancelFunc // 与 close(stopChan) 在 stopOnce 内同点调用，保证语义一致
	wg         sync.WaitGroup

	cacheDir string
	// onStale F9.4（内部PRD §4.9.4）：表龄告警回调（blacklist_stale 通知；
	// blacklist 包不依赖 notification，由 server 注入；nil = no-op）。每个超龄
	// 事件只告警一次（恢复后 staleNotified 重置）
	onStale       func(age time.Duration)
	staleNotified bool
}

// SetStaleNotifier F9.4：注入表龄告警回调（server 在 SetNotifier 中级联注入）
func (m *Manager) SetStaleNotifier(f func(age time.Duration)) {
	m.onStale = f
}

// contentPolicy F9.1：由配置构建单条前缀围栏
func (m *Manager) contentPolicy() ContentPolicy {
	return ContentPolicy{
		MinPrefixV4: m.cfg.GetEffectiveCIDRMinPrefixV4(),
		MinPrefixV6: m.cfg.GetEffectiveCIDRMinPrefixV6(),
	}
}

// minEntriesEffective F9.5：可配下限（nil=1000；显式 0=禁用）
func (m *Manager) minEntriesEffective() int {
	min, enabled := m.cfg.GetEffectiveMinEntries()
	if !enabled {
		return 0
	}
	return min
}

// NewManager 创建黑名单管理器
func NewManager(cfg config.BlacklistConfig, log logger.ILogger) *Manager {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	stopCtx, stopCancel := context.WithCancel(context.Background())
	return &Manager{
		cfg:        cfg,
		log:        log,
		httpClient: &http.Client{Timeout: timeout, CheckRedirect: redirectPolicy},
		stats:      newStatsTracker(),
		stopChan:   make(chan struct{}),
		stopCtx:    stopCtx,
		stopCancel: stopCancel,
		cacheDir:   defaultCacheDir,
	}
}

// Start 加载磁盘缓存（如有且过 minEntries 检查），随后异步首刷并进入定时循环。
// 首刷失败且无缓存时保留空表继续运行（fail-open），Error 日志，下周期重试。
func (m *Manager) Start() {
	if !m.cfg.Enabled {
		return
	}

	m.loadCache()

	m.wg.Add(1)
	go m.runLoop()
}

// Stop 关闭定时循环、取消在途拉取并等待刷新完成。
// stopCancel 与 close(stopChan) 同点触发：绑定 stopCtx 的 http.Client.Do
// 在 Stop 后立即返回，无需等待 源数×2×timeout 的最坏阻塞。
func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopChan)
		m.stopCancel()
	})
	m.wg.Wait()
}

// runLoop 定时刷新循环：先立即首刷，再按 update_interval + rand(0, maxJitter) 间隔刷新。
// F9.4：每轮检查表龄（LastSuccessAt 超过 staleness_threshold → Warn + 一次性回调告警）
func (m *Manager) runLoop() {
	defer m.wg.Done()
	for {
		m.refresh()
		m.checkStaleness()
		wait := m.updateIntervalWithJitter()
		select {
		case <-m.stopChan:
			return
		case <-time.After(wait):
		}
	}
}

// checkStaleness 表龄告警（F9.4：≈6 个刷新周期无成功刷新 = 数据源异常）
func (m *Manager) checkStaleness() {
	s := m.store.Load()
	if s == nil || s.meta.LastSuccessAt.IsZero() {
		return
	}
	age := time.Since(s.meta.LastSuccessAt)
	if age <= m.cfg.GetEffectiveStalenessThreshold() {
		m.staleNotified = false // 恢复即重置，下轮超龄重新告警
		return
	}
	if m.staleNotified {
		return
	}
	m.staleNotified = true
	m.log.Warn("Blacklist table is stale (no successful refresh within threshold)",
		logger.NewField("age", age.Round(time.Minute).String()),
		logger.NewField("threshold", m.cfg.GetEffectiveStalenessThreshold().String()),
		logger.NewField("last_success_at", s.meta.LastSuccessAt.Format(time.RFC3339)))
	if m.onStale != nil {
		m.onStale(age)
	}
}

// updateIntervalWithJitter 计算下一次刷新间隔（错峰抖动）
func (m *Manager) updateIntervalWithJitter() time.Duration {
	interval := m.cfg.UpdateInterval
	if interval <= 0 {
		interval = defaultUpdateInterval
	}
	return interval + time.Duration(rand.Int63n(int64(maxJitter)+1))
}

// loadCache 从磁盘缓存构建 Store。缓存同样要过 minEntries 检查（去重口径），不过则忽略缓存。
// 缓存文件首行携带写入时的来源 URL 标记，与当前配置 URL 不一致（换 URL 后的陈旧缓存）则忽略该文件。
func (m *Manager) loadCache() {
	m.cleanupStaleTempFiles()

	datas := make([]SourceData, 0, len(m.cfg.Sources))
	for _, src := range m.cfg.Sources {
		path := filepath.Join(m.cacheDir, cacheFileName(src.Name))
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				m.log.Warn("Failed to read blacklist cache file",
					logger.NewField("source", src.Name),
					logger.NewField("path", path),
					logger.NewField("error", err.Error()))
			}
			continue
		}
		// 防陈旧：缓存按 source name 键控，换 URL 后旧数据必须作废
		if !bytes.HasPrefix(data, []byte(cacheURLHeader(src.URL))) {
			m.log.Info("Blacklist cache ignored: source URL changed since cache was written",
				logger.NewField("source", src.Name),
				logger.NewField("path", path))
			continue
		}
		// F9.4：缓存判龄（mtime 超过 cache_ttl 忽略 + Warn；对齐 feed 单条封锁
		// 最长 ~3 天语义，默认 72h）
		if fi, statErr := os.Stat(path); statErr == nil {
			if age := time.Since(fi.ModTime()); age > m.cfg.GetEffectiveCacheTTL() {
				m.log.Warn("Blacklist cache ignored: older than cache_ttl",
					logger.NewField("source", src.Name),
					logger.NewField("age", age.Round(time.Minute).String()),
					logger.NewField("cache_ttl", m.cfg.GetEffectiveCacheTTL().String()))
				continue
			}
		}
		// 首行 URL 标记为 # 注释行，解析器天然跳过，不影响条目解析
		datas = append(datas, SourceData{Name: src.Name, Data: data})
	}
	if len(datas) == 0 {
		return
	}

	store := NewStoreWithPolicy(datas, m.cfg.GetIgnorePrivateIPs(), time.Now(), m.contentPolicy())
	if min := m.minEntriesEffective(); min > 0 && store.meta.DistinctEntries < min {
		m.log.Warn("Blacklist cache ignored: entries below minimum",
			logger.NewField("total_entries", store.meta.TotalEntries),
			logger.NewField("distinct_entries", store.meta.DistinctEntries),
			logger.NewField("minimum", min))
		return
	}
	// F9.2/F9.3：缓存同样过覆盖率与 v6 条目围栏（拒表忽略缓存）
	if m.storeShapeRejected(store, true) {
		return
	}

	store.meta.LoadedFromCache = true
	m.store.Store(store)

	m.log.Info("Blacklist loaded from disk cache",
		logger.NewField("sources", len(datas)),
		logger.NewField("total_entries", store.meta.TotalEntries),
		logger.NewField("distinct_entries", store.meta.DistinctEntries))
}

// refresh 执行一轮完整刷新：全部 source 拉取成功 → 合并解析 → 防污染检查 →
// 原子换新（含完整运行期 meta，单次发布）→ 磁盘缓存原子写。
// 任一 source 失败或防污染检查不通过则保留旧表，仅原子更新 lastAttemptAt。
// 设计为可单独调用的内部方法以便测试。
func (m *Manager) refresh() {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	attemptAt := time.Now()

	datas := make([]SourceData, 0, len(m.cfg.Sources))
	for _, src := range m.cfg.Sources {
		data, err := m.fetchSource(src)
		if err != nil {
			// 任一 source 失败则本轮整体失败，保留旧表，下周期重试。
			// 冷启动（无有效表）时为 fail-open 空表运行，记 Error 提升可见性（PRD §13）
			if m.hasTable() {
				m.log.Warn("Blacklist refresh failed for source, keeping existing store",
					logger.NewField("source", src.Name),
					logger.NewField("error", err.Error()))
			} else {
				m.log.Error("Blacklist refresh failed and no existing store, running with empty table (fail-open)",
					logger.NewField("source", src.Name),
					logger.NewField("error", err.Error()))
			}
			m.recordAttemptOnly(attemptAt)
			return
		}
		datas = append(datas, SourceData{Name: src.Name, Data: data})
	}

	newStore := NewStoreWithPolicy(datas, m.cfg.GetIgnorePrivateIPs(), time.Now(), m.contentPolicy())

	// 防污染检查：基于 Store 去重后规模（DistinctEntries）而非行数。
	// HTML 错误页等异常内容会因无法解析为 IP 而条目骤减，在此被拒绝替换；
	// 上游返回大量重复行时行数口径虚高（如 2000 行同一 IP），同样必须被拒绝
	prevDistinct := m.currentDistinctEntries()

	if min := m.minEntriesEffective(); min > 0 && newStore.meta.DistinctEntries < min {
		if prevDistinct == 0 {
			// 冷启动首刷即被防污染拒绝：同样属于无数据空表运行，记 Error（PRD §13）
			m.log.Error("Blacklist refresh rejected: entries below minimum, running with empty table (fail-open)",
				logger.NewField("total_entries", newStore.meta.TotalEntries),
				logger.NewField("distinct_entries", newStore.meta.DistinctEntries),
				logger.NewField("minimum", min))
		} else {
			m.log.Warn("Blacklist refresh rejected: entries below minimum",
				logger.NewField("total_entries", newStore.meta.TotalEntries),
				logger.NewField("distinct_entries", newStore.meta.DistinctEntries),
				logger.NewField("minimum", min),
				logger.NewField("previous_entries", prevDistinct))
		}
		m.recordAttemptOnly(attemptAt)
		return
	}
	// F9.2/F9.3：形态围栏拒表（覆盖率超限 / v6 条目超限 → 保留旧表）
	if m.storeShapeRejected(newStore, false) {
		m.recordAttemptOnly(attemptAt)
		return
	}
	if prevDistinct > 0 && float64(newStore.meta.DistinctEntries) < float64(prevDistinct)*shrinkRatio {
		m.log.Warn("Blacklist refresh rejected: entries shrank below safety ratio",
			logger.NewField("total_entries", newStore.meta.TotalEntries),
			logger.NewField("distinct_entries", newStore.meta.DistinctEntries),
			logger.NewField("previous_entries", prevDistinct),
			logger.NewField("shrink_ratio", shrinkRatio))
		m.recordAttemptOnly(attemptAt)
		return
	}

	// L6（内部PRD）：防追加式投毒的增长上限——既有防缩水检查只防变小，
	// 不防「在旧表基础上成倍追加」的投毒形态。新 feed 去重条目数超过
	// max(2×上次成功条目数, MaxEntries) → 拒绝替换、保留旧表。
	// 上次成功条目数随成功替换更新（prevDistinct 取自当前生效 Store）；
	// 首次加载（无旧表，prevDistinct=0）不受 2× 增长约束，但仍受 MaxEntries 硬上限。
	// 日志级别对齐 minEntries 拒绝的既有约定：有旧表 Warn（正常降级），
	// 冷启动（无旧表）Error（fail-open 空表运行需提升可见性，内部PRD §13）
	growthCap := int64(prevDistinct) * 2
	if maxEntries := int64(m.cfg.GetEffectiveMaxEntries()); growthCap < maxEntries {
		growthCap = maxEntries
	}
	if int64(newStore.meta.DistinctEntries) > growthCap {
		if prevDistinct == 0 {
			m.log.Error("Blacklist refresh rejected: entries exceed growth cap, running with empty table (fail-open)",
				logger.NewField("total_entries", newStore.meta.TotalEntries),
				logger.NewField("distinct_entries", newStore.meta.DistinctEntries),
				logger.NewField("growth_cap", growthCap))
		} else {
			m.log.Warn("Blacklist refresh rejected: entries exceed growth cap (possible append-style poisoning), keeping existing store",
				logger.NewField("total_entries", newStore.meta.TotalEntries),
				logger.NewField("distinct_entries", newStore.meta.DistinctEntries),
				logger.NewField("previous_entries", prevDistinct),
				logger.NewField("growth_cap", growthCap))
		}
		m.recordAttemptOnly(attemptAt)
		return
	}

	// 成功路径：运行期 meta 随新 Store 单次原子发布，保证 GetStats 快照一致
	newStore.meta.LastAttemptAt = attemptAt
	newStore.meta.LastSuccessAt = time.Now()
	newStore.meta.LoadedFromCache = false
	m.store.Store(newStore)
	m.writeCache(datas)

	for _, sc := range newStore.meta.Sources {
		m.log.Info("Blacklist source parsed",
			logger.NewField("source", sc.Name),
			logger.NewField("entries", sc.Entries),
			logger.NewField("invalid_lines", sc.InvalidLines),
			logger.NewField("oversized_lines", sc.OversizedLines))
	}
	// F9.1：单条超限聚合 Warn（每次成功刷新一条；投毒一行封半互联网的场景已被
	// 覆盖率拒表拦截，这里的超限是「合法但粗」的条目，如实测 USTC 的 3 条 /12）
	if newStore.meta.OversizedLinesTotal > 0 {
		m.log.Warn("Blacklist feed contains oversized CIDR entries (skipped and counted)",
			logger.NewField("oversized_lines_total", newStore.meta.OversizedLinesTotal),
			logger.NewField("min_prefix_v4", m.contentPolicy().MinPrefixV4),
			logger.NewField("min_prefix_v6", m.contentPolicy().MinPrefixV6))
	}
	m.log.Info("Blacklist refreshed",
		logger.NewField("total_entries", newStore.meta.TotalEntries),
		logger.NewField("distinct_entries", newStore.meta.DistinctEntries),
		logger.NewField("previous_entries", prevDistinct),
		logger.NewField("v4_coverage_percent", newStore.meta.V4CoveragePercent))
}

// storeShapeRejected F9 形态围栏拒表判定（聚合覆盖率 / v6 条目数），返回 true
// 表示拒绝该表。fromCache=true 为缓存路径（无旧表时静默忽略），false 为刷新
// 路径（保留旧表 + Warn；冷启动 Error fail-open）
func (m *Manager) storeShapeRejected(store *Store, fromCache bool) bool {
	maxPct := m.cfg.GetEffectiveMaxV4CoveragePercent()
	if store.meta.V4CoveragePercent > maxPct {
		if fromCache {
			m.log.Warn("Blacklist cache ignored: v4 coverage exceeds limit",
				logger.NewField("coverage_percent", store.meta.V4CoveragePercent),
				logger.NewField("max_percent", maxPct))
			return true
		}
		if !m.hasTable() {
			m.log.Error("Blacklist refresh rejected: v4 coverage exceeds limit (possible feed poisoning), running with empty table (fail-open)",
				logger.NewField("coverage_percent", store.meta.V4CoveragePercent),
				logger.NewField("covered_v4_addrs", store.meta.CoveredV4Addrs),
				logger.NewField("max_percent", maxPct))
		} else {
			m.log.Warn("Blacklist refresh rejected: v4 coverage exceeds limit, keeping existing store",
				logger.NewField("coverage_percent", store.meta.V4CoveragePercent),
				logger.NewField("covered_v4_addrs", store.meta.CoveredV4Addrs),
				logger.NewField("max_percent", maxPct))
		}
		return true
	}
	maxV6 := m.cfg.GetEffectiveMaxV6CIDREntries()
	if store.meta.V6CIDREntries > maxV6 {
		if fromCache {
			m.log.Warn("Blacklist cache ignored: v6 CIDR entries exceed limit",
				logger.NewField("v6_cidr_entries", store.meta.V6CIDREntries),
				logger.NewField("max_entries", maxV6))
			return true
		}
		if !m.hasTable() {
			m.log.Error("Blacklist refresh rejected: v6 CIDR entries exceed limit (possible feed poisoning), running with empty table (fail-open)",
				logger.NewField("v6_cidr_entries", store.meta.V6CIDREntries),
				logger.NewField("max_entries", maxV6))
		} else {
			m.log.Warn("Blacklist refresh rejected: v6 CIDR entries exceed limit, keeping existing store",
				logger.NewField("v6_cidr_entries", store.meta.V6CIDREntries),
				logger.NewField("max_entries", maxV6))
		}
		return true
	}
	return false
}

// hasTable 当前是否持有有效黑名单表（nil 或空占位表均视为无表，用于 fail-open 日志级别判定）
func (m *Manager) hasTable() bool {
	return m.currentDistinctEntries() > 0
}

// currentDistinctEntries 原子读取当前 Store 的去重后条目数（无表时返回 0）
func (m *Manager) currentDistinctEntries() int {
	if s := m.store.Load(); s != nil {
		return s.meta.DistinctEntries
	}
	return 0
}

// recordAttemptOnly 刷新失败路径的原子更新：浅拷贝旧 Store 仅更新 lastAttemptAt
// （Store 一经发布不可变，底层 slices/maps 引用共享是安全的）。
// 尚无任何 Store 时发布仅含 lastAttemptAt 的空占位表（Lookup 语义与 nil 等价，fail-open），
// 使 GetStats 在冷启动失败后仍能看到尝试时间。
func (m *Manager) recordAttemptOnly(at time.Time) {
	old := m.store.Load()
	if old == nil {
		empty := NewStore(nil, m.cfg.GetIgnorePrivateIPs(), time.Time{})
		empty.meta.LastAttemptAt = at
		m.store.Store(empty)
		return
	}
	updated := *old // 浅拷贝：meta 为值结构体，仅 LastAttemptAt 字段被替换
	updated.meta.LastAttemptAt = at
	m.store.Store(&updated)
}

// fetchSource 拉取单个数据源：直连失败且配置了代理时经代理重试 1 次。
// HTTP 非 200 或网络错误均视为失败。
func (m *Manager) fetchSource(src config.BlacklistSourceConfig) ([]byte, error) {
	data, directErr := m.doFetch(src.URL, m.httpClient)
	if directErr == nil {
		return data, nil
	}

	if !m.cfg.Proxy.Enabled || m.cfg.Proxy.URL == "" {
		return nil, directErr
	}

	proxyClient, err := m.getProxyClient()
	if err != nil {
		return nil, fmt.Errorf("direct: %v; proxy setup: %w", directErr, err)
	}

	data, proxyErr := m.doFetch(src.URL, proxyClient)
	if proxyErr != nil {
		return nil, fmt.Errorf("direct: %v; proxy: %w", directErr, proxyErr)
	}
	return data, nil
}

// doFetch 执行 HTTP GET（带自定义 User-Agent 与重定向约束），非 200 或网络错误返回错误。
// 请求绑定 stopCtx：Stop 后（含在途请求）立即取消，不等待超时。
// 调用方保证并发安全（仅在 refreshMu 持有期间调用）。
func (m *Manager) doFetch(rawURL string, client *http.Client) ([]byte, error) {
	req, err := http.NewRequestWithContext(m.stopCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", blacklistUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadSize+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(data) > maxDownloadSize {
		return nil, fmt.Errorf("response body exceeds limit: %d bytes", len(data))
	}
	return data, nil
}

// getProxyClient 构建带认证的代理 HTTP 客户端（仅 refreshMu 持有期间调用）
func (m *Manager) getProxyClient() (*http.Client, error) {
	if m.proxyURL == nil {
		proxyURL, err := url.Parse(m.cfg.Proxy.URL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %q: %w", m.cfg.Proxy.URL, err)
		}
		if m.cfg.Proxy.Username != "" && m.cfg.Proxy.Password != "" {
			proxyURL.User = url.UserPassword(m.cfg.Proxy.Username, m.cfg.Proxy.Password)
		}
		m.proxyURL = proxyURL
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyURL(m.proxyURL),
		ResponseHeaderTimeout: m.httpClient.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       m.httpClient.Timeout,
		CheckRedirect: redirectPolicy, // 代理路径与直连共用同一重定向约束
	}, nil
}

// writeCache 将各源原始数据原子写入磁盘缓存（临时文件 + rename，0644）。
// 首行写入来源 URL 标记，供 loadCache 校验缓存是否属于当前配置 URL。
func (m *Manager) writeCache(datas []SourceData) {
	m.cleanupStaleTempFiles()

	if err := os.MkdirAll(m.cacheDir, 0755); err != nil {
		m.log.Warn("Failed to create blacklist cache directory",
			logger.NewField("dir", m.cacheDir),
			logger.NewField("error", err.Error()))
		return
	}

	for _, d := range datas {
		path := filepath.Join(m.cacheDir, cacheFileName(d.Name))
		payload := append([]byte(cacheURLHeader(m.sourceURL(d.Name))), d.Data...)
		if err := atomicWriteFile(path, payload, 0644); err != nil {
			m.log.Warn("Failed to write blacklist cache file",
				logger.NewField("source", d.Name),
				logger.NewField("path", path),
				logger.NewField("error", err.Error()))
		}
	}
}

// cleanupStaleTempFiles 删除缓存目录内同前缀 .tmp-* 的残留临时文件（crash 遗留）。
// 正常路径下 atomicWriteFile 的 defer Remove 已自清理，此处兜底。
func (m *Manager) cleanupStaleTempFiles() {
	entries, err := os.ReadDir(m.cacheDir)
	if err != nil {
		return // 目录不存在（首次写缓存前）属正常，静默跳过
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), tempFilePrefix) {
			continue
		}
		path := filepath.Join(m.cacheDir, e.Name())
		if err := os.Remove(path); err != nil {
			m.log.Warn("Failed to remove stale blacklist temp file",
				logger.NewField("path", path),
				logger.NewField("error", err.Error()))
		} else {
			m.log.Info("Removed stale blacklist temp file",
				logger.NewField("path", path))
		}
	}
}

// sourceURL 返回来源名对应的配置 URL（datas 均来自配置驱动的拉取，正常必有；找不到返回空）
func (m *Manager) sourceURL(name string) string {
	for _, src := range m.cfg.Sources {
		if src.Name == name {
			return src.URL
		}
	}
	return ""
}

// cacheURLHeader 缓存文件首行的来源 URL 标记（# 开头，解析器天然跳过该行）
func cacheURLHeader(rawURL string) string {
	return "# source_url: " + rawURL + "\n"
}

// Lookup 查询 IP 是否命中黑名单（nil Store 视为空表，fail-open）
func (m *Manager) Lookup(ip string) (bool, string) {
	s := m.store.Load()
	if s == nil {
		return false, ""
	}
	return s.Lookup(ip)
}

// Enabled 全局开关快捷判断
func (m *Manager) Enabled() bool {
	return m.cfg.Enabled
}

// RecordHit 记录一次黑名单命中：统计计数总是记录；
// 事件记录先过按 IP 限速（每 IP 每分钟最多 1 条），防扫描器刷爆环形缓冲与日志
func (m *Manager) RecordHit(mode, clientIP, matched, host, path, traceID string) {
	m.stats.recordHit(mode, clientIP, matched, host, path, traceID)
}

// GetStats 返回统计快照（供 admin 注入）。
// 表相关元信息全部来自同一次原子加载的 Store，消除分步更新造成的混合快照。
func (m *Manager) GetStats() StatsSnapshot {
	snap := StatsSnapshot{
		Enabled:     m.cfg.Enabled,
		DefaultMode: m.cfg.DefaultMode,
	}
	if snap.DefaultMode == "" {
		snap.DefaultMode = config.BlacklistModeBlock
	}

	if s := m.store.Load(); s != nil {
		snap.TotalEntries = s.meta.TotalEntries
		if srcs := sourceStatsFromStore(s, m.cfg.Sources); len(srcs) > 0 {
			snap.Sources = srcs
		}
		if !s.meta.LastSuccessAt.IsZero() {
			t := s.meta.LastSuccessAt
			snap.LastSuccessAt = &t
		}
		if !s.meta.LastAttemptAt.IsZero() {
			t := s.meta.LastAttemptAt
			snap.LastAttemptAt = &t
		}
		snap.LoadedFromCache = s.meta.LoadedFromCache
		snap.CoveredV4Addrs = s.meta.CoveredV4Addrs
		snap.V4CoveragePercent = s.meta.V4CoveragePercent
		snap.V6CIDREntries = s.meta.V6CIDREntries
		snap.OversizedLinesTotal = s.meta.OversizedLinesTotal
	}

	snap.HitTotalBlock, snap.HitTotalDetect = m.stats.hitCounts()
	snap.RecentHits = m.stats.recentHits()
	return snap
}

// GetEvents 返回最新的 limit 条命中事件（供 admin 注入）
func (m *Manager) GetEvents(limit int) []BlacklistEvent {
	return m.stats.recentEvents(limit)
}

// sourceStatsFromStore 将 Store 元信息与配置中的 URL 合成 admin 展示用的来源统计
func sourceStatsFromStore(store *Store, sources []config.BlacklistSourceConfig) []SourceStat {
	urls := make(map[string]string, len(sources))
	for _, src := range sources {
		urls[src.Name] = src.URL
	}

	result := make([]SourceStat, 0, len(store.meta.Sources))
	for _, sc := range store.meta.Sources {
		result = append(result, SourceStat{
			Name:           sc.Name,
			URL:            urls[sc.Name],
			Entries:        sc.Entries,
			InvalidLines:   sc.InvalidLines,
			OversizedLines: sc.OversizedLines,
		})
	}
	return result
}

// cacheFileName 将来源名转为安全的缓存文件名（仅允许字母数字与 . _ -，其余替换为 _）
func cacheFileName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_.txt"
	}
	return b.String() + ".txt"
}

// atomicWriteFile 原子写入文件（同目录临时文件 + Sync + rename，对齐证书管理器做法）
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)

	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) // 清理未 rename 的临时文件（rename 成功后 Remove 为 no-op）

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := tmpFile.Chmod(perm); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to chmod temp file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to rename temp file to target: %w", err)
	}

	return nil
}
