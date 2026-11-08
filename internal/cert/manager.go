package cert

import (
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// Manager 证书管理器
type Manager struct {
	cacheDir     string
	logger       logger.ILogger
	loader       *Loader
	updater      *Updater
	certificates map[string]*CertPair // 域名到证书对的映射
	mutex        sync.RWMutex

	// 证书 Reconciler（内部PRD §7.2）：期望证书集合的后台收敛。
	// notifier 在 srv.Start() 之前经 SetNotifier 注入（cert 包不反向依赖
	// notification 包，经 CertNotifier 接口解耦）；reconcilerMu 保护 reconciler
	// 指针的生命周期竞态（Start/Stop/Snapshot 可能来自不同 goroutine）
	notifier     CertNotifier
	reconciler   *Reconciler
	reconcilerMu sync.Mutex

	// 续期去重与节流，防止高并发 TLS 握手在证书临近过期时惊群触发远程下载
	renewalMu       sync.Mutex
	renewalInflight map[string]bool      // 标记正在进行的异步续期
	renewalLastRun  map[string]time.Time // 最近一次续期触发时间，用于节流

	// H25: 每域名更新锁，序列化 forceUpdateCertificate 和 triggerRenewal 的磁盘写入
	updateMu sync.Map // map[string]*sync.Mutex

	// goroutine 生命周期管理
	stopChan  chan struct{}
	stopOnce  sync.Once
	renewalWg sync.WaitGroup
}

// renewalThrottleInterval 两次异步续期之间的最小间隔
const renewalThrottleInterval = 10 * time.Minute

// NewManager 创建证书管理器
func NewManager(cacheDir string, log logger.ILogger) *Manager {
	fullCacheDir := filepath.Join(cacheDir, "certs")
	manager := &Manager{
		cacheDir:        fullCacheDir,
		logger:          log,
		loader:          NewLoader(fullCacheDir, log),
		certificates:    make(map[string]*CertPair),
		renewalInflight: make(map[string]bool),
		renewalLastRun:  make(map[string]time.Time),
		stopChan:        make(chan struct{}),
	}

	// 创建更新器，注册回调以便续期后同步内存
	manager.updater = NewUpdater(fullCacheDir, manager.loader, log, func(domain string, certPair *CertPair) {
		manager.updateCertInMemory(domain, certPair)
	})

	return manager
}

// updateCertInMemory 仅更新内存中的证书（由 Updater 回调调用）
func (m *Manager) updateCertInMemory(domain string, certPair *CertPair) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.certificates[domain] = certPair
	m.logger.Info("Certificate updated in memory",
		logger.NewField("domain", domain),
		logger.NewField("not_after", certPair.Metadata.NotAfter.Format(time.RFC3339)))
}

// GetCertificate 从内存获取证书（TLS GetCertificate 回调专用）
func (m *Manager) GetCertificate(serverName string) (*tls.Certificate, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 精确匹配
	if certPair, exists := m.certificates[serverName]; exists {
		return certPair.Certificate, nil
	}

	// 通配符匹配
	// H21: 按确定性顺序遍历（排序后），避免 map 随机迭代返回不同证书
	type certMatch struct {
		domain string
		pair   *CertPair
	}
	var matches []certMatch
	for domain, certPair := range m.certificates {
		if matchWildcardDomain(domain, serverName) {
			matches = append(matches, certMatch{domain: domain, pair: certPair})
		}
	}
	if len(matches) > 0 {
		// 按 domain 排序，取第一个匹配的，确保确定性
		sort.Slice(matches, func(i, j int) bool {
			return matches[i].domain < matches[j].domain
		})
		return matches[0].pair.Certificate, nil
	}

	// 未命中（精确 + 通配符均无匹配）直接返回 error → Go TLS 中止该次握手，
	// 客户端收到干净 TLS 错误。defaultDomain 回退已移除（内部PRD §7.3 / D2）：
	// 旧回退会让任意指向本机的未知域名完成握手拿到他人证书（域名不匹配 + 指纹收集面）
	return nil, fmt.Errorf("no certificate found for server name: %s", serverName)
}

// matchWildcardDomain 匹配通配符域名
// RFC 6125: 通配符 *.example.com 只匹配单层子域名（如 foo.example.com），
// 不匹配裸域名 example.com，也不匹配多层子域名 bar.baz.example.com
func matchWildcardDomain(pattern, hostname string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == hostname
	}

	if strings.HasPrefix(pattern, "*.") {
		domain := pattern[2:]
		// 通配符只匹配单层子域名：hostname 必须以 ".domain" 结尾，
		// 且 hostname 去掉 ".domain" 后缀后的部分不能包含 "."
		suffix := "." + domain
		if !strings.HasSuffix(hostname, suffix) {
			return false
		}
		subPart := hostname[:len(hostname)-len(suffix)]
		// subPart 不能为空（裸域名）也不能包含 "."（多层子域名）
		return subPart != "" && !strings.Contains(subPart, ".")
	}

	return false
}

// LoadCertificate 加载指定域名的证书（double-checked locking，避免在网络 I/O 期间持锁）
func (m *Manager) LoadCertificate(domain string, config *CertConfig) (*tls.Certificate, error) {
	return m.loadCertificate(domain, config, config)
}

// LoadCertificateBackground 后台加载变体（内部PRD §7.2 / D3-A）：
// 复用 LoadCertificate 的完整成功路径（写内存 + 注册 Updater），仅对"本次拉取"用
// attemptTimeout 覆写超时。config 与 loaderConfig 分离的原因：同一 *CertConfig 会被
// Updater 长期持有，夜间续期必须保持配置默认 6 分钟超时，绝不能原地改 Remote.Timeout
// （§14.2 不动 Updater 语义），因此续期触发与 Updater 注册一律使用原始 config。
func (m *Manager) LoadCertificateBackground(domain string, config *CertConfig, attemptTimeout time.Duration) (*tls.Certificate, error) {
	return m.loadCertificate(domain, config, cloneCertConfigWithTimeout(config, attemptTimeout))
}

// loadCertificate 加载主体；loaderConfig 仅用于 m.loader.LoadCertificate 那一步
func (m *Manager) loadCertificate(domain string, config, loaderConfig *CertConfig) (*tls.Certificate, error) {
	// 第一次检查（读锁，快路径）
	m.mutex.RLock()
	if certPair, exists := m.certificates[domain]; exists {
		cert := certPair.Certificate
		m.mutex.RUnlock()

		// 异步检查是否需要更新（带去重和节流）
		if certPair.Metadata.IsExpiringSoon() && config.Remote != nil && config.Remote.Enabled && config.Remote.AutoUpdate {
			m.triggerRenewal(domain, config, certPair.Metadata.NotAfter)
		}

		return cert, nil
	}
	m.mutex.RUnlock()

	// 缓存未命中，做 I/O（无锁，避免阻塞其他 TLS 握手）
	certPair, err := m.loader.LoadCertificate(domain, loaderConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate for domain %s: %w", domain, err)
	}

	// 写锁存结果
	m.mutex.Lock()
	// 再次检查（可能其他 goroutine 已经加载了）
	if existing, exists := m.certificates[domain]; exists {
		m.mutex.Unlock()
		return existing.Certificate, nil
	}
	m.certificates[domain] = certPair
	m.mutex.Unlock()

	// 如果启用了自动更新，启动更新器
	if config.Remote != nil && config.Remote.Enabled && config.Remote.AutoUpdate {
		if err := m.updater.StartAutoUpdate(domain, config); err != nil {
			m.logger.Warn("Failed to start auto-update for domain",
				logger.NewField("domain", domain),
				logger.NewField("error", err.Error()))
		}
	}

	m.logger.Info("Certificate loaded successfully",
		logger.NewField("domain", domain),
		logger.NewField("source", certPair.Metadata.Source),
		logger.NewField("not_after", certPair.Metadata.NotAfter.Format(time.RFC3339)))

	return certPair.Certificate, nil
}

// GetCertificateMetadata 获取证书元数据
func (m *Manager) GetCertificateMetadata(domain string) (*CertMetadata, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if certPair, exists := m.certificates[domain]; exists {
		return certPair.Metadata, nil
	}

	return LoadMetadata(m.cacheDir, domain)
}

// getDomainUpdateLock H25: 获取指定域名的更新锁（per-domain mutex）
func (m *Manager) getDomainUpdateLock(domain string) *sync.Mutex {
	val, _ := m.updateMu.LoadOrStore(domain, &sync.Mutex{})
	return val.(*sync.Mutex)
}

// UpdateCertificate 手动更新证书
func (m *Manager) UpdateCertificate(domain string, config *CertConfig) error {
	// H25: 获取 per-domain 锁，序列化 forceUpdateCertificate 和 triggerRenewal 的磁盘写入
	mu := m.getDomainUpdateLock(domain)
	mu.Lock()
	defer mu.Unlock()

	m.logger.Info("Manually updating certificate", logger.NewField("domain", domain))

	if config.Remote == nil || !config.Remote.Enabled {
		return fmt.Errorf("remote certificate not enabled for domain %s", domain)
	}

	certPair, err := m.loader.loadRemoteCertificate(domain, config.Remote)
	if err != nil {
		return fmt.Errorf("failed to update certificate from remote: %w", err)
	}

	m.updateCertInMemory(domain, certPair)

	m.logger.Info("Certificate updated successfully",
		logger.NewField("domain", domain),
		logger.NewField("not_after", certPair.Metadata.NotAfter.Format(time.RFC3339)))

	return nil
}

// updateCertificateAsync 异步更新证书
func (m *Manager) updateCertificateAsync(domain string, config *CertConfig) error {
	if err := m.UpdateCertificate(domain, config); err != nil {
		m.logger.Error("Failed to update certificate asynchronously",
			logger.NewField("domain", domain),
			logger.NewField("error", err.Error()))
		return err
	}
	return nil
}

// triggerRenewal 触发异步续期，带 in-flight 去重和节流
// 当多个 TLS 握手并发检查到证书即将过期时，确保同一域名同时只有一个续期请求在飞行，
// 且两次续期尝试之间至少间隔 renewalThrottleInterval
func (m *Manager) triggerRenewal(domain string, config *CertConfig, notAfter time.Time) {
	m.renewalMu.Lock()
	if m.renewalInflight[domain] {
		m.renewalMu.Unlock()
		return
	}
	if lastRun, exists := m.renewalLastRun[domain]; exists && time.Since(lastRun) < renewalThrottleInterval {
		m.renewalMu.Unlock()
		return
	}
	m.renewalInflight[domain] = true
	m.renewalMu.Unlock()

	m.logger.Info("Certificate expiring soon, triggering update",
		logger.NewField("domain", domain),
		logger.NewField("not_after", notAfter.Format(time.RFC3339)))

	m.renewalWg.Add(1)
	go func() {
		defer m.renewalWg.Done()
		defer func() {
			if r := recover(); r != nil {
				m.logger.Error("Panic in certificate renewal goroutine",
					logger.NewField("domain", domain),
					logger.NewField("panic", fmt.Sprintf("%v", r)))
			}
			m.renewalMu.Lock()
			delete(m.renewalInflight, domain)
			m.renewalMu.Unlock()
		}()

		// 检查 stopChan，避免在 Shutdown 后启动不必要的续期
		select {
		case <-m.stopChan:
			return
		default:
		}

		err := m.updateCertificateAsync(domain, config)

		// 续期成功后才更新节流时间戳，失败时允许快速重试
		if err == nil {
			m.renewalMu.Lock()
			m.renewalLastRun[domain] = time.Now()
			m.renewalMu.Unlock()
		}
	}()
}

// ListCertificates 列出所有已加载的证书
func (m *Manager) ListCertificates() map[string]*CertMetadata {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	result := make(map[string]*CertMetadata)
	for domain, certPair := range m.certificates {
		result[domain] = certPair.Metadata
	}

	return result
}

// HasCertificate 判断域名证书是否已在内存。
// Reconciler 调度与 admin 可观测均以内存 map 为唯一真相源（内部PRD §7.2），
// 不维护第二真相源。
func (m *Manager) HasCertificate(domain string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	_, exists := m.certificates[domain]
	return exists
}

// SetNotifier 注入证书事件通知器。main.go 在 srv.Start() 之前调用：
// Start 过程中即会启动 Reconciler，之后注入对已创建的 Reconciler 不生效。
// F6.5（内部PRD §4.6.5）：级联注入 Updater 续期失败回调
// （cert_renewal_failed 限频上抛 / cert_expired 最高优），未注入 notifier 时 no-op。
func (m *Manager) SetNotifier(n CertNotifier) {
	m.notifier = n
	m.updater.SetRenewalFailedNotifier(func(domain string, consecutive int, errStr string) {
		if n == nil {
			return
		}
		if strings.HasPrefix(errStr, "cert_expired:") {
			_ = n.SendNotification("cert_expired", map[string]string{
				"域名": domain,
				"详情": strings.TrimPrefix(errStr, "cert_expired:"),
				"风险": "证书已过期仍在服务，正在强制续期",
			})
			return
		}
		_ = n.SendNotification("cert_renewal_failed", map[string]string{
			"域名":   domain,
			"连续失败": strconv.Itoa(consecutive),
			"错误":   errStr,
		})
	})
}

// StartReconciler 创建并启动证书 Reconciler（内部PRD §7.1/§7.2）。
// 空 targets 直接 no-op（该网关无任何 HTTPS host）；重复调用 Warn+忽略
// （生命周期由 server.Start/shutdownAllServers 独占，二次调用属编程错误）。
func (m *Manager) StartReconciler(targets []CertTarget) {
	if len(targets) == 0 {
		return
	}

	m.reconcilerMu.Lock()
	defer m.reconcilerMu.Unlock()
	if m.reconciler != nil {
		m.logger.Warn("Certificate reconciler already started, ignoring duplicate start")
		return
	}

	r := newReconciler(m, targets, m.notifier, m.logger)
	m.reconciler = r
	r.start()
}

// StopReconciler 停止证书 Reconciler（nil 安全：未启动时为 no-op）。
// 调用顺序约束（PRD §14.2）：必须在 certManager.Shutdown()（清空证书 map、
// 停止 Updater）之前执行，保证收敛循环不会引用已清空的组件。
func (m *Manager) StopReconciler() {
	m.reconcilerMu.Lock()
	r := m.reconciler
	m.reconciler = nil
	m.reconcilerMu.Unlock()
	if r != nil {
		r.Stop()
	}
}

// PendingSnapshot 导出 pending 域名的收敛状态快照（admin /api/certs 用）：
// 按域名排序的深拷贝；reconciler 未启动时返回空非 nil 切片（JSON 输出 [] 而非 null）。
func (m *Manager) PendingSnapshot() []PendingCertState {
	m.reconcilerMu.Lock()
	r := m.reconciler
	m.reconcilerMu.Unlock()
	if r == nil {
		return []PendingCertState{}
	}
	return r.snapshot()
}

// Shutdown 关闭证书管理器
func (m *Manager) Shutdown() {
	m.logger.Info("Shutting down certificate manager")

	// 防御性先停 Reconciler（幂等，内部PRD §14.2 顺序约束）：
	// 无论调用方是否已显式 StopReconciler，都保证收敛循环先于证书 map 清空停止
	m.StopReconciler()

	// 通知所有续期 goroutine 停止
	m.stopOnce.Do(func() { close(m.stopChan) })

	// 等待所有飞行中的续期 goroutine 完成（带超时，防止远程下载永久阻塞关闭流程）
	done := make(chan struct{})
	go func() {
		m.renewalWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		m.logger.Warn("Timed out waiting for certificate renewal goroutines, proceeding with shutdown")
	}

	if m.updater != nil {
		m.updater.Stop()
	}

	m.mutex.Lock()
	m.certificates = make(map[string]*CertPair)
	m.mutex.Unlock()
}

// ParseUpdateWindow 解析更新时间窗口
func ParseUpdateWindow(window string) (startHour, startMinute, endHour, endMinute int, err error) {
	if window == "" {
		return 0, 0, 0, 59, nil
	}

	parts := strings.Split(window, "-")
	if len(parts) != 2 {
		return 0, 0, 0, 0, fmt.Errorf("invalid update window format: %s", window)
	}

	start, err := parseTime(parts[0])
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("invalid start time: %w", err)
	}

	end, err := parseTime(parts[1])
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("invalid end time: %w", err)
	}

	return start.hour, start.minute, end.hour, end.minute, nil
}

type timeParts struct {
	hour, minute int
}

func parseTime(timeStr string) (timeParts, error) {
	parts := strings.Split(timeStr, ":")
	if len(parts) != 2 {
		return timeParts{}, fmt.Errorf("invalid time format: %s", timeStr)
	}

	var hour, minute int
	if _, err := fmt.Sscanf(parts[0], "%d", &hour); err != nil {
		return timeParts{}, fmt.Errorf("invalid hour: %s", parts[0])
	}

	if _, err := fmt.Sscanf(parts[1], "%d", &minute); err != nil {
		return timeParts{}, fmt.Errorf("invalid minute: %s", parts[1])
	}

	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return timeParts{}, fmt.Errorf("time out of range: %s", timeStr)
	}

	return timeParts{hour, minute}, nil
}

// IsInUpdateWindow 检查当前时间是否在更新窗口内
func IsInUpdateWindow(window string) bool {
	startHour, startMinute, endHour, endMinute, err := ParseUpdateWindow(window)
	if err != nil {
		return false
	}

	now := time.Now()
	currentHour, currentMinute := now.Hour(), now.Minute()

	startTotal := startHour*60 + startMinute
	endTotal := endHour*60 + endMinute
	currentTotal := currentHour*60 + currentMinute

	if startTotal > endTotal {
		return currentTotal >= startTotal || currentTotal <= endTotal
	}

	return currentTotal >= startTotal && currentTotal <= endTotal
}

// RandomTimeInWindow 在更新窗口内生成随机时间
func RandomTimeInWindow(window string) time.Duration {
	startHour, startMinute, endHour, endMinute, err := ParseUpdateWindow(window)
	if err != nil {
		return 30 * time.Minute
	}

	startTotal := startHour*60 + startMinute
	endTotal := endHour*60 + endMinute

	var windowMinutes int
	if startTotal > endTotal {
		windowMinutes = (24*60 - startTotal) + endTotal
	} else {
		windowMinutes = endTotal - startTotal
	}

	var randomMinutes int
	if windowMinutes > 0 {
		var n uint32
		if err := binary.Read(cryptorand.Reader, binary.LittleEndian, &n); err != nil {
			// 降级：使用时间戳作为随机源
			n = uint32(time.Now().UnixNano() % int64(windowMinutes+1))
		}
		randomMinutes = int(n % uint32(windowMinutes+1))
	}

	return time.Duration(randomMinutes) * time.Minute
}
