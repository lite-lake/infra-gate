package cert

import (
	"fmt"
	"sync"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// UpdateTask 更新任务
type UpdateTask struct {
	Domain     string
	Config     *CertConfig
	NextUpdate time.Time
	StopChan   chan struct{}
	stopOnce   sync.Once
}

// Updater 证书自动更新器
type Updater struct {
	cacheDir string
	loader   *Loader
	logger   logger.ILogger

	tasks         map[string]*UpdateTask // 域名到更新任务的映射
	mutex         sync.RWMutex
	running       bool
	stopChan      chan struct{}
	stopOnce      sync.Once
	wg            sync.WaitGroup
	onCertUpdated func(domain string, certPair *CertPair)
	// F6.5（内部PRD §4.6.5）：续期失败计数与回调（nil-guard，
	// 首次 + 每 N 次上抛，对齐 reconciler shouldNotifyCertFailure 限频模式）
	onRenewalFailed func(domain string, consecutive int, errStr string)
	failCounts      map[string]int
}

// NewUpdater 创建证书更新器
func NewUpdater(cacheDir string, loader *Loader, log logger.ILogger, onCertUpdated func(string, *CertPair)) *Updater {
	return &Updater{
		cacheDir:      cacheDir,
		loader:        loader,
		logger:        log,
		tasks:         make(map[string]*UpdateTask),
		stopChan:      make(chan struct{}),
		onCertUpdated: onCertUpdated,
		failCounts:    make(map[string]int),
	}
}

// SetRenewalFailedNotifier F6.5：注入续期失败回调（nil-guard；main 经
// Manager.SetRenewalNotifier 级联注入，未注入时 no-op）
func (u *Updater) SetRenewalFailedNotifier(f func(domain string, consecutive int, errStr string)) {
	u.onRenewalFailed = f
}

// renewalFailedNotifyEvery F6.5：连续失败上抛间隔（首次 + 每 12 次，对齐
// reconciler failedNotifyEvery）
const renewalFailedNotifyEvery = 12

// noteRenewalFailure F6.5：失败计数 + 限频上抛（首次必发）
func (u *Updater) noteRenewalFailure(domain string, errStr string) {
	u.failCounts[domain]++
	n := u.failCounts[domain]
	if u.onRenewalFailed != nil && (n == 1 || n%renewalFailedNotifyEvery == 0) {
		u.onRenewalFailed(domain, n, errStr)
	}
}

// StartAutoUpdate 启动自动更新
func (u *Updater) StartAutoUpdate(domain string, config *CertConfig) error {
	if !config.Remote.Enabled || !config.Remote.AutoUpdate {
		return fmt.Errorf("auto-update not enabled for domain %s", domain)
	}

	u.mutex.Lock()
	defer u.mutex.Unlock()

	if _, exists := u.tasks[domain]; exists {
		return fmt.Errorf("auto-update already started for domain %s", domain)
	}

	task := &UpdateTask{
		Domain:   domain,
		Config:   config,
		StopChan: make(chan struct{}),
	}

	task.NextUpdate = u.calculateNextUpdateTime(config.Remote.UpdateCheckWindow)

	u.tasks[domain] = task

	if !u.running {
		u.running = true
		u.stopOnce = sync.Once{}
		u.stopChan = make(chan struct{})
		u.wg.Add(1)
		go u.run()
	}

	u.logger.Info("Auto-update started for domain",
		logger.NewField("domain", domain),
		logger.NewField("next_update", task.NextUpdate.Format(time.RFC3339)))

	return nil
}

// StopAutoUpdate 停止指定域名的自动更新
func (u *Updater) StopAutoUpdate(domain string) {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	if task, exists := u.tasks[domain]; exists {
		task.stopOnce.Do(func() { close(task.StopChan) })
		delete(u.tasks, domain)

		u.logger.Info("Auto-update stopped for domain", logger.NewField("domain", domain))
	}

	if len(u.tasks) == 0 && u.running {
		u.stopOnce.Do(func() { close(u.stopChan) })
		u.running = false
	}
}

// Stop 停止所有更新任务
func (u *Updater) Stop() {
	u.mutex.Lock()

	for domain, task := range u.tasks {
		task.stopOnce.Do(func() { close(task.StopChan) })
		delete(u.tasks, domain)
		u.logger.Info("Auto-update stopped for domain", logger.NewField("domain", domain))
	}

	if u.running {
		u.stopOnce.Do(func() { close(u.stopChan) })
		u.running = false
	}

	u.mutex.Unlock()

	// 不持锁等待，避免与 run() 中 checkAndUpdateCertificates 获取写锁产生死锁
	u.wg.Wait()
}

// run 运行更新器主循环
func (u *Updater) run() {
	defer u.wg.Done()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	u.logger.Info("Certificate updater started")

	for {
		select {
		case <-u.stopChan:
			u.logger.Info("Certificate updater stopped")
			return

		case <-ticker.C:
			u.checkAndUpdateCertificates()
		}
	}
}

// taskSnapshot 用于无锁比较的任务快照
type taskSnapshot struct {
	domain     string
	config     *CertConfig
	nextUpdate time.Time
	stopChan   chan struct{}
}

// checkAndUpdateCertificates 检查并更新证书
func (u *Updater) checkAndUpdateCertificates() {
	u.mutex.RLock()
	snapshots := make([]taskSnapshot, 0, len(u.tasks))
	for _, task := range u.tasks {
		snapshots = append(snapshots, taskSnapshot{
			domain:     task.Domain,
			config:     task.Config,
			nextUpdate: task.NextUpdate,
			stopChan:   task.StopChan,
		})
	}
	u.mutex.RUnlock()

	now := time.Now()

	for _, snap := range snapshots {
		select {
		case <-snap.stopChan:
			continue
		default:
		}

		if now.After(snap.nextUpdate) || now.Equal(snap.nextUpdate) {
			// I/O 操作在无锁状态下执行
			u.updateCertificate(snap.domain, snap.config)

			// 仅在更新 NextUpdate 时加写锁
			u.mutex.Lock()
			if task, exists := u.tasks[snap.domain]; exists {
				task.NextUpdate = u.calculateNextUpdateTime(task.Config.Remote.UpdateCheckWindow)
			}
			u.mutex.Unlock()
		}
	}
}

// updateCertificate 更新指定域名的证书
func (u *Updater) updateCertificate(domain string, config *CertConfig) {
	u.logger.Info("Checking certificate for update",
		logger.NewField("domain", domain))

	metadata, err := LoadMetadata(u.cacheDir, domain)
	if err != nil {
		u.logger.Warn("Failed to load certificate metadata, forcing update",
			logger.NewField("domain", domain),
			logger.NewField("error", err.Error()))

		u.forceUpdateCertificate(domain, config)
		return
	}

	if metadata.IsExpired() {
		// F6.5（内部PRD §4.6.5）：证书已过期仍在服务（可用性优先的降级
		// 状态）——最高优告警（cert_expired），随后强制续期
		u.logger.Error("Certificate EXPIRED and still being served, forcing renewal",
			logger.NewField("domain", domain),
			logger.NewField("not_after", metadata.NotAfter.Format(time.RFC3339)))
		if u.onRenewalFailed != nil {
			u.onRenewalFailed(domain, -1, "cert_expired:not_after="+metadata.NotAfter.Format(time.RFC3339))
		}
		u.forceUpdateCertificate(domain, config)
		return
	}
	if metadata.IsExpiringSoon() {
		u.logger.Info("Certificate expiring soon, updating",
			logger.NewField("domain", domain),
			logger.NewField("not_after", metadata.NotAfter.Format(time.RFC3339)),
			logger.NewField("days_until_expiry", int(metadata.NotAfter.Sub(time.Now()).Hours()/24)))

		u.forceUpdateCertificate(domain, config)
		return
	}

	u.logger.Debug("Certificate still valid, no update needed",
		logger.NewField("domain", domain),
		logger.NewField("not_after", metadata.NotAfter.Format(time.RFC3339)))
}

// forceUpdateCertificate 强制更新证书
func (u *Updater) forceUpdateCertificate(domain string, config *CertConfig) {
	// 在调用 loadRemoteCertificate 之前读取旧 metadata
	// loadRemoteCertificate 会覆盖磁盘缓存中的 metadata 文件，
	// 之后读取将得到新 metadata，指纹比较永远相等，onCertUpdated 永不触发
	oldMetadata, _ := LoadMetadata(u.cacheDir, domain)

	certPair, err := u.loader.loadRemoteCertificate(domain, config.Remote)
	if err != nil {
		u.logger.Error("Failed to update certificate from remote",
			logger.NewField("domain", domain),
			logger.NewField("error", err.Error()))
		u.noteRenewalFailure(domain, err.Error())
		return
	}
	delete(u.failCounts, domain) // 成功即清零连续失败计数

	// 用指纹比较是否真正更新了（H4）
	if oldMetadata != nil && certPair.Metadata.Fingerprint == oldMetadata.Fingerprint {
		u.logger.Info("Certificate unchanged (fingerprint match)",
			logger.NewField("domain", domain))
		return
	}

	// 通知 Manager 更新内存（C1）
	if u.onCertUpdated != nil {
		u.onCertUpdated(domain, certPair)
	}

	u.logger.Info("Certificate updated successfully",
		logger.NewField("domain", domain),
		logger.NewField("new_not_after", certPair.Metadata.NotAfter.Format(time.RFC3339)),
		logger.NewField("old_not_after", func() string {
			if oldMetadata != nil {
				return oldMetadata.NotAfter.Format(time.RFC3339)
			}
			return "N/A"
		}()))
}

// calculateNextUpdateTime 计算下次更新时间
func (u *Updater) calculateNextUpdateTime(window string) time.Time {
	now := time.Now()

	tomorrow := now.Add(24 * time.Hour)

	randomOffset := RandomTimeInWindow(window)

	nextUpdate := time.Date(tomorrow.Year(), tomorrow.Month(), tomorrow.Day(), 0, 0, 0, 0, time.Local).Add(randomOffset)

	return nextUpdate
}

// GetUpdateStatus 获取更新状态
func (u *Updater) GetUpdateStatus() map[string]UpdateStatus {
	u.mutex.RLock()
	defer u.mutex.RUnlock()

	status := make(map[string]UpdateStatus)
	for domain, task := range u.tasks {
		status[domain] = UpdateStatus{
			Domain:       domain,
			NextUpdate:   task.NextUpdate,
			AutoUpdate:   task.Config.Remote.AutoUpdate,
			UpdateWindow: task.Config.Remote.UpdateCheckWindow,
		}
	}

	return status
}

// UpdateStatus 更新状态
type UpdateStatus struct {
	Domain       string    `json:"domain"`
	NextUpdate   time.Time `json:"next_update"`
	AutoUpdate   bool      `json:"auto_update"`
	UpdateWindow string    `json:"update_window"`
}
