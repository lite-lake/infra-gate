package cert

import (
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// Reconciler 调度与退避常量（内部PRD §8）。
// 数值决定线上收敛节奏与告警频率，勿随意调整。
const (
	// reconcileWorkers 并发 worker 数
	reconcileWorkers = 3
	// retryBaseInterval 退避基数（表内前三项为 1/2/4 倍基数）
	retryBaseInterval = 30 * time.Second
	// retryCapInterval 退避封顶
	retryCapInterval = 5 * time.Minute
	// failedNotifyEvery 连续失败 N 次重发一次告警（5m 封顶下 ≈ 1 小时一次）
	failedNotifyEvery = 12
	// reconcilerStopTimeout Stop 等待在途 worker 的上限
	reconcilerStopTimeout = 30 * time.Second
)

// 可注入变量：实现为 var 以便测试注入短超时/短间隔（内部PRD §15.1），
// 生产代码不得在运行期改写。
var (
	// reconcileAttemptTimeout 单次后台拉取超时（D3-A：60s；ssl-api 服务端签发继续跑，
	// 短超时释放 worker，靠重试捡回已签发完成的证书）
	reconcileAttemptTimeout = 60 * time.Second
	// reconcileTickInterval 调度扫描 pending 的周期
	reconcileTickInterval = 1 * time.Second
	// retryBackoffTable 失败第 N 次对应的重试间隔表（取 min(N-1, 末项)）：
	// 30s → 1m → 2m → 5m 封顶，不引入配置项（内部PRD §8）
	retryBackoffTable = []time.Duration{
		retryBaseInterval,
		2 * retryBaseInterval,
		4 * retryBaseInterval,
		retryCapInterval,
	}
)

// pending 状态取值（内部PRD §9）
const (
	pendingStatusLoading  = "loading"
	pendingStatusRetrying = "retrying"
)

// maxPendingErrorLength pending.last_error 截断上限
// （PRD §10：防止上游响应体回显进 admin API）
const maxPendingErrorLength = 256

// CertNotifier 证书事件通知接口。
// 定义在 cert 包而非直接引用 *notification.Notifier 的原因：避免 cert → notification
// 反向依赖，同时便于测试注入 fake（PRD §9 数据结构旁注）。*notification.Notifier
// 的 SendNotification 签名天然满足该接口。
type CertNotifier interface {
	SendNotification(event string, details map[string]string) error
}

// CertTarget 期望证书集合中的一个目标（host 的 GetEffectiveSSLConfig 结果，
// 由 server.Start 收集，多端口同域名已合并去重）
type CertTarget struct {
	Domain string
	Config *CertConfig
}

// PendingCertState 单个 pending 域名的当前收敛状态（仅内存，无持久化）。
// "已就绪"事实以 Manager.certificates 为唯一真相源：ready 后域名从 pending 移除，
// 不双写（PRD §9）。
type PendingCertState struct {
	Domain              string     `json:"domain"`
	Status              string     `json:"status"` // loading | retrying
	Attempts            int        `json:"attempts"`
	LastError           string     `json:"last_error,omitempty"`
	NextRetryAt         *time.Time `json:"next_retry_at,omitempty"`
	ConsecutiveFailures int        `json:"-"` // 内部限频计数，不对外暴露
}

// Reconciler 证书后台收敛器（内部PRD §7.2）：
// 对每个目标域名调用 Manager 的后台加载变体（复用缓存/远程/注册 Updater 的完整
// 成功路径），失败按退避表持续重试（不设上限，D1），状态跃迁发通知，向 admin 导出快照。
type Reconciler struct {
	manager  *Manager
	notifier CertNotifier
	logger   logger.ILogger

	mu       sync.RWMutex                 // 独立锁：绝不与 Manager.mutex 嵌套（PRD §14.2）
	pending  map[string]*PendingCertState // 全部目标域名的收敛状态（ready 后移除）
	inflight map[string]bool              // 单域名去重：同一域名同时只在一个 worker 中
	targets  map[string]*CertConfig       // domain → 加载配置（构造后只读）

	jobCh    chan string // 容量 = len(targets)，派发非阻塞
	stopChan chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// retryBackoff 失败第 N 次对应的下次重试间隔：min(N-1, 末项)。
// 独立成函数以便表驱动测试退避序列（PRD §15.1），不 sleep。
func retryBackoff(consecutiveFailures int) time.Duration {
	if consecutiveFailures <= 0 {
		return retryBackoffTable[0]
	}
	idx := consecutiveFailures - 1
	if idx >= len(retryBackoffTable) {
		idx = len(retryBackoffTable) - 1
	}
	return retryBackoffTable[idx]
}

// shouldNotifyCertFailure cert_failed 通知限频判定（PRD §7.2）：
// 首次失败必发，此后每连续失败 failedNotifyEvery 次重发一次，避免告警刷屏。
func shouldNotifyCertFailure(consecutiveFailures int) bool {
	return consecutiveFailures == 1 || consecutiveFailures%failedNotifyEvery == 0
}

// truncatePendingError 截断错误摘要（PRD §10：≤256 字符）
func truncatePendingError(err error) string {
	msg := err.Error()
	if len(msg) > maxPendingErrorLength {
		return msg[:maxPendingErrorLength]
	}
	return msg
}

// cloneCertConfigWithTimeout 克隆 CertConfig 并仅覆写副本的 Remote.Timeout（D3 关键实现约束）。
// Remote 是指针且同一 *CertConfig 会被 Updater 长期持有（夜间续期必须保持配置默认
// 6 分钟超时，PRD §7.2 / §14.2），因此绝不能原地改 Timeout——浅拷贝 CertConfig +
// 浅拷贝 RemoteCertConfig 后仅覆写副本字段，原 config（含 Remote 指针指向的值）零污染。
func cloneCertConfigWithTimeout(config *CertConfig, timeout time.Duration) *CertConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	if config.Remote != nil {
		remote := *config.Remote
		remote.Timeout = timeout
		cloned.Remote = &remote
	}
	return &cloned
}

// newReconciler 创建 Reconciler：pending 以 loading 态收录全部目标（去重），
// NextRetryAt 为 nil 使首个调度 tick 即派发。
func newReconciler(manager *Manager, targets []CertTarget, notifier CertNotifier, log logger.ILogger) *Reconciler {
	r := &Reconciler{
		manager:  manager,
		notifier: notifier,
		logger:   log,
		pending:  make(map[string]*PendingCertState),
		inflight: make(map[string]bool),
		targets:  make(map[string]*CertConfig),
		stopChan: make(chan struct{}),
	}
	for _, t := range targets {
		// 防御：空域名/nil 配置的目标无法收敛，直接丢弃
		if t.Domain == "" || t.Config == nil {
			continue
		}
		if _, exists := r.targets[t.Domain]; exists {
			continue // 多端口同域名去重（server.Start 已合并，此处兜底）
		}
		r.targets[t.Domain] = t.Config
		r.pending[t.Domain] = &PendingCertState{Domain: t.Domain, Status: pendingStatusLoading}
	}
	r.jobCh = make(chan string, len(r.targets))
	return r
}

// start 启动 1 个调度 goroutine + reconcileWorkers 个 worker（PRD §7.2 工作模型）
func (r *Reconciler) start() {
	r.wg.Add(1 + reconcileWorkers)
	go r.schedulerLoop()
	for i := 0; i < reconcileWorkers; i++ {
		go r.workerLoop()
	}
}

// Stop 停止 Reconciler 并等待在途 worker（上限 reconcilerStopTimeout）。
// 60s 拉取超时的在途请求最多再等一个余量，超时则 Warn 后继续，不悬挂优雅关闭。
// 幂等：stopOnce 保证二次调用为 no-op（PRD §7.2）。
func (r *Reconciler) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopChan)

		done := make(chan struct{})
		go func() {
			r.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(reconcilerStopTimeout):
			r.logger.Warn("Reconciler stop timed out waiting for in-flight workers, proceeding",
				logger.NewField("timeout", reconcilerStopTimeout.String()))
		}
	})
}

// schedulerLoop 调度主循环：每 tick 扫描一次 pending
func (r *Reconciler) schedulerLoop() {
	defer r.wg.Done()

	ticker := time.NewTicker(reconcileTickInterval)
	defer ticker.Stop()

	r.logger.Info("Certificate reconciler scheduler started",
		logger.NewField("targets", len(r.targets)),
		logger.NewField("workers", reconcileWorkers),
		logger.NewField("tick", reconcileTickInterval.String()))

	for {
		select {
		case <-r.stopChan:
			r.logger.Info("Certificate reconciler scheduler stopped")
			return
		case <-ticker.C:
			r.scheduleOnce()
		}
	}
}

// scheduleOnce 单轮调度，三阶段执行以恪守锁纪律（PRD §14.2：pending 锁绝不与
// Manager.mutex 嵌套——Manager 锁在 TLS 握手热路径上）：
//  1. 仅持 pending 锁：收集全部 pending 域名与其中"未 inflight 且到期"的派发候选；
//  2. 仅 Manager 锁（HasCertificate）：外部路径（admin 手动更新等）就绪判定，
//     以内存 map 为唯一真相源（PRD §7.2），就绪者从 pending 静默移除（不发通知）——
//     判定不分 inflight：worker 在途时外部路径已就绪的域名同样立即移除，
//     worker 之后的成功/失败落账对已删除条目自动作废；
//  3. 仅持 pending 锁：派发到期域名并标记 inflight（单域名去重），
//     jobCh 满时非阻塞 send 失败回滚 inflight（防御，下轮 tick 重新调度）。
func (r *Reconciler) scheduleOnce() {
	now := time.Now()

	// 阶段 1：收集全部 pending 域名 + 派发候选（未 inflight 且 NextRetryAt==nil 或已到期）
	r.mu.Lock()
	all := make([]string, 0, len(r.pending))
	var dispatchCandidates []string
	for domain, state := range r.pending {
		all = append(all, domain)
		if r.inflight[domain] {
			continue
		}
		if state.NextRetryAt != nil && state.NextRetryAt.After(now) {
			continue
		}
		dispatchCandidates = append(dispatchCandidates, domain)
	}
	r.mu.Unlock()

	// 阶段 2：外部就绪判定（只碰 Manager 锁）
	var ready []string
	var due []string
	for _, domain := range all {
		if r.manager.HasCertificate(domain) {
			ready = append(ready, domain)
			continue
		}
		due = append(due, domain)
	}

	// 阶段 3：应用移除与派发。
	// all/due 来自阶段 1 快照：期间 pending 条目只会被 worker 落账删除
	//（inflight 域名）或被本函数移除，delete 对缺失键为 no-op，无需二次校验。
	r.mu.Lock()
	for _, domain := range ready {
		delete(r.pending, domain) // 静默移除：外部路径就绪不发通知（PRD §7.2）
	}
	for _, domain := range due {
		if r.inflight[domain] {
			continue
		}
		if _, exists := r.pending[domain]; !exists {
			continue // 阶段 2 判定后、加锁前被 worker 落账删除（成功即就绪）
		}
		r.inflight[domain] = true
		select {
		case r.jobCh <- domain:
		default:
			// 防御：jobCh 满时回滚 inflight，等待下轮 tick
			delete(r.inflight, domain)
		}
	}
	r.mu.Unlock()
}

// workerLoop 从 jobCh 取域名并处理，直到 Stop
func (r *Reconciler) workerLoop() {
	defer r.wg.Done()
	for {
		select {
		case <-r.stopChan:
			return
		case domain := <-r.jobCh:
			r.processDomain(domain)
		}
	}
}

// configFor 读取域名的加载配置（targets 构造后只读，RLock 仅防御未来变更）
func (r *Reconciler) configFor(domain string) *CertConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.targets[domain]
}

// processDomain worker 处理单个域名（PRD §7.2）。
// inflight 的释放在 defer 统一完成：成功/失败/panic 任一路径都必须清除，
// 否则该域名永久失去派发资格。
func (r *Reconciler) processDomain(domain string) {
	defer func() {
		if rec := recover(); rec != nil {
			r.logger.Error("Panic in reconciler worker",
				logger.NewField("domain", domain),
				logger.NewField("panic", fmt.Sprintf("%v", rec)))
		}
		r.mu.Lock()
		delete(r.inflight, domain)
		r.mu.Unlock()
	}()

	// Stop 后不再发起新的加载（防 select 双就绪时多跑一轮）
	select {
	case <-r.stopChan:
		return
	default:
	}

	config := r.configFor(domain)
	if config == nil {
		// 防御：目标配置缺失（newReconciler 已过滤），放弃该域名
		r.mu.Lock()
		delete(r.pending, domain)
		r.mu.Unlock()
		return
	}

	// 缓存命中静默判定（PRD §7.2 / §7.5）：远程拉取前先探测本地缓存；命中则本次
	// 属"缓存路径"——重启后缓存秒就绪是常态，不该触发 cert_ready 告警渠道。
	// 同包直接访问 loader.loadFromCache，不改 Loader 签名（PRD §14.2）。
	_, cacheErr := r.manager.loader.loadFromCache(domain)
	cacheHit := cacheErr == nil

	_, err := r.manager.LoadCertificateBackground(domain, config, reconcileAttemptTimeout)
	if err != nil {
		r.handleFailure(domain, err)
		return
	}
	r.handleSuccess(domain, cacheHit)
}

// handleSuccess 加载成功：从 pending 移除并清退避计数（随条目销毁，无需独立清理）；
// 仅非缓存路径发 cert_ready（details：域名、not_after、attempts）。
// LoadCertificateBackground 成功即已写内存 + 注册 Updater（Manager 既有逻辑），
// 下一次 TLS 握手即插即用，Reconciler 无需额外动作（PRD §6.3）。
func (r *Reconciler) handleSuccess(domain string, cacheHit bool) {
	attempts := 1
	r.mu.Lock()
	if state, exists := r.pending[domain]; exists {
		attempts = state.Attempts + 1 // 含本次成功的尝试序号
		delete(r.pending, domain)
	}
	r.mu.Unlock()

	if cacheHit {
		return // 缓存路径静默（PRD §7.5）
	}

	notAfter := ""
	if meta, err := r.manager.GetCertificateMetadata(domain); err == nil && meta != nil {
		notAfter = meta.NotAfter.Format(time.RFC3339)
	}

	r.logger.Info("Certificate ready, domain now serving HTTPS",
		logger.NewField("domain", domain),
		logger.NewField("attempts", attempts))

	if r.notifier != nil {
		_ = r.notifier.SendNotification("cert_ready", map[string]string{
			"domain":    domain,
			"not_after": notAfter,
			"attempts":  strconv.Itoa(attempts),
		})
	}
}

// handleFailure 加载失败：更新退避状态（Status=retrying、错误截断、计数累加、
// NextRetryAt=now+backoff(N)）；重试不设上限（D1：持续收敛）。
// 通知限频：首次失败 + 每连续失败 failedNotifyEvery 次重发 cert_failed。
func (r *Reconciler) handleFailure(domain string, loadErr error) {
	lastErr := truncatePendingError(loadErr)

	r.mu.Lock()
	state, exists := r.pending[domain]
	if !exists {
		// pending 已被移除（admin 手动更新等外部路径已就绪）：本次失败作废，
		// 不 resurrect 条目、不发通知（PRD §7.2 以内存 map 为准）
		r.mu.Unlock()
		return
	}
	state.Status = pendingStatusRetrying
	state.Attempts++
	state.ConsecutiveFailures++
	state.LastError = lastErr
	wait := retryBackoff(state.ConsecutiveFailures)
	nextRetryAt := time.Now().Add(wait)
	state.NextRetryAt = &nextRetryAt
	attempts := state.Attempts
	failures := state.ConsecutiveFailures
	r.mu.Unlock()

	// 日志纪律（PRD §14.2）：重试失败用 Warn（含 attempts/next_retry_in），不刷 Error
	r.logger.Warn("Certificate load failed, scheduled for retry",
		logger.NewField("domain", domain),
		logger.NewField("attempts", attempts),
		logger.NewField("consecutive_failures", failures),
		logger.NewField("next_retry_in", wait.String()),
		logger.NewField("error", lastErr))

	if shouldNotifyCertFailure(failures) && r.notifier != nil {
		// SendNotification 本身 best-effort，失败不影响收敛循环（PRD §14.2）
		_ = r.notifier.SendNotification("cert_failed", map[string]string{
			"domain":               domain,
			"error":                lastErr,
			"attempts":             strconv.Itoa(attempts),
			"consecutive_failures": strconv.Itoa(failures),
		})
	}
}

// snapshot 导出按域名排序的深拷贝快照（admin /api/certs 用）。
// NextRetryAt 指针一并深拷贝，避免外部持有快照期间内部状态翻转被观察到。
func (r *Reconciler) snapshot() []PendingCertState {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]PendingCertState, 0, len(r.pending))
	for _, state := range r.pending {
		cp := *state
		if state.NextRetryAt != nil {
			nextRetryAt := *state.NextRetryAt
			cp.NextRetryAt = &nextRetryAt
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}
