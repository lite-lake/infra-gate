// Package crs 负责 OWASP CRS 规则包的启动期保障（内部PRD）：
// 缓存状态机（valid/stale/absent）、原子缓存替换、下载预算收敛、本地金副本兜底、
// 失败策略（degrade/fail）与状态发布（供 admin API 与启动通知读取）。
//
// 核心纪律：
//   - 任何失败路径永不删除旧缓存；只有新目录完整校验通过后才原子切换；
//   - 所有网络调用必须带 context 超时，受总预算约束，禁止无界等待；
//   - 金副本目录只读使用，不拷贝、不写入缓存目录。
package crs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

const (
	// CRSReleaseAPI 获取最新版本的API
	CRSReleaseAPI = "https://api.github.com/repos/coreruleset/coreruleset/releases/latest"
	// CRSReleaseAPITemplate 获取指定版本的API
	CRSReleaseAPITemplate = "https://api.github.com/repos/coreruleset/coreruleset/releases/tags/%s"
	// DefaultCRSVersion 默认CRS版本（与 yamlops 生成配置一致，内部PRD）
	DefaultCRSVersion = "v4.19.0"
	// minCRSTarballSize CRS tarball 最小合理大小（100KB），低于此值可能是空内容或被截断
	minCRSTarballSize = 100 * 1024
	// minCRSRuleFileCount CRS rules 目录中最少应有的 .conf 文件数。
	// 注意：CRS v4 的数百条规则分布在少量 .conf 文件内，官方发行包 rules/ 实际仅含
	// 26 个 .conf（codeload 完整归档与镜像 minimal 包一致），阈值必须低于该值，
	// 否则完整官方包也会被误判残缺（历史上曾致网关启动失败）。取 20 仍可拦截
	// 仅含个位数文件的截断/残缺下载。
	minCRSRuleFileCount = 20
	// minCRSRulesTotalSize CRS rules 目录中最少应有的文件总大小（500KB）
	minCRSRulesTotalSize = 500 * 1024
	// metadataCallTimeout 单次元数据（版本/SHA/URL）请求超时（内部PRD §5.3）
	metadataCallTimeout = 10 * time.Second
	// metadataMaxAttempts 元数据最大尝试轮数（多镜像端点故障转移共享该预算）
	metadataMaxAttempts = 2
	// oldVersionsToKeep 原子切换后保留的 .old-* 旧缓存份数（超出异步清理）
	oldVersionsToKeep = 2
	// maxManifestDiffLines 哈希不一致诊断日志中每类差异的最大输出行数（防刷屏）
	maxManifestDiffLines = 50

	// pinsManifestFileName 金副本根目录下的 pin 清单文件名（H2，内部PRD §7.3）。
	// 镜像内完整路径 /app/crs/pins.sha256（DefaultCRSGoldenDir + 本文件名，与
	// Dockerfile-prod/dev 的 COPY 目标一致）；文件缺失视为「无清单」而非错误
	pinsManifestFileName = "pins.sha256"

	// ── M2（内部PRD §1.3）：CRS 下载/元数据/解压三级大小上限 ──
	// gzip 炸弹与内存/磁盘 DoS 防线：全部经 io.LimitReader/计数有界读取，超限立即失败
	// maxTarballBytes tarball 下载响应体上限（100MB）
	maxTarballBytes = 100 * 1024 * 1024
	// maxMetadataBytes 元数据响应体上限（1MB）
	maxMetadataBytes = 1 * 1024 * 1024
	// maxExtractTotalBytes 单次解压累计总量上限（300MB）
	maxExtractTotalBytes = 300 * 1024 * 1024
	// maxExtractSingleFileBytes 解压单文件上限（100MB）
	maxExtractSingleFileBytes = 100 * 1024 * 1024
)

// pin 期望哈希来源取值（H2 日志与测试断言用）
const (
	// pinSourceConfig 配置 waf.crs.download.pinned_sha256（最高优先）
	pinSourceConfig = "config"
	// pinSourceManifest 金副本根目录 pins.sha256 清单
	pinSourceManifest = "manifest"
)

// sha256HexLength 十六进制 SHA256 摘要长度（pin 清单行格式校验用）
const sha256HexLength = 64

// CRS 状态机状态取值（内部PRD §5.1）
const (
	// StateValid 缓存存在且哈希匹配（或从金副本/下载完整校验通过）
	StateValid = "valid"
	// StateStale 缓存存在但哈希不匹配/无 hash 文件/哈希计算失败，已按旧缓存启动
	StateStale = "stale"
	// StateDegraded 无任何可用 CRS，按 failure_policy=degrade 无 WAF 启动
	StateDegraded = "degraded"
)

// CRS 来源取值（EnsureCRS 结果与 admin API 的 crs_source）
const (
	// SourceNone 无来源（degraded）
	SourceNone = ""
	// SourceCache 本地可写缓存
	SourceCache = "cache"
	// SourceGolden 本地金副本（只读）
	SourceGolden = "golden"
	// SourceMirror 镜像站下载
	SourceMirror = "mirror"
	// SourceProxy 经代理下载
	SourceProxy = "proxy"
	// SourceDownload 直连（GitHub Release / codeload）下载
	SourceDownload = "download"
)

// IntegrityReasonCode 缓存完整性校验结构化原因（F10，内部PRD §4.10.1）
const (
	// IntegrityOK 校验通过
	IntegrityOK = ""
	// ReasonHashFileMissing 无 hash 文件（历史遗留缓存，宽松档）
	ReasonHashFileMissing = "hash_file_missing"
	// ReasonHashDeleted hash 文件被删（.manifest 在场佐证两者同批原子落盘，严格档）
	ReasonHashDeleted = "hash_deleted"
	// ReasonHashMismatch hash 不匹配（严格档：疑似篡改）
	ReasonHashMismatch = "hash_mismatch"
	// ReasonHashComputeFailed 目录哈希计算失败（严格档：疑似篡改/损坏）
	ReasonHashComputeFailed = "hash_compute_failed"
)

// IntegrityStatus Status.Integrity 取值（F10）：
// ok = 校验通过；stale-unverified = 宽松档旧缓存（未经完整性验证）；
// tampered = 存在篡改证据（hash 在场不匹配/被删/计算失败）
const (
	IntegrityStatusVerified   = "ok"
	IntegrityStatusStaleUnver = "stale-unverified"
	IntegrityStatusTampered   = "tampered"
)

// IntegrityReason 结构化校验原因（Code 为 IntegrityOK 时其余字段为零值）
type IntegrityReason struct {
	Code   string
	Detail string
}

// IsStrictTier 是否严格档（有篡改证据）：hash 在场不匹配/被删/计算失败
func (r IntegrityReason) IsStrictTier() bool {
	switch r.Code {
	case ReasonHashMismatch, ReasonHashDeleted, ReasonHashComputeFailed:
		return true
	}
	return false
}

// ErrCRSDegraded 降级哨兵错误：failure_policy=degrade 且无任何可用 CRS。
// 调用方（waf.CreateWAF）应以 errors.Is 识别并转为 ErrWAFDegraded，使对应配置
// 无 WAF 启动而非进程退出。
var ErrCRSDegraded = errors.New("crs degraded: no usable CRS available")

// Result EnsureCRS 的富结果：目录 + 状态 + 来源 + 错误（内部PRD §5.1）。
// State 取值 StateValid/StateStale/StateDegraded；硬失败（fail 策略路径）时 State 为空串。
type Result struct {
	// Dir 本次可加载的 CRS 规则目录；degraded/硬失败时为空串
	Dir string
	// State valid | stale | degraded（硬失败时为空串）
	State string
	// Source cache | golden | mirror | proxy | download | ""（degraded）
	Source string
	// Err degraded 时为包装 ErrCRSDegraded 的错误；fail 策略失败时为普通错误；成功为 nil
	Err error
}

// Status CRS 运行状态快照（状态注册表条目，供 admin API 与启动通知读取）
type Status struct {
	// State valid | stale | degraded
	State string
	// Version CRS 版本（注册表键）
	Version string
	// Source cache | golden | mirror | proxy | download | ""
	Source string
	// Dir 当前生效的规则目录（degraded 时为空）
	Dir string
	// CacheAgeSeconds 缓存目录 ModTime 距今的秒数（degraded 时为 0）
	CacheAgeSeconds int64
	// LastError 最近一次失败原因（成功后清空）
	LastError string
	// Integrity F10（additive）：ok | stale-unverified | tampered | ""（未评估）
	Integrity string
	// CheckedAt 本次状态发布时间
	CheckedAt time.Time
}

// statusRegistry 包级状态注册表：EnsureCRS 发布、admin API / 启动通知读取。
// 按 version 键控；并发安全（sync.RWMutex）。
var statusRegistry = &statusStore{entries: make(map[string]Status)}

type statusStore struct {
	mu      sync.RWMutex
	entries map[string]Status
}

// PublishStatus 发布指定版本的 CRS 状态（EnsureCRS 内部调用；导出供测试/未来扩展）
func PublishStatus(version string, st Status) {
	statusRegistry.mu.Lock()
	defer statusRegistry.mu.Unlock()
	st.Version = version
	statusRegistry.entries[version] = st
}

// StatusSnapshot 读取指定版本的 CRS 状态快照（值拷贝）。不存在时返回 (零值, false)
func StatusSnapshot(version string) (Status, bool) {
	statusRegistry.mu.RLock()
	defer statusRegistry.mu.RUnlock()
	st, ok := statusRegistry.entries[version]
	return st, ok
}

// AllStatuses 返回全部版本的 CRS 状态快照（深拷贝，键为版本号）
func AllStatuses() map[string]Status {
	statusRegistry.mu.RLock()
	defer statusRegistry.mu.RUnlock()
	result := make(map[string]Status, len(statusRegistry.entries))
	for k, v := range statusRegistry.entries {
		result[k] = v
	}
	return result
}

// ResolveVersion 归一化 CRS 版本：空串取 DefaultCRSVersion
func ResolveVersion(version string) string {
	if version == "" {
		return DefaultCRSVersion
	}
	return version
}

// GitHubReleaseAsset GitHub Release 附件信息
type GitHubReleaseAsset struct {
	Name               string `json:"name"`
	Digest             string `json:"digest"` // 格式: "sha256:xxxx"
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// GitHubRelease GitHub发布信息
type GitHubRelease struct {
	TagName    string               `json:"tag_name"`
	TarballURL string               `json:"tarball_url"`
	Assets     []GitHubReleaseAsset `json:"assets"`
}

// Manager CRS管理器：状态机 + 原子替换 + 预算下载 + 金副本 + 状态发布。
// 实例可并发使用；同一版本的 EnsureCRS 经 per-version 互斥串行化（PRD §11.1）。
type Manager struct {
	cacheDir  string // 可写缓存根目录（内含 owasp_crs/ 子目录）
	goldenDir string // 有效金副本根目录；空 = 禁用
	logger    logger.ILogger
	config    *config.WAFCRSConfig

	httpClient *http.Client // 无整体 Timeout：每次请求以 context 预算控制（PRD §10.1）

	locksMu sync.Mutex
	locks   map[string]*sync.Mutex // per-version 互斥，防并发 EnsureCRS 相互覆盖 staging
}

// NewManager 创建CRS管理器。cacheDir 为可写缓存根目录（历史约定，owasp_crs 挂其下）；
// crsConfig 为 nil 时按最保守默认工作（无金副本、无镜像、无代理、无 pin → 拒绝下载）。
func NewManager(cacheDir string, log logger.ILogger, crsConfig *config.WAFCRSConfig) *Manager {
	// GetEffectiveGoldenDir 的返回约定保证「启用时目录非空、禁用时为空串」，
	// 故 m.goldenDir != "" 即金副本启用
	goldenDir := ""
	if crsConfig != nil {
		goldenDir, _ = crsConfig.GetEffectiveGoldenDir()
		// H2（内部PRD D6）：明文镜像显式放行属受控逃生口，启动 Warn 提升可见性
		//（完整性此时完全依赖 pin 校验）
		if crsConfig.Download.GetEffectiveMirrorAllowInsecureHTTP() {
			log.Warn("waf.crs.download.mirror_allow_insecure_http=true: plaintext http mirror endpoints are ALLOWED, tarball integrity relies solely on pinned sha256",
				logger.NewField("config", "waf.crs.download.mirror_allow_insecure_http"))
		}
	}

	return &Manager{
		cacheDir:   cacheDir,
		goldenDir:  goldenDir,
		logger:     log,
		config:     crsConfig,
		httpClient: &http.Client{},
		locks:      make(map[string]*sync.Mutex),
	}
}

// crsRoot 可写缓存的 owasp_crs 子目录（PRD §5.2 布局的根）
func (m *Manager) crsRoot() string {
	return filepath.Join(m.cacheDir, "owasp_crs")
}

func (m *Manager) activeDir(version string) string {
	return filepath.Join(m.crsRoot(), version)
}

func (m *Manager) hashFilePath(version string) string {
	return filepath.Join(m.crsRoot(), version+".sha256")
}

func (m *Manager) manifestFilePath(version string) string {
	return filepath.Join(m.crsRoot(), version+".manifest")
}

// lockVersion 获取指定版本的互斥锁，返回解锁函数（PRD §11.1 并发约束）
func (m *Manager) lockVersion(version string) func() {
	m.locksMu.Lock()
	defer m.locksMu.Unlock()
	if m.locks == nil {
		m.locks = make(map[string]*sync.Mutex)
	}
	l, ok := m.locks[version]
	if !ok {
		l = &sync.Mutex{}
		m.locks[version] = l
	}
	l.Lock()
	return l.Unlock
}

// EnsureCRS 确保 CRS 可用，返回富结果（目录 + 状态 + 来源 + 错误）。
//
// 状态机（内部PRD §5.1）：
//   - valid：缓存目录存在且 .sha256 匹配 → 直接返回目录，零网络调用；
//   - stale：缓存存在但哈希不匹配/哈希计算失败/无 hash 文件 → 先按预算刷新；
//     成功则原子切换（状态 valid）；失败保留旧缓存并以旧目录启动（状态 stale）；
//   - absent：缓存不存在 → 金副本（只读）→ 镜像站/代理下载；都失败按
//     failure_policy 处理（degrade → ErrCRSDegraded 哨兵；fail → 普通错误）。
func (m *Manager) EnsureCRS(version string) Result {
	version = ResolveVersion(version)

	// per-version 互斥：并发 EnsureCRS 不得产生相互覆盖的 staging（PRD §11.1）
	defer m.lockVersion(version)()

	crsDir := m.activeDir(version)
	hashFile := m.hashFilePath(version)
	manifestFile := m.manifestFilePath(version)

	// ── 状态一：缓存目录存在 ──
	if m.dirExists(crsDir) {
		reason := m.verifyCacheIntegrity(crsDir, hashFile, manifestFile, version)
		if reason.Code == IntegrityOK {
			m.logger.Info("CRS cache integrity verified, using cache",
				logger.NewField("version", version),
				logger.NewField("path", crsDir))
			m.publish(version, StateValid, SourceCache, crsDir, IntegrityStatusVerified, "")
			return Result{Dir: crsDir, State: StateValid, Source: SourceCache}
		}
		// F10（内部PRD §4.10.1）旁路检测：hash 缺失但 .manifest 在场
		//（两者同批原子落盘）→ 判定「哈希文件被删」升级严格档（封堵删哈希旁路）
		if reason.Code == ReasonHashFileMissing && m.regularFileExists(manifestFile) {
			reason = IntegrityReason{Code: ReasonHashDeleted, Detail: "hash file missing while .manifest present"}
		}

		// stale：先按预算尝试刷新（成功即原子替换为可信内容）
		m.logger.Warn("CRS cache is stale, attempting in-budget refresh",
			logger.NewField("version", version),
			logger.NewField("reason", reason.Code),
			logger.NewField("detail", reason.Detail))
		source, err := m.refreshCRS(version)
		if err == nil {
			// F10.3：疑似篡改 + 刷新成功（已原子替换）仍保留 tampered 证据标记，
			// 供 admin/告警读取（一次性 tampered 告警由 server 侧读取状态发出）
			integrity := ""
			if reason.IsStrictTier() {
				integrity = IntegrityStatusTampered
			}
			m.publish(version, StateValid, source, crsDir, integrity, "")
			return Result{Dir: crsDir, State: StateValid, Source: source}
		}

		// 刷新失败：按「是否具备篡改证据」分档处置（F10.2，PRD §4.10.2）
		if reason.IsStrictTier() {
			// 严格档（疑似篡改）：被篡改缓存永不加载；金副本兜底（不跨版本
			// substitution——版本是 yamlops 下发的配置契约）；目录原位保留（取证
			// + 维持「失败路径永不删旧缓存」纪律）
			m.logger.Error("CRS cache integrity evidence of tampering, refusing to load (strict tier)",
				logger.NewField("version", version),
				logger.NewField("reason", reason.Code),
				logger.NewField("path", crsDir),
				logger.NewField("refresh_error", err.Error()))
			goldenVersionDir := m.goldenDirFor(version)
			if goldenVersionDir != "" {
				m.logger.Warn("Using read-only golden CRS copy after tamper evidence (stale until restart)",
					logger.NewField("version", version),
					logger.NewField("path", goldenVersionDir))
				m.publish(version, StateStale, SourceGolden, goldenVersionDir, IntegrityStatusTampered, err.Error())
				return Result{Dir: goldenVersionDir, State: StateStale, Source: SourceGolden}
			}
			// 无金副本：按 failure_policy 处置（degrade 哨兵 / fail 报错）
			if m.failurePolicy() == config.WAFFailurePolicyDegrade {
				derr := fmt.Errorf("%w: version=%s cache tampered (%s) and no golden copy: %v", ErrCRSDegraded, version, reason.Code, err)
				m.publish(version, StateDegraded, SourceNone, "", IntegrityStatusTampered, derr.Error())
				return Result{Dir: "", State: StateDegraded, Source: SourceNone, Err: derr}
			}
			// 注册表留痕（进程将按 fail 策略退出，条目供启动通知/测试读取）
			m.publish(version, "", SourceNone, "", IntegrityStatusTampered, err.Error())
			return Result{Dir: "", State: "", Source: SourceNone, Err: fmt.Errorf("CRS cache tampered (%s) and refresh failed, no golden copy for version %s: %w", reason.Code, version, err)}
		}

		// 宽松档（无 hash 文件的历史遗留缓存，可用性优先）：金副本有该版本则用
		// 金副本（封堵「删哈希降档」旁路——攻击者删 hash 即可让篡改缓存走宽松档）
		if goldenVersionDir := m.goldenDirFor(version); goldenVersionDir != "" {
			m.logger.Warn("Using golden CRS copy instead of unverified legacy cache (loose tier)",
				logger.NewField("version", version),
				logger.NewField("path", goldenVersionDir))
			m.publish(version, StateValid, SourceGolden, goldenVersionDir, IntegrityStatusVerified, "")
			return Result{Dir: goldenVersionDir, State: StateValid, Source: SourceGolden}
		}
		// 无金副本：维持 D4（内部PRD）加载旧缓存（可用性优先）
		m.logger.Warn("CRS refresh failed, starting with stale cache (old cache preserved, integrity unverified)",
			logger.NewField("version", version),
			logger.NewField("path", crsDir),
			logger.NewField("error", err.Error()))
		m.publish(version, StateStale, SourceCache, crsDir, IntegrityStatusStaleUnver, err.Error())
		return Result{Dir: crsDir, State: StateStale, Source: SourceCache}
	}

	// ── 状态二：缓存不存在（absent）──
	// 优先金副本（只读使用，不拷贝、不写缓存；PRD §5.5 优先级 valid cache > golden > 下载）
	if m.goldenDir != "" {
		goldenVersionDir := filepath.Join(m.goldenDir, version)
		if m.dirExists(goldenVersionDir) {
			if err := m.verifyCRSStructure(goldenVersionDir); err != nil {
				m.logger.Warn("Golden CRS copy failed structure verification, skipping",
					logger.NewField("version", version),
					logger.NewField("path", goldenVersionDir),
					logger.NewField("error", err.Error()))
			} else {
				m.logger.Info("Using read-only golden CRS copy",
					logger.NewField("version", version),
					logger.NewField("path", goldenVersionDir))
				m.publish(version, StateValid, SourceGolden, goldenVersionDir, IntegrityStatusVerified, "")
				return Result{Dir: goldenVersionDir, State: StateValid, Source: SourceGolden}
			}
		} else {
			m.logger.Debug("No golden CRS copy for version",
				logger.NewField("version", version),
				logger.NewField("golden_dir", m.goldenDir))
		}
	}

	// 镜像站/代理下载
	source, err := m.refreshCRS(version)
	if err == nil {
		m.publish(version, StateValid, source, crsDir, IntegrityStatusVerified, "")
		return Result{Dir: crsDir, State: StateValid, Source: source}
	}

	// 全部失败：按 failure_policy 处理（PRD §5.4）
	if m.failurePolicy() == config.WAFFailurePolicyDegrade {
		derr := fmt.Errorf("%w: version=%s: %v", ErrCRSDegraded, version, err)
		m.logger.Error("CRS unavailable, degrading per failure_policy=degrade (WAF will not start for this config)",
			logger.NewField("version", version),
			logger.NewField("error", err.Error()))
		m.publish(version, StateDegraded, SourceNone, "", "", derr.Error())
		return Result{Dir: "", State: StateDegraded, Source: SourceNone, Err: derr}
	}

	// fail（默认）：维持现状——返回普通错误，由调用方使 WAF 构造失败
	m.logger.Error("CRS unavailable, failing per failure_policy=fail",
		logger.NewField("version", version),
		logger.NewField("error", err.Error()))
	return Result{Dir: "", State: "", Source: SourceNone, Err: fmt.Errorf("failed to ensure CRS: %w", err)}
}

// verifyCacheIntegrity 校验缓存完整性，返回结构化原因（F10：Code 为 IntegrityOK
// 表示 valid）。哈希不匹配时若存在 .manifest 诊断清单，输出「期望 vs 实际」文件
// 差异日志（PRD §4.7/§10.4）。
func (m *Manager) verifyCacheIntegrity(crsDir, hashFile, manifestFile, version string) IntegrityReason {
	stored, err := os.ReadFile(hashFile)
	if err != nil {
		// 旧版本缓存无 hash 文件：宽松档（先刷新，失败仍可用；旁路升级由调用方判定）
		m.logger.Warn("CRS cache exists but integrity hash file is missing/unreadable",
			logger.NewField("version", version),
			logger.NewField("path", crsDir),
			logger.NewField("error", err.Error()))
		return IntegrityReason{Code: ReasonHashFileMissing, Detail: err.Error()}
	}
	actual, err := m.hashDirectory(crsDir)
	if err != nil {
		m.logger.Warn("Failed to compute CRS cache directory hash",
			logger.NewField("version", version),
			logger.NewField("error", err.Error()))
		return IntegrityReason{Code: ReasonHashComputeFailed, Detail: err.Error()}
	}
	if !strings.EqualFold(strings.TrimSpace(string(stored)), actual) {
		m.logger.Warn("CRS cache integrity check failed (hash mismatch)",
			logger.NewField("version", version),
			logger.NewField("expected", truncHash(strings.TrimSpace(string(stored)))),
			logger.NewField("actual", truncHash(actual)))
		m.logManifestDiff(manifestFile, crsDir, version)
		return IntegrityReason{Code: ReasonHashMismatch, Detail: "stored hash does not match directory hash"}
	}
	return IntegrityReason{Code: IntegrityOK}
}

// regularFileExists 路径存在且为常规文件（目录占位不算同批原子落盘的证据）
func (m *Manager) regularFileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// goldenDirFor 金副本中该版本的可用目录（结构校验通过），无则空串（F10 分档用）
func (m *Manager) goldenDirFor(version string) string {
	if m.goldenDir == "" {
		return ""
	}
	g := filepath.Join(m.goldenDir, version)
	if !m.dirExists(g) {
		return ""
	}
	if err := m.verifyCRSStructure(g); err != nil {
		m.logger.Warn("Golden CRS copy failed structure verification, unusable",
			logger.NewField("path", g),
			logger.NewField("error", err.Error()))
		return ""
	}
	return g
}

// logManifestDiff 哈希不一致时的文件清单差异诊断（相对路径 + 大小 + 前后哈希），
// 用于定位类似 2026-09-15 的「缓存哈希不一致」问题（PRD §4.7/§10.4）。
// 任何失败（无清单/解析失败）只记日志，绝不影响主流程。
func (m *Manager) logManifestDiff(manifestFile, crsDir, version string) {
	raw, err := os.ReadFile(manifestFile)
	if err != nil {
		m.logger.Debug("No CRS manifest available for hash-mismatch diff diagnosis",
			logger.NewField("version", version),
			logger.NewField("error", err.Error()))
		return
	}
	oldEntries, err := parseManifest(raw)
	if err != nil {
		m.logger.Warn("Failed to parse CRS manifest for diff diagnosis",
			logger.NewField("version", version),
			logger.NewField("error", err.Error()))
		return
	}
	newRaw, err := buildManifestData(crsDir)
	if err != nil {
		m.logger.Warn("Failed to build current CRS manifest for diff diagnosis",
			logger.NewField("version", version),
			logger.NewField("error", err.Error()))
		return
	}
	newEntries, err := parseManifest(newRaw)
	if err != nil {
		m.logger.Warn("Failed to parse current CRS manifest for diff diagnosis",
			logger.NewField("version", version),
			logger.NewField("error", err.Error()))
		return
	}

	var changed, removed, added []string
	for path, old := range oldEntries {
		if nw, ok := newEntries[path]; ok {
			if old.Hash != nw.Hash || old.Size != nw.Size {
				changed = append(changed, fmt.Sprintf("%s: size %d -> %d, hash %s -> %s", path, old.Size, nw.Size, old.Hash, nw.Hash))
			}
		} else {
			removed = append(removed, fmt.Sprintf("%s: missing now (was size %d, hash %s)", path, old.Size, old.Hash))
		}
	}
	for path, nw := range newEntries {
		if _, ok := oldEntries[path]; !ok {
			added = append(added, fmt.Sprintf("%s: new file (size %d, hash %s)", path, nw.Size, nw.Hash))
		}
	}
	sort.Strings(changed)
	sort.Strings(removed)
	sort.Strings(added)

	m.logger.Warn("CRS cache manifest diff (expected vs actual), diagnosis for hash mismatch",
		logger.NewField("version", version),
		logger.NewField("changed_count", len(changed)),
		logger.NewField("removed_count", len(removed)),
		logger.NewField("added_count", len(added)),
		logger.NewField("changed_sample", sampleLines(changed, maxManifestDiffLines)),
		logger.NewField("removed_sample", sampleLines(removed, maxManifestDiffLines)),
		logger.NewField("added_sample", sampleLines(added, maxManifestDiffLines)))
}

// sampleLines 截取前 n 行并以换行连接，超出部分以「...(+N more)」收尾
func sampleLines(lines []string, n int) string {
	if len(lines) == 0 {
		return ""
	}
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:n], "\n") + fmt.Sprintf("\n...(+%d more)", len(lines)-n)
}

// truncHash 哈希缩短为前 16 位用于日志
func truncHash(h string) string {
	if len(h) > 16 {
		return h[:16] + "..."
	}
	return h
}

// publish 发布状态到包级注册表。dir 非空时以目录 ModTime 计算 cache_age_seconds；
// 成功路径 lastError 传空串即清空。
func (m *Manager) publish(version, state, source, dir, integrity, lastError string) {
	var age int64
	if dir != "" {
		if fi, err := os.Stat(dir); err == nil {
			age = int64(time.Since(fi.ModTime()).Seconds())
			if age < 0 {
				age = 0
			}
		}
	}
	PublishStatus(version, Status{
		State:           state,
		Version:         version,
		Source:          source,
		Dir:             dir,
		CacheAgeSeconds: age,
		Integrity:       integrity,
		LastError:       lastError,
		CheckedAt:       time.Now(),
	})
}

// failurePolicy 有效的失败策略（nil 配置 = fail 安全缺省）
func (m *Manager) failurePolicy() string {
	if m.config == nil {
		return config.WAFFailurePolicyFail
	}
	return m.config.GetEffectiveFailurePolicy()
}

// retryCount 有效的下载轮数（nil 配置 = 默认）
func (m *Manager) retryCount() int {
	if m.config == nil {
		return config.DefaultCRSDownloadRetryCount
	}
	return m.config.Download.GetEffectiveRetryCount()
}

// downloadBudget tarball 下载总预算（时长）。配置秒数即预算，不再做 180s 钳制（PRD §5.3）。
func (m *Manager) downloadBudget() time.Duration {
	seconds := config.DefaultCRSDownloadTimeoutSeconds
	if m.config != nil {
		seconds = m.config.Download.GetEffectiveTimeoutSeconds()
	}
	return time.Duration(seconds) * time.Second
}

// proxyEnabled 是否配置了可用代理（不打印凭据）
func (m *Manager) proxyEnabled() bool {
	return m.config != nil && m.config.Download.Proxy.Enabled && m.config.Download.Proxy.URL != ""
}

// mirrorEnabled 是否配置了镜像端点
func (m *Manager) mirrorEnabled() bool {
	return m.config != nil && !m.config.Download.MirrorURL.IsEmpty()
}

// refreshCRS 下载 → 解压到 staging → 结构校验 → 哈希/manifest 原子落盘 → 原子切换。
// 任一步失败：清理 staging 与 tmp，原目录保持不变（PRD §5.2）。返回本次下载来源。
//
// H2（内部PRD §7.3）：期望哈希在发起任何网络请求前解析（配置 pin >
// 金副本 pins 清单），都无 → D2 拒绝下载（零网络调用）；下载后一律以 pin 校验，
// 镜像自供哈希仅记对照日志，GitHub 官方 digest 保留参与交叉校验。
func (m *Manager) refreshCRS(version string) (string, error) {
	m.logger.Info("Refreshing OWASP CRS", logger.NewField("version", version))

	crsDir := m.activeDir(version)
	hashFile := m.hashFilePath(version)
	manifestFile := m.manifestFilePath(version)

	// H2：先解析期望哈希（配置 pin > 金副本 pins 清单）；都无 → 拒绝下载（D2），
	// 直接走既有状态机（stale/degrade）按 failure_policy 处置，不新造状态（§11.5）
	expectedSHA256, pinSource, err := m.resolvePinnedSHA256(version)
	if err != nil {
		return "", err
	}

	// 元数据（预算：单次 10s，最多 2 轮，镜像端点故障转移共享预算）
	metadataSHA256, downloadURL, fromMirror, err := m.getReleaseAssetInfo(version)
	if err != nil {
		m.logger.Warn("Failed to get release asset info, falling back to codeload",
			logger.NewField("version", version),
			logger.NewField("error", err.Error()))
		// 回退到 codeload 下载：tarball 完整性由 pin 校验兜底（H2）
		downloadURL = fmt.Sprintf("https://codeload.github.com/coreruleset/coreruleset/tar.gz/refs/tags/%s", version)
		metadataSHA256 = ""
		fromMirror = false
	}

	// H2：元数据哈希仅作对照，不参与判定——镜像自供哈希与 tarball 同源（自签自验），
	// 不可作为信任锚，与 pin 不一致时仅记对照日志；GitHub 官方 digest 与 pin 打架
	// 属严重异常（清单过期或官方源被篡改），fail closed
	if err := crossCheckMetadataHash(version, expectedSHA256, pinSource, metadataSHA256, fromMirror, m.logger); err != nil {
		return "", err
	}

	// tarball 下载（总预算 = download.timeout，默认 60s；最多 retry_count 轮，每轮先直连后代理）
	deadline := time.Now().Add(m.downloadBudget())
	data, usedProxy, err := m.downloadTarball(downloadURL, deadline)
	if err != nil {
		return "", err
	}

	// 大小阈值校验
	if len(data) < minCRSTarballSize {
		return "", fmt.Errorf("downloaded CRS tarball is suspiciously small: %d bytes (minimum expected: %d)", len(data), minCRSTarballSize)
	}

	// SHA256 完整性校验：一律以 pin 为准（H2：网关只信独立分发的 pin，不信下载源返回值）
	actualHash := sha256.Sum256(data)
	actualSHA256 := hex.EncodeToString(actualHash[:])
	if !strings.EqualFold(actualSHA256, expectedSHA256) {
		return "", fmt.Errorf("CRS integrity check failed: pinned SHA256 %s (source: %s), got %s", expectedSHA256, pinSource, actualSHA256)
	}
	m.logger.Info("CRS tarball integrity verified against pin",
		logger.NewField("version", version),
		logger.NewField("pin_source", pinSource),
		logger.NewField("sha256", truncHash(actualSHA256)))

	// staging 目录（同盘保证 rename 原子性，PRD §5.2）
	if err := os.MkdirAll(m.crsRoot(), 0755); err != nil {
		return "", fmt.Errorf("failed to create cache directory: %w", err)
	}
	stagingDir, err := m.newStagingDir(version)
	if err != nil {
		return "", err
	}
	// 任一步失败：删除 staging 与 tmp，原目录保持不变
	cleanup := func() {
		os.RemoveAll(stagingDir)
		os.Remove(hashFile + ".tmp")
		os.Remove(manifestFile + ".tmp")
	}

	// 解压（含路径遍历防护）
	if err := m.extractTarGz(bytes.NewReader(data), stagingDir); err != nil {
		cleanup()
		return "", fmt.Errorf("failed to extract CRS: %w", err)
	}

	// 结构校验（所有路径都做，不只 codeload fallback；PRD §5.2 流程 3）
	if err := m.verifyCRSStructure(stagingDir); err != nil {
		cleanup()
		return "", fmt.Errorf("CRS structural integrity check failed: %w", err)
	}

	// 计算目录哈希与诊断清单，tmp 写入后 rename 原子落盘。
	// 顺序纪律：.manifest 先写、.sha256 最后写——.sha256 描述「当前生效目录」，
	// 若先写哈希后 manifest 失败，会把仍生效的旧目录永久打成哈希不匹配（valid→stale）；
	// manifest 最后落盘前任何失败都不触碰 .sha256，旧缓存保持 valid（PRD §10.2）。
	dirHash, err := m.hashDirectory(stagingDir)
	if err != nil {
		cleanup()
		return "", fmt.Errorf("failed to compute extracted CRS directory hash: %w", err)
	}
	manifestData, err := buildManifestData(stagingDir)
	if err != nil {
		cleanup()
		return "", fmt.Errorf("failed to build CRS manifest: %w", err)
	}
	if err := atomicWriteFile(manifestFile, manifestData); err != nil {
		cleanup()
		return "", fmt.Errorf("failed to save CRS manifest file: %w", err)
	}
	if err := atomicWriteFile(hashFile, []byte(dirHash)); err != nil {
		cleanup()
		return "", fmt.Errorf("failed to save CRS hash file: %w", err)
	}

	// 原子切换：旧目录 → .old-<rand>；staging → 生效目录
	movedOld := ""
	if m.dirExists(crsDir) {
		movedOld = crsDir + ".old-" + randToken()
		if err := os.Rename(crsDir, movedOld); err != nil {
			cleanup()
			return "", fmt.Errorf("failed to move old CRS directory aside: %w", err)
		}
	}
	if err := os.Rename(stagingDir, crsDir); err != nil {
		// 切换失败：尽力把旧目录放回原位，保证原目录始终可用
		if movedOld != "" {
			if rbErr := os.Rename(movedOld, crsDir); rbErr != nil {
				m.logger.Error("Failed to restore old CRS directory after failed switch",
					logger.NewField("version", version),
					logger.NewField("old_path", movedOld),
					logger.NewField("error", rbErr.Error()))
			}
		}
		cleanup()
		return "", fmt.Errorf("failed to activate new CRS directory: %w", err)
	}

	source := resolveSource(fromMirror, usedProxy)
	m.logger.Info("OWASP CRS refreshed and switched atomically",
		logger.NewField("version", version),
		logger.NewField("source", source),
		logger.NewField("path", crsDir),
		logger.NewField("sha256", truncHash(dirHash)))

	// 成功后异步清理多余的 .old-*（保留最近 2 份）
	go m.cleanupOldVersions(version)

	return source, nil
}

// resolveSource 根据元数据来源与成功链路解析本次下载来源标记
func resolveSource(fromMirror, usedProxy bool) string {
	if usedProxy {
		return SourceProxy
	}
	if fromMirror {
		return SourceMirror
	}
	return SourceDownload
}

// pinsManifestPath pin 清单文件路径：金副本根目录下 pins.sha256（H2）。
// golden_dir 禁用（空串）时返回空串 = 无清单可用
func (m *Manager) pinsManifestPath() string {
	if m.goldenDir == "" {
		return ""
	}
	return filepath.Join(m.goldenDir, pinsManifestFileName)
}

// resolvePinnedSHA256 解析指定版本的期望 tarball SHA256（H2，内部PRD §7.3
// 查找优先级）：
//  1. 配置 waf.crs.download.pinned_sha256（最高优先；与清单同时存在记 Info 说明配置优先）
//  2. 金副本根目录 pins.sha256 清单按当前版本查行（文件缺失/无该版本行 = 无清单，非错误）
//
// 都无 → 返回错误（D2：完整性优先，拒绝下载）。调用方（refreshCRS）直接失败并走
// 既有 stale/degrade 状态机按 failure_policy 处置，不新造状态（PRD §11.5）。
func (m *Manager) resolvePinnedSHA256(version string) (hash, source string, err error) {
	configPin := ""
	if m.config != nil {
		// GetEffectivePinnedSHA256：去空白 + 容忍可选 sha256: 前缀 + 小写归一
		//（格式合法性由 config.Validate fail-fast 把关，此处拿到的必为合法值或空串）
		configPin = m.config.Download.GetEffectivePinnedSHA256()
	}
	manifestPin := ""
	if manifestPath := m.pinsManifestPath(); manifestPath != "" {
		raw, readErr := os.ReadFile(manifestPath)
		if readErr != nil {
			// 文件缺失 = 无清单（非错误状态，配置 pin 仍可兜底）；其他读取失败同样降级为无清单
			m.logger.Debug("No pins manifest available for pin lookup",
				logger.NewField("path", manifestPath),
				logger.NewField("error", readErr.Error()))
		} else if h, ok := lookupPinManifest(raw, version); ok {
			manifestPin = h
		}
	}

	switch {
	case configPin != "":
		if manifestPin != "" {
			m.logger.Info("Config pinned_sha256 takes precedence over pins manifest",
				logger.NewField("version", version),
				logger.NewField("config_pin", truncHash(configPin)),
				logger.NewField("manifest_pin", truncHash(manifestPin)))
		}
		return configPin, pinSourceConfig, nil
	case manifestPin != "":
		return manifestPin, pinSourceManifest, nil
	default:
		return "", "", m.noPinError(version)
	}
}

// noPinError D2 拒绝下载的明确错误（无配置 pin 且清单中也无该版本条目）
func (m *Manager) noPinError(version string) error {
	return fmt.Errorf("no pinned sha256 for CRS %s (neither waf.crs.download.pinned_sha256 nor %s manifest entry); download refused (integrity-first, 内部PRD D2)",
		version, pinsManifestFileName)
}

// lookupPinManifest 解析 pin 清单内容，返回指定版本的期望哈希。
// 格式：每行 `<version> <sha256>`；# 开头注释行与空行跳过；版本精确匹配；
// 哈希非法（非 64 位十六进制）的行跳过（防清单被污染出垃圾行时误判）
func lookupPinManifest(data []byte, version string) (string, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != version {
			continue
		}
		hash := strings.ToLower(fields[1])
		if len(hash) == sha256HexLength && isHexString(hash) {
			return hash, true
		}
	}
	return "", false
}

// isHexString 判断字符串是否非空且全为十六进制字符
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// crossCheckMetadataHash 元数据哈希对照（H2）：镜像自供哈希与 pin 不一致仅记对照日志
// （不参与判定）；GitHub 官方 digest 与 pin 不一致 fail closed（清单过期或官方源被
// 篡改属严重异常）。digest 为空（镜像元数据失败走 codeload 回退等）跳过对照
func crossCheckMetadataHash(version, pinnedSHA256, pinSource, metadataSHA256 string, fromMirror bool, log logger.ILogger) error {
	if metadataSHA256 == "" || strings.EqualFold(metadataSHA256, pinnedSHA256) {
		return nil
	}
	if fromMirror {
		log.Info("Mirror-reported sha256 differs from pinned sha256 (mirror-reported hash is not trusted, pin governs)",
			logger.NewField("version", version),
			logger.NewField("pin_source", pinSource),
			logger.NewField("pinned_sha256", truncHash(pinnedSHA256)),
			logger.NewField("mirror_reported_sha256", truncHash(metadataSHA256)))
		return nil
	}
	return fmt.Errorf("official GitHub digest %s disagrees with pinned sha256 %s (source: %s) for CRS %s",
		truncHash(strings.ToLower(metadataSHA256)), truncHash(pinnedSHA256), pinSource, version)
}

// newStagingDir 创建唯一的 staging 目录（版本 + 随机后缀；per-version 互斥下天然唯一）
func (m *Manager) newStagingDir(version string) (string, error) {
	dir := filepath.Join(m.crsRoot(), version+".staging-"+randToken())
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create staging directory: %w", err)
	}
	return dir, nil
}

// randToken 生成 8 位十六进制随机串（crypto/rand；失败时退化为纳秒时间戳，仅用于命名唯一性）
func randToken() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(buf)
}

// atomicWriteFile 先写 .tmp 再 rename 原子落盘（同目录同盘）
func atomicWriteFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// cleanupOldVersions 异步清理多余的 <version>.old-* 目录，保留最近 oldVersionsToKeep 份
func (m *Manager) cleanupOldVersions(version string) {
	entries, err := os.ReadDir(m.crsRoot())
	if err != nil {
		return
	}
	prefix := version + ".old-"
	type oldDir struct {
		name    string
		modTime time.Time
	}
	var olds []oldDir
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		olds = append(olds, oldDir{name: e.Name(), modTime: info.ModTime()})
	}
	if len(olds) <= oldVersionsToKeep {
		return
	}
	sort.Slice(olds, func(i, j int) bool { return olds[i].modTime.After(olds[j].modTime) })
	for _, od := range olds[oldVersionsToKeep:] {
		if err := os.RemoveAll(filepath.Join(m.crsRoot(), od.name)); err != nil {
			m.logger.Warn("Failed to clean up old CRS cache directory",
				logger.NewField("version", version),
				logger.NewField("path", od.name),
				logger.NewField("error", err.Error()))
		} else {
			m.logger.Info("Cleaned up old CRS cache directory",
				logger.NewField("version", version),
				logger.NewField("path", od.name))
		}
	}
}

// downloadTarball 在总预算内下载 tarball：最多 retryCount 轮，每轮先直连后代理。
// 每次网络调用以剩余预算动态分配 context 超时，禁止无界调用（PRD §5.3/§10.1）。
// 返回 (数据, 成功链路是否经代理, 错误)。
func (m *Manager) downloadTarball(downloadURL string, deadline time.Time) ([]byte, bool, error) {
	rounds := m.retryCount()
	var lastErr error
	for round := 1; round <= rounds; round++ {
		if round > 1 {
			// 预算内短退避（1s/轮），不得超出总预算
			backoff := time.Duration(round-1) * time.Second
			if remaining := time.Until(deadline); remaining <= backoff {
				if lastErr != nil {
					return nil, false, fmt.Errorf("download budget exhausted before retry: %w", lastErr)
				}
				return nil, false, errors.New("download budget exhausted before retry")
			}
			m.logger.Info("Retrying CRS download",
				logger.NewField("round", round),
				logger.NewField("backoff", backoff.String()))
			time.Sleep(backoff)
		}

		// 先直连
		data, err := m.fetchOnce(downloadURL, false, deadline)
		if err == nil {
			return data, false, nil
		}
		lastErr = err
		m.logger.Warn("Direct download failed",
			logger.NewField("round", round),
			logger.NewField("error", err.Error()))

		// 后代理（保留现有顺序：直连优先、代理兜底）
		if m.proxyEnabled() {
			data, err = m.fetchOnce(downloadURL, true, deadline)
			if err == nil {
				return data, true, nil
			}
			lastErr = err
			m.logger.Warn("Proxy download failed",
				logger.NewField("round", round),
				logger.NewField("error", err.Error()))
		}
	}
	if lastErr != nil {
		return nil, false, fmt.Errorf("failed to download CRS after %d rounds: %w", rounds, lastErr)
	}
	return nil, false, fmt.Errorf("failed to download CRS after %d rounds", rounds)
}

// fetchOnce 单次 HTTP 下载：context 超时 = min(剩余预算, +∞)，context 治理整个
// 请求生命周期（含 body 读取）。返回原始字节。
func (m *Manager) fetchOnce(target string, useProxy bool, deadline time.Time) ([]byte, error) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, errors.New("download budget exhausted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), remaining)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}

	client := m.httpClient
	if useProxy {
		client = m.createProxyClient()
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}
	// M2（内部PRD）：tarball 响应体 ≤100MB，LimitReader 有界读取，超限立即失败
	return readLimited(resp.Body, maxTarballBytes, "tarball response")
}

// readLimited 读取 r 至多 limit 字节（M2 统一入口）：LimitReader 保证读取有界、
// 进程内存平稳（禁止整块无上限 ReadAll），超出 limit 立即报错（明确错误信息）
func readLimited(r io.Reader, limit int64, what string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds size limit: >%d bytes", what, limit)
	}
	return data, nil
}

// createProxyClient 创建使用代理的HTTP客户端（无整体 Timeout，预算由请求 context 控制；
// 日志与错误不打印代理凭据）
func (m *Manager) createProxyClient() *http.Client {
	proxyConfig := m.config.Download.Proxy

	proxyURL, err := url.Parse(proxyConfig.URL)
	if err != nil {
		m.logger.Error("Invalid proxy URL, falling back to direct client",
			logger.NewField("error", err.Error()))
		return m.httpClient
	}

	// 如果需要认证
	if proxyConfig.Username != "" && proxyConfig.Password != "" {
		proxyURL.User = url.UserPassword(proxyConfig.Username, proxyConfig.Password)
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
	}

	return &http.Client{Transport: transport}
}

// metadataDeadline 元数据阶段总预算：单次 10s × 最多 2 轮（多端点共享）
func metadataDeadline() time.Time {
	return time.Now().Add(metadataMaxAttempts * metadataCallTimeout)
}

// GetLatestVersion 获取最新版本
func (m *Manager) GetLatestVersion() (string, error) {
	// 镜像模式：从镜像服务获取最新版本
	if m.mirrorEnabled() {
		return m.getLatestVersionFromMirror()
	}
	resp, err := m.httpClient.Get(CRSReleaseAPI)
	if err != nil {
		return "", fmt.Errorf("failed to get latest version: %w", err)
	}
	defer resp.Body.Close()

	// P2-37: 处理 GitHub API 限流 (403 + X-RateLimit-Remaining: 0)
	if resp.StatusCode == http.StatusForbidden {
		if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining == "0" {
			resetTime := resp.Header.Get("X-RateLimit-Reset")
			return "", fmt.Errorf("GitHub API rate limit exceeded, resets at: %s", resetTime)
		}
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status: %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return release.TagName, nil
}

// getLatestVersionFromMirror 从镜像服务获取最新版本
// 支持多镜像端点故障转移：随机选择一个镜像，失败后依次尝试其他镜像
func (m *Manager) getLatestVersionFromMirror() (string, error) {
	deadline := metadataDeadline()
	picker := m.config.Download.MirrorURL.NewPicker()

	var lastErr error
	for {
		mirrorURL, _, ok := picker.Next()
		if !ok {
			break
		}
		mirrorURL = strings.TrimRight(mirrorURL, "/")
		mirrorAPI := mirrorURL + "/api/crs/releases/latest"

		body, err := m.metadataGet(mirrorAPI, deadline)
		if err != nil {
			m.logger.Warn("Failed to get latest version from mirror, trying next",
				logger.NewField("mirror", mirrorURL),
				logger.NewField("error", err.Error()))
			lastErr = err
			continue
		}

		var result struct {
			Code int `json:"code"`
			Data struct {
				Version string `json:"version"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			m.logger.Warn("Failed to decode mirror response, trying next",
				logger.NewField("mirror", mirrorURL),
				logger.NewField("error", err.Error()))
			lastErr = err
			continue
		}

		if result.Code != 200 || result.Data.Version == "" {
			m.logger.Warn("Mirror API returned invalid data, trying next",
				logger.NewField("mirror", mirrorURL),
				logger.NewField("code", result.Code))
			lastErr = fmt.Errorf("mirror API returned invalid data: code=%d", result.Code)
			continue
		}

		m.logger.Info("Got latest version from mirror",
			logger.NewField("version", result.Data.Version),
			logger.NewField("mirror", mirrorURL))
		return result.Data.Version, nil
	}

	if lastErr != nil {
		return "", fmt.Errorf("failed to get latest version from all mirrors: %w", lastErr)
	}
	return "", fmt.Errorf("no mirror endpoints configured")
}

// metadataGet 单次元数据请求：context 超时 = min(metadataCallTimeout, 元数据总预算剩余)
func (m *Manager) metadataGet(target string, deadline time.Time) ([]byte, error) {
	timeout := metadataCallTimeout
	if remaining := time.Until(deadline); remaining < timeout {
		if remaining <= 0 {
			return nil, errors.New("metadata budget exhausted")
		}
		timeout = remaining
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	client := m.httpClient
	if m.proxyEnabled() {
		client = m.createProxyClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata request returned status: %d", resp.StatusCode)
	}
	// M2（内部PRD）：元数据响应体 ≤1MB，LimitReader 有界读取，超限立即失败
	return readLimited(resp.Body, maxMetadataBytes, "metadata response")
}

// getReleaseAssetInfo 获取指定版本的 Release asset 信息（minimal.tar.gz 的 SHA256 和下载 URL）。
// 返回 fromMirror 标记用于来源统计。元数据预算：单次 10s、最多 metadataMaxAttempts 轮
// （多镜像端点故障转移共享预算，PRD §5.3）。
func (m *Manager) getReleaseAssetInfo(version string) (sha256Hash, downloadURL string, fromMirror bool, err error) {
	// 镜像模式：从镜像服务获取版本信息
	if m.mirrorEnabled() {
		h, u, err := m.getReleaseAssetInfoFromMirror(version)
		return h, u, true, err
	}
	h, u, err := m.getReleaseAssetInfoFromGitHub(version)
	return h, u, false, err
}

// getReleaseAssetInfoFromGitHub 从 GitHub Release API 获取 asset 信息（受元数据预算约束）
func (m *Manager) getReleaseAssetInfoFromGitHub(version string) (sha256Hash, downloadURL string, err error) {
	deadline := metadataDeadline()
	releaseAPI := fmt.Sprintf(CRSReleaseAPITemplate, version)

	var lastErr error
	for attempt := 0; attempt < metadataMaxAttempts; attempt++ {
		body, err := m.metadataGet(releaseAPI, deadline)
		if err != nil {
			// P2-37: GitHub API 限流在非 200 分支中识别（metadataGet 统一非 200 报错）
			lastErr = err
			continue
		}

		var release GitHubRelease
		if err := json.Unmarshal(body, &release); err != nil {
			lastErr = fmt.Errorf("failed to decode release response: %w", err)
			continue
		}

		// 查找 minimal.tar.gz asset
		assetName := fmt.Sprintf("coreruleset-%s-minimal.tar.gz", strings.TrimPrefix(version, "v"))
		for _, asset := range release.Assets {
			if asset.Name == assetName && asset.Digest != "" {
				parts := strings.SplitN(asset.Digest, ":", 2)
				if len(parts) == 2 {
					return parts[1], asset.BrowserDownloadURL, nil
				}
			}
		}
		lastErr = fmt.Errorf("no minimal.tar.gz asset with digest found for version %s", version)
	}
	if lastErr != nil {
		return "", "", lastErr
	}
	return "", "", fmt.Errorf("failed to get release info from GitHub")
}

// getReleaseAssetInfoFromMirror 从镜像服务获取版本信息（受元数据预算约束）。
// 镜像 API 返回 {code:200, data:{version, sha256, tarball_url, size}}；
// tarball_url 为相对路径（如 /api/crs/v4.19.0/tarball），需拼接 mirrorURL 前缀；
// 支持多镜像端点故障转移：随机选择一个镜像，失败后依次尝试其他镜像。
func (m *Manager) getReleaseAssetInfoFromMirror(version string) (sha256Hash, downloadURL string, err error) {
	deadline := metadataDeadline()

	var lastErr error
	// 最多 metadataMaxAttempts 轮；每轮重建 Picker 随机打乱端点顺序做完整故障转移
	for attempt := 0; attempt < metadataMaxAttempts; attempt++ {
		picker := m.config.Download.MirrorURL.NewPicker()
		for {
			mirrorURL, _, ok := picker.Next()
			if !ok {
				break
			}
			mirrorURL = strings.TrimRight(mirrorURL, "/")
			mirrorAPI := mirrorURL + fmt.Sprintf("/api/crs/releases/tags/%s", version)

			body, err := m.metadataGet(mirrorAPI, deadline)
			if err != nil {
				m.logger.Warn("Failed to get release info from mirror, trying next",
					logger.NewField("mirror", mirrorURL),
					logger.NewField("version", version),
					logger.NewField("error", err.Error()))
				lastErr = err
				continue
			}

			var result struct {
				Code int `json:"code"`
				Data struct {
					Version    string `json:"version"`
					Sha256     string `json:"sha256"`
					TarballURL string `json:"tarball_url"`
					Size       int64  `json:"size"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				m.logger.Warn("Failed to decode mirror response, trying next",
					logger.NewField("mirror", mirrorURL),
					logger.NewField("error", err.Error()))
				lastErr = err
				continue
			}

			if result.Code != 200 || result.Data.Sha256 == "" {
				m.logger.Warn("Mirror API returned invalid data, trying next",
					logger.NewField("mirror", mirrorURL),
					logger.NewField("code", result.Code))
				lastErr = fmt.Errorf("mirror API returned invalid data for version %s", version)
				continue
			}

			// tarball_url 是相对路径，拼接 mirrorURL 前缀
			fullDownloadURL := mirrorURL + result.Data.TarballURL

			m.logger.Info("Got release info from mirror",
				logger.NewField("version", version),
				logger.NewField("sha256", truncHash(result.Data.Sha256)),
				logger.NewField("download_url", fullDownloadURL),
				logger.NewField("mirror", mirrorURL))

			return result.Data.Sha256, fullDownloadURL, nil
		}
	}

	if lastErr != nil {
		return "", "", fmt.Errorf("failed to get release info from all mirrors: %w", lastErr)
	}
	return "", "", fmt.Errorf("no mirror endpoints configured")
}

// extractTarGz 解压tar.gz文件，使用安全的路径检查防止路径遍历攻击。
// M2（内部PRD）：解压限幅——单文件 ≤100MB、累计总量 ≤300MB（gzip 炸弹与
// 磁盘 DoS 防线）。tar 头声明大小即条目真实长度，超限条目在打开文件前预检失败
// （不落任何字节）；读取阶段以 LimitReader 有界读取并核对声明长度（纵深防御），
// 调用方（refreshCRS）失败时清理 staging，原目录保持不变
func (m *Manager) extractTarGz(reader io.Reader, targetDir string) error {
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	extractedTotal := int64(0)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// 安全路径检查：确保解压路径在 targetDir 内
		// P2-34: 检测到路径遍历尝试时中止解压，而非 skip 单个条目
		path := filepath.Join(targetDir, filepath.Clean(header.Name))
		relPath, err := filepath.Rel(targetDir, path)
		if err != nil || strings.HasPrefix(relPath, "..") || filepath.IsAbs(relPath) {
			return fmt.Errorf("path traversal attempt detected in tarball: entry %q resolved to %q", header.Name, path)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// L5（内部PRD）：目录权限固定 0755，忽略 tarball 内 mode；
			// MkdirAll 后显式 Chmod 对冲 umask，保证已存在目录同样收敛
			if err := os.MkdirAll(path, 0755); err != nil {
				return err
			}
			if err := os.Chmod(path, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			// M2：限幅预检——tar 头声明的解压大小即条目真实长度（tar.Reader 按声明
			// 长度读取），注定超限的条目在打开文件前直接失败，不落任何字节
			if header.Size > maxExtractSingleFileBytes {
				return fmt.Errorf("tar entry %q exceeds single-file extraction limit: declared size %d bytes (limit: %d)", header.Name, header.Size, maxExtractSingleFileBytes)
			}
			if header.Size > maxExtractTotalBytes-extractedTotal {
				return fmt.Errorf("cumulative extraction exceeds total limit: >%d bytes (at entry %q, declared size %d)", maxExtractTotalBytes, header.Name, header.Size)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return err
			}
			// L5（内部PRD）：文件权限固定 0644，忽略 tarball 内 mode
			//（此前用 header.Mode，恶意/异常 tarball 可落 0777 可执行位）；
			// 创建后显式 Chmod 对冲 umask 与预存在文件
			file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
			if err != nil {
				return err
			}
			if err := file.Chmod(0644); err != nil {
				file.Close()
				return err
			}
			// M2：单文件与累计总量双重限幅——本条目允许写入的字节数
			// = min(单文件上限, 累计剩余预算)，LimitReader 有界读取（纵深防御：
			// 读取字节数超出声明长度即失败，正常 tar 不会触达）
			entryCap := int64(maxExtractSingleFileBytes)
			if remaining := maxExtractTotalBytes - extractedTotal; entryCap > remaining {
				entryCap = remaining
			}
			n, err := io.Copy(file, io.LimitReader(tarReader, entryCap+1))
			if err != nil {
				file.Close()
				return err
			}
			if n != header.Size {
				file.Close()
				return fmt.Errorf("tar entry %q read %d bytes, want declared size %d", header.Name, n, header.Size)
			}
			extractedTotal += n
			file.Close()
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("symlink/hardlink entries are not allowed: %s -> %s", header.Name, header.Linkname)
		}
	}

	return nil
}

// exists 检查路径是否存在
func (m *Manager) exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dirExists 检查目录是否存在
func (m *Manager) dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// hashDirectory 计算目录中所有文件的 SHA256 哈希
// 用于 CRS 缓存完整性校验，检测缓存是否被篡改或损坏
// P2-36: 哈希计算包含文件相对路径、文件内容、文件权限和符号链接信息
func (m *Manager) hashDirectory(dir string) (string, error) {
	hasher := sha256.New()
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		// 写入文件相对路径（确保不同目录结构产生不同哈希）
		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		hasher.Write([]byte(relPath))
		hasher.Write([]byte{0})
		// P2-36: 写入文件权限信息，检测权限篡改
		mode := info.Mode()
		hasher.Write([]byte(fmt.Sprintf("mode=%04o", mode.Perm())))
		if mode&os.ModeSymlink != 0 {
			// 符号链接：记录链接目标
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return err
			}
			hasher.Write([]byte("symlink=" + linkTarget))
		}
		hasher.Write([]byte{0})
		// 写入文件内容
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.Copy(hasher, f); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// manifestEntry 诊断清单条目：文件大小 + 文件内容 SHA256 前 16 位
type manifestEntry struct {
	Size int64
	Hash string
}

// buildManifestData 生成诊断清单：每文件一行 `相对路径\t大小\t文件sha256前16位`。
// Walk 顺序为字典序，输出确定性可 diff。
func buildManifestData(dir string) ([]byte, error) {
	var buf bytes.Buffer
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		fileHash, err := fileSHA256(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(&buf, "%s\t%d\t%s\n", relPath, info.Size(), fileHash[:16])
		return nil
	})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// parseManifest 解析诊断清单为 map；格式非法时返回错误（诊断用途，失败不影响主流程）
func parseManifest(data []byte) (map[string]manifestEntry, error) {
	entries := make(map[string]manifestEntry)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			return nil, fmt.Errorf("malformed manifest line: %q", line)
		}
		size, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("malformed manifest size in line %q: %w", line, err)
		}
		entries[parts[0]] = manifestEntry{Size: size, Hash: parts[2]}
	}
	return entries, nil
}

// fileSHA256 计算单文件内容 SHA256
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// GetCRSConfigFiles 获取CRS配置文件路径
// 兼容两种目录结构：源码 tarball（有 coreruleset- 前缀目录）和 minimal asset（文件在根目录）
func (m *Manager) GetCRSConfigFiles(crsDir string) ([]string, error) {
	var files []string

	// 查找 coreruleset 子目录（源码 tarball 解压后的结构）
	corerulesetDir := crsDir
	entries, err := os.ReadDir(crsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRS directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "coreruleset-") {
			corerulesetDir = filepath.Join(crsDir, entry.Name())
			break
		}
	}

	// 如果没有找到 coreruleset- 子目录，corerulesetDir 保持为 crsDir
	// 这适用于 minimal.tar.gz（文件直接在根目录）的情况

	// 添加crs-setup.conf.example
	crsSetup := filepath.Join(corerulesetDir, "crs-setup.conf.example")
	if m.exists(crsSetup) {
		files = append(files, crsSetup)
	}

	// 添加rules目录下的所有.conf文件
	rulesDir := filepath.Join(corerulesetDir, "rules")
	if m.exists(rulesDir) {
		err := filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(path, ".conf") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to scan rules directory: %w", err)
		}
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no CRS configuration files found in %s", crsDir)
	}

	return files, nil
}

// verifyCRSStructure 验证目录包含 CRS 的核心文件结构。
// 内部PRD §5.2：所有路径都做结构校验（下载解压后的 staging、金副本目录），
// 不再仅限 codeload fallback。通过结构验证 + 内容抽样确保内容是合法的 CRS。
// P2-35: 增强结构验证，检查更多核心文件和规则文件内容
func (m *Manager) verifyCRSStructure(crsDir string) error {
	// 查找 coreruleset 子目录（源码 tarball 解压后的结构）
	corerulesetDir := crsDir
	entries, err := os.ReadDir(crsDir)
	if err != nil {
		return fmt.Errorf("failed to read CRS directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "coreruleset-") {
			corerulesetDir = filepath.Join(crsDir, entry.Name())
			break
		}
	}

	// 检查 crs-setup.conf.example 是否存在
	crsSetup := filepath.Join(corerulesetDir, "crs-setup.conf.example")
	if !m.exists(crsSetup) {
		return fmt.Errorf("crs-setup.conf.example not found in %s", corerulesetDir)
	}

	// 验证 crs-setup.conf.example 包含有效内容（非空且包含 SecRule/SecAction 指令）
	setupContent, err := os.ReadFile(crsSetup)
	if err != nil {
		return fmt.Errorf("failed to read crs-setup.conf.example: %w", err)
	}
	if len(setupContent) < 100 {
		return fmt.Errorf("crs-setup.conf.example is suspiciously small (%d bytes)", len(setupContent))
	}
	if !strings.Contains(string(setupContent), "SecRule") && !strings.Contains(string(setupContent), "SecAction") {
		return fmt.Errorf("crs-setup.conf.example does not contain expected SecRule/SecAction directives")
	}

	// 检查 rules 目录是否存在且包含 .conf 文件
	rulesDir := filepath.Join(corerulesetDir, "rules")
	if !m.exists(rulesDir) {
		return fmt.Errorf("rules directory not found in %s", corerulesetDir)
	}

	ruleCount := 0
	totalRuleSize := int64(0)
	err = filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".conf") {
			ruleCount++
			totalRuleSize += info.Size()
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to scan rules directory: %w", err)
	}

	if ruleCount == 0 {
		return fmt.Errorf("no .conf files found in rules directory %s", rulesDir)
	}

	// CRS v4 的规则分布在少量 .conf 文件内（官方包 26 个），数量过少（个位数）
	// 才可能指示下载不完整或被篡改
	if ruleCount < minCRSRuleFileCount {
		return fmt.Errorf("CRS rules directory contains only %d .conf files (minimum expected: %d)", ruleCount, minCRSRuleFileCount)
	}
	if totalRuleSize < minCRSRulesTotalSize {
		return fmt.Errorf("CRS rules total size %d bytes is suspiciously small (minimum expected: %d)", totalRuleSize, minCRSRulesTotalSize)
	}

	// P2-35: 抽样验证多个核心规则文件包含有效的 ModSecurity 指令
	coreRuleFiles := []string{
		"REQUEST-933-APPLICATION-ATTACK-PHP.conf",
		"REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
		"REQUEST-941-APPLICATION-ATTACK-XSS.conf",
	}
	validSampleCount := 0
	checkedCount := 0
	for _, ruleFile := range coreRuleFiles {
		sampleRule := filepath.Join(rulesDir, ruleFile)
		if m.exists(sampleRule) {
			checkedCount++
			content, err := os.ReadFile(sampleRule)
			if err != nil {
				return fmt.Errorf("failed to read sample rule file %s: %w", ruleFile, err)
			}
			if !strings.Contains(string(content), "SecRule") {
				return fmt.Errorf("sample rule file does not contain SecRule directives: %s", ruleFile)
			}
			validSampleCount++
		}
	}
	// 至少 2 个核心规则文件必须存在且有效
	if checkedCount < 2 {
		return fmt.Errorf("only %d of %d core rule files found (expected at least 2)", checkedCount, len(coreRuleFiles))
	}

	// P2-35: 验证规则文件中包含 CRS 标识性内容（crs-setup 或 SecRule 引用）
	// 检查 rules 目录下是否存在 REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
	exclusionRule := filepath.Join(rulesDir, "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf")
	if !m.exists(exclusionRule) {
		// 不强制要求存在，但记录 Debug
		m.logger.Debug("REQUEST-900 exclusion rule file not found, may be a different CRS version",
			logger.NewField("rules_dir", rulesDir))
	}

	m.logger.Debug("CRS structure verified",
		logger.NewField("coreruleset_dir", corerulesetDir),
		logger.NewField("rule_count", ruleCount),
		logger.NewField("total_rule_size", totalRuleSize),
		logger.NewField("checked_core_rules", checkedCount))

	return nil
}
