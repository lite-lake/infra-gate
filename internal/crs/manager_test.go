package crs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/endpoints"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// versionSeq 生成每次测试唯一的 CRS 版本号，隔离包级状态注册表（PublishStatus 全局）
var versionSeq int

func uniqueVersion() string {
	versionSeq++
	return fmt.Sprintf("v4.19.%d", versionSeq)
}

func strPtr(s string) *string { return &s }

// testLogger 输出 Error 级别，测试日志不刷屏
func testLogger() logger.ILogger {
	return logger.NewLogger(logger.LoggerConfig{
		Level:         logger.ErrorLevel,
		EnableConsole: false,
		EnableFile:    false,
	})
}

// ── CRS 目录 fixture ────────────────────────────────────────────────────────
// 最小合法 CRS 结构（同时是 coraza 可解析的合法指令，供 server/waf 包测试复用思路）：
// crs-setup.conf.example（≥100B 含 SecAction）+ rules/ 下 ≥20 个 .conf（≥500KB，
// 含 3 个核心规则文件且内容含 SecRule）。填充用随机十六进制，保证 tar.gz 不被压缩到
// minCRSTarballSize 阈值以下。

// ruleFileSpec 描述一个规则文件（name 为 rules/ 下文件名）
func crsRuleFileNames() []string {
	names := []string{
		"REQUEST-933-APPLICATION-ATTACK-PHP.conf",
		"REQUEST-941-APPLICATION-ATTACK-XSS.conf",
		"REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
	}
	for i := 0; i < 19; i++ {
		names = append(names, fmt.Sprintf("REQUEST-910-TEST-%02d.conf", i))
	}
	return names
}

// randomHexPad 生成 n 字节的高熵十六进制填充（gzip 压缩率低）
func randomHexPad(t *testing.T, n int) string {
	t.Helper()
	raw := make([]byte, (n+1)/2)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	return hex.EncodeToString(raw)[:n]
}

// writeCRSTree 在 dir 写入最小合法 CRS 结构，返回 rules 目录总大小
func writeCRSTree(t *testing.T, dir string) {
	t.Helper()
	setup := "# CRS setup example (test fixture)\n# " + randomHexPad(t, 200) + "\nSecAction \"id:900001,phase:1,pass,nolog\"\n"
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "crs-setup.conf.example"), []byte(setup), 0644); err != nil {
		t.Fatalf("write crs-setup.conf.example: %v", err)
	}
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	for i, name := range crsRuleFileNames() {
		content := fmt.Sprintf("# test fixture rule file %s\n# %s\nSecRule REQUEST_URI \"@contains pad-%d\" \"id:%d,phase:1,pass,nolog\"\n",
			name, randomHexPad(t, 24*1024), i, 900100+i)
		if err := os.WriteFile(filepath.Join(rulesDir, name), []byte(content), 0644); err != nil {
			t.Fatalf("write rule file %s: %v", name, err)
		}
	}
}

// tarCRSGz 将 srcDir 打包为条目名带 prefix/ 的 tar.gz 字节（模拟源码归档布局）
func tarCRSGz(t *testing.T, srcDir, prefix string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		name := prefix + filepath.ToSlash(rel)
		if info.IsDir() {
			if rel == "." {
				return nil
			}
			hdr, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			hdr.Name = name + "/"
			return tw.WriteHeader(hdr)
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = name
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
	if err != nil {
		t.Fatalf("build tar: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

// sha256Hex 字节串 SHA256 十六进制
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ── 假镜像站 ────────────────────────────────────────────────────────────────

// fakeMirror httptest 假 CRS 镜像站：/api/crs/releases/tags/<v> 元数据 +
// /api/crs/<v>/tarball 下载；记录请求总数供「零网络调用」断言。
type fakeMirror struct {
	srv      *httptest.Server
	mu       sync.Mutex
	requests int
	tarball  []byte
	// delay tarball 端点响应时延（并发测试制造下载窗口）
	delay time.Duration
	// truncateTo ≥0 时按该长度截断响应体并中断连接（模拟下载中断）
	truncateTo int
	// ignoreTarball 置真时 tarball 端点返回 404（模拟元数据可达、下载失败）
	ignoreTarball bool
	// reportedSHA256 非空时元数据返回该值而非 tarball 实际哈希（H2：模拟镜像
	// 自供哈希与实际内容脱钩，断言其不参与判定）
	reportedSHA256 string
}

func newFakeMirror(t *testing.T, tarball []byte) *fakeMirror {
	t.Helper()
	m := &fakeMirror{tarball: tarball}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/crs/releases/tags/", func(w http.ResponseWriter, r *http.Request) {
		m.count()
		version := strings.TrimPrefix(r.URL.Path, "/api/crs/releases/tags/")
		reported := m.reportedSHA256
		if reported == "" {
			reported = sha256Hex(m.tarball)
		}
		resp := map[string]interface{}{
			"code": 200,
			"data": map[string]interface{}{
				"version":     version,
				"sha256":      reported,
				"tarball_url": "/api/crs/" + version + "/tarball",
				"size":        len(m.tarball),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		m.count()
		if m.ignoreTarball || !strings.HasSuffix(r.URL.Path, "/tarball") {
			http.NotFound(w, r)
			return
		}
		if m.delay > 0 {
			time.Sleep(m.delay)
		}
		body := m.tarball
		if m.truncateTo > 0 && m.truncateTo < len(body) {
			body = body[:m.truncateTo]
			w.Header().Set("Content-Length", strconv.Itoa(len(m.tarball)))
			_, _ = w.Write(body)
			// 中断连接：客户端读 body 时得到 unexpected EOF
			panic(http.ErrAbortHandler)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(m.tarball)))
		_, _ = w.Write(body)
	})
	m.srv = httptest.NewServer(mux)
	m.srv.URL = strings.TrimRight(m.srv.URL, "/")
	t.Cleanup(m.srv.Close)
	return m
}

func (m *fakeMirror) count() {
	m.mu.Lock()
	m.requests++
	m.mu.Unlock()
}

func (m *fakeMirror) requestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests
}

// unreachableMirrorURL 返回一个必然连接失败的镜像 URL（已关闭的本地 httptest 端口，
// 连接立即被拒绝，测试不等待超时）
func unreachableMirrorURL(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(http.NewServeMux())
	u := ts.URL
	ts.Close()
	return u
}

// ── Manager 构造 ────────────────────────────────────────────────────────────

type testManagerOpts struct {
	mirrorURL     string
	failurePolicy string
	goldenDir     *string // nil = 不设置（走默认 /app/crs）；strPtr("") = 显式禁用
	timeout       int
	retryCount    int
	proxyEnabled  bool
	// pinnedSHA256 H2：配置级 pin（waf.crs.download.pinned_sha256）；空 = 不配置
	pinnedSHA256 string
}

func newTestCRSConfig(t *testing.T, o testManagerOpts) *config.WAFCRSConfig {
	t.Helper()
	cfg := &config.WAFCRSConfig{
		Enabled:       true,
		Version:       "",
		FailurePolicy: o.failurePolicy,
		Download: config.WAFCRSDownloadConfig{
			Timeout:      o.timeout,
			RetryCount:   o.retryCount,
			MirrorURL:    endpoints.New(o.mirrorURL),
			PinnedSHA256: o.pinnedSHA256,
		},
	}
	if o.goldenDir != nil {
		cfg.GoldenDir = strPtr(*o.goldenDir)
	}
	if o.proxyEnabled {
		cfg.Download.Proxy = config.WAFCRSProxyConfig{Enabled: true, URL: "http://127.0.0.1:1"}
	}
	return cfg
}

// pinsOnlyGoldenDir 创建仅含 pins.sha256 清单的金副本根目录（不含任何版本子目录），
// 返回目录路径。H2 测试基建：金副本加载不受影响（无 <version>/ 目录可加载），
// 而下载路径可经清单查得期望哈希。entries 为 版本 → sha256 映射
func pinsOnlyGoldenDir(t *testing.T, entries map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("# test pins manifest\n")
	for v, h := range entries {
		fmt.Fprintf(&b, "%s %s\n", v, h)
	}
	if err := os.WriteFile(filepath.Join(dir, "pins.sha256"), []byte(b.String()), 0644); err != nil {
		t.Fatalf("write pins.sha256: %v", err)
	}
	return dir
}

// seedValidCache 依据当前 Manager 的哈希算法播种「已校验」缓存：目录 + .sha256 + .manifest
func seedValidCache(t *testing.T, m *Manager, version string) string {
	t.Helper()
	dir := m.activeDir(version)
	writeCRSTree(t, dir)
	hash, err := m.hashDirectory(dir)
	if err != nil {
		t.Fatalf("hashDirectory: %v", err)
	}
	if err := os.WriteFile(m.hashFilePath(version), []byte(hash), 0644); err != nil {
		t.Fatalf("write hash file: %v", err)
	}
	manifest, err := buildManifestData(dir)
	if err != nil {
		t.Fatalf("buildManifestData: %v", err)
	}
	if err := os.WriteFile(m.manifestFilePath(version), manifest, 0644); err != nil {
		t.Fatalf("write manifest file: %v", err)
	}
	return dir
}

// dirHashSnapshot 目录内容的 SHA256（基于 buildManifestData，供「目录未变」断言）
func dirHashSnapshot(t *testing.T, dir string) string {
	t.Helper()
	data, err := buildManifestData(dir)
	if err != nil {
		t.Fatalf("buildManifestData(%s): %v", dir, err)
	}
	return sha256Hex(data)
}

// assertNoHalfWrittenArtifacts 断言 owasp_crs 根下无 staging 目录与 .tmp 残留
func assertNoHalfWrittenArtifacts(t *testing.T, cacheDir, version string) {
	t.Helper()
	root := filepath.Join(cacheDir, "owasp_crs")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("read cache root: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), version+".staging-") {
			t.Errorf("found leftover staging dir: %s", e.Name())
		}
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("found leftover tmp file: %s", e.Name())
		}
	}
}

// ── 场景 1：缓存 valid → 零网络调用 ─────────────────────────────────────────

func TestEnsureCRSValidCacheZeroNetwork(t *testing.T) {
	cacheDir := t.TempDir()
	version := uniqueVersion()
	mirror := newFakeMirror(t, []byte("unused"))
	// 镜像必须真实接入配置：否则 requestCount==0 断言空洞（根本没有可请求的端点）
	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: mirror.srv.URL, timeout: 2, retryCount: 1, goldenDir: strPtr(""),
	}))
	seedValidCache(t, m, version)

	res := m.EnsureCRS(version)
	if res.Err != nil {
		t.Fatalf("EnsureCRS error: %v", res.Err)
	}
	if res.State != StateValid || res.Source != SourceCache {
		t.Errorf("state/source = %s/%s, want valid/cache", res.State, res.Source)
	}
	if res.Dir != m.activeDir(version) {
		t.Errorf("dir = %s, want %s", res.Dir, m.activeDir(version))
	}
	if n := mirror.requestCount(); n != 0 {
		t.Errorf("mirror request count = %d, want 0 (valid cache must not trigger network)", n)
	}

	st, ok := StatusSnapshot(version)
	if !ok || st.State != StateValid || st.Source != SourceCache {
		t.Errorf("status snapshot = %+v ok=%v, want valid/cache", st, ok)
	}
}

// ── 场景 2：hash 不匹配 + 镜像可达 → 原子切换，旧目录保留为 .old-* ───────────

func TestEnsureCRSHashMismatchRefreshSwitchesAtomically(t *testing.T) {
	cacheDir := t.TempDir()
	version := uniqueVersion()

	// 镜像提供一份全新的合法 tarball（内容与旧缓存不同）
	newTree := filepath.Join(t.TempDir(), "newtree")
	writeCRSTree(t, newTree)
	tarball := tarCRSGz(t, newTree, "coreruleset-"+strings.TrimPrefix(version, "v")+"/")
	mirror := newFakeMirror(t, tarball)

	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: mirror.srv.URL, timeout: 5, retryCount: 1,
		goldenDir: strPtr(pinsOnlyGoldenDir(t, map[string]string{version: sha256Hex(tarball)})),
	}))

	seedValidCache(t, m, version)
	// 破坏缓存：向一个规则文件追加内容 → 哈希不再匹配
	corrupted := filepath.Join(m.activeDir(version), "rules", "REQUEST-910-TEST-00.conf")
	f, err := os.OpenFile(corrupted, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open corrupted target: %v", err)
	}
	if _, err := f.WriteString("# appended corruption\n"); err != nil {
		t.Fatalf("append corruption: %v", err)
	}
	f.Close()
	oldTreeSnapshot := dirHashSnapshot(t, m.activeDir(version))

	res := m.EnsureCRS(version)
	if res.Err != nil {
		t.Fatalf("EnsureCRS error: %v", res.Err)
	}
	if res.State != StateValid {
		t.Errorf("state = %s, want valid (refresh succeeded)", res.State)
	}
	if res.Source != SourceMirror {
		t.Errorf("source = %s, want mirror", res.Source)
	}
	// 刷新确实经过了网络（元数据 + tarball 至少各一次）
	if n := mirror.requestCount(); n < 2 {
		t.Errorf("mirror request count = %d, want >= 2", n)
	}

	// 生效目录内容已切换为新 tarball 内容
	newHash, err := m.hashDirectory(m.activeDir(version))
	if err != nil {
		t.Fatalf("hash new active dir: %v", err)
	}
	stored, err := os.ReadFile(m.hashFilePath(version))
	if err != nil {
		t.Fatalf("read hash file: %v", err)
	}
	if !strings.EqualFold(strings.TrimSpace(string(stored)), newHash) {
		t.Error("hash file does not match switched directory")
	}

	// 旧目录保留为 .old-*（保留 2 份策略下 1 份必然在场）
	entries, err := os.ReadDir(filepath.Join(cacheDir, "owasp_crs"))
	if err != nil {
		t.Fatalf("read cache root: %v", err)
	}
	var oldDirs []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), version+".old-") {
			oldDirs = append(oldDirs, e.Name())
		}
	}
	if len(oldDirs) != 1 {
		t.Fatalf("old dirs = %v, want exactly 1", oldDirs)
	}
	if got := dirHashSnapshot(t, filepath.Join(cacheDir, "owasp_crs", oldDirs[0])); got != oldTreeSnapshot {
		t.Error("old directory content changed after switch")
	}

	// 无 staging 残留
	assertNoHalfWrittenArtifacts(t, cacheDir, version)

	st, _ := StatusSnapshot(version)
	if st.State != StateValid || st.LastError != "" {
		t.Errorf("status = %+v, want valid with empty last_error", st)
	}
}

// ── 场景 3：hash 不匹配 + 镜像不可达 → F10（内部PRD §4.10/D10 窄化）
// 严格档：疑似篡改永不加载（无该版本金副本 + fail 策略 → 硬失败），
// 被篡改目录原样保留（取证 + 失败路径永不删旧缓存） ─────────────

func TestEnsureCRSHashMismatchUnreachableRefusesTampered(t *testing.T) {
	cacheDir := t.TempDir()
	version := uniqueVersion()
	// 清单 pin 与真实 tarball 无关即可：镜像不可达时刷新止步于网络错误（H2 下仍需
	// 有 pin 才会发起下载，否则会在 pin 解析处直接拒绝，测不到本场景本意）
	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: unreachableMirrorURL(t), timeout: 2, retryCount: 1,
		goldenDir: strPtr(pinsOnlyGoldenDir(t, map[string]string{version: strings.Repeat("ab", 32)})),
	}))

	seedValidCache(t, m, version)
	corrupted := filepath.Join(m.activeDir(version), "rules", "REQUEST-910-TEST-00.conf")
	f, err := os.OpenFile(corrupted, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open corrupted target: %v", err)
	}
	if _, err := f.WriteString("# appended corruption\n"); err != nil {
		t.Fatalf("append corruption: %v", err)
	}
	f.Close()
	snapshot := dirHashSnapshot(t, m.activeDir(version))

	res := m.EnsureCRS(version)
	// F10：严格档无金副本 + fail 策略 → 硬失败（被篡改缓存禁止加载）
	if res.Err == nil {
		t.Fatal("EnsureCRS must refuse tampered cache (strict tier, no golden, fail policy)")
	}
	if res.State != "" || res.Dir != "" {
		t.Errorf("state/dir = %q/%q, want empty (refused)", res.State, res.Dir)
	}
	// 状态注册表暴露篡改证据
	if st, ok := StatusSnapshot(version); !ok || st.Integrity != IntegrityStatusTampered {
		t.Errorf("status integrity = %q, want tampered", st.Integrity)
	}

	// 被篡改目录原样保留（取证 + 绝不先删后下）
	if got := dirHashSnapshot(t, m.activeDir(version)); got != snapshot {
		t.Error("tampered cache directory changed during failed refresh")
	}
	assertNoHalfWrittenArtifacts(t, cacheDir, version)

}

// ── 场景 4：缓存缺失 + 镜像不可达 + 金副本存在 → golden 只读加载 ──────────────

func TestEnsureCRSAbsentFallsBackToGoldenReadOnly(t *testing.T) {
	cacheDir := t.TempDir()
	goldenDir := t.TempDir()
	version := uniqueVersion()
	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: unreachableMirrorURL(t), timeout: 2, retryCount: 1, goldenDir: strPtr(goldenDir),
	}))

	goldenVersionDir := filepath.Join(goldenDir, version)
	writeCRSTree(t, goldenVersionDir)
	before := dirHashSnapshot(t, goldenVersionDir)
	// 记录加载前各条目 mtime（写入发生在 EnsureCRS 之前）
	type mtimeEntry struct {
		name    string
		modTime time.Time
	}
	var beforeMtimes []mtimeEntry
	goldenEntries, err := os.ReadDir(goldenVersionDir)
	if err != nil {
		t.Fatalf("read golden dir: %v", err)
	}
	for _, e := range goldenEntries {
		info, err := e.Info()
		if err != nil {
			t.Fatalf("stat golden entry: %v", err)
		}
		beforeMtimes = append(beforeMtimes, mtimeEntry{name: e.Name(), modTime: info.ModTime()})
	}

	res := m.EnsureCRS(version)
	if res.Err != nil {
		t.Fatalf("EnsureCRS error: %v", res.Err)
	}
	if res.State != StateValid || res.Source != SourceGolden {
		t.Errorf("state/source = %s/%s, want valid/golden", res.State, res.Source)
	}
	if res.Dir != goldenVersionDir {
		t.Errorf("dir = %s, want golden dir %s", res.Dir, goldenVersionDir)
	}

	// 金副本只读语义：加载后内容与 mtime 均未改变
	if got := dirHashSnapshot(t, goldenVersionDir); got != before {
		t.Error("golden copy content changed during load")
	}
	afterEntries, err := os.ReadDir(goldenVersionDir)
	if err != nil {
		t.Fatalf("read golden dir: %v", err)
	}
	if len(afterEntries) != len(beforeMtimes) {
		t.Fatalf("golden dir entry count = %d, want %d", len(afterEntries), len(beforeMtimes))
	}
	for _, be := range beforeMtimes {
		info, err := os.Stat(filepath.Join(goldenVersionDir, be.name))
		if err != nil {
			t.Fatalf("stat golden entry %s: %v", be.name, err)
		}
		if !info.ModTime().Equal(be.modTime) {
			t.Errorf("golden entry %s was modified (mtime %v -> %v)", be.name, be.modTime, info.ModTime())
		}
	}

	// 可写缓存目录不被写入（金副本不拷贝、不落缓存）
	if _, err := os.Stat(filepath.Join(cacheDir, "owasp_crs")); !os.IsNotExist(err) {
		t.Error("writable cache dir should not be created when loading from golden copy")
	}

	st, _ := StatusSnapshot(version)
	if st.State != StateValid || st.Source != SourceGolden || st.Dir != goldenVersionDir {
		t.Errorf("status = %+v, want valid/golden", st)
	}
}

// timeBeforeTestStart golden mtime 断言基线已改为测试内采集（写入后、EnsureCRS 前），
// 不再需要包级变量；保留该处注释避免误用。

// ── 场景 5：缓存缺失 + 镜像不可达 + 无金副本 + degrade → ErrCRSDegraded ───────

func TestEnsureCRSAbsentDegradePolicyReturnsSentinel(t *testing.T) {
	cacheDir := t.TempDir()
	version := uniqueVersion()
	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: unreachableMirrorURL(t), timeout: 2, retryCount: 1,
		goldenDir: strPtr(""), failurePolicy: config.WAFFailurePolicyDegrade,
		// H2：配置 pin 在场（金副本禁用 = 无清单，配置 pin 兜底），使失败止步于
		// 镜像不可达而非 pin 解析，保持本场景「镜像不可达 → degrade」本意
		pinnedSHA256: strings.Repeat("ab", 32),
	}))

	res := m.EnsureCRS(version)
	if res.Err == nil {
		t.Fatal("EnsureCRS should fail with degrade sentinel")
	}
	if !errors.Is(res.Err, ErrCRSDegraded) {
		t.Fatalf("error should wrap ErrCRSDegraded, got: %v", res.Err)
	}
	if res.State != StateDegraded || res.Dir != "" {
		t.Errorf("state/dir = %s/%q, want degraded/empty", res.State, res.Dir)
	}

	// 不产生任何半成品目录
	assertNoHalfWrittenArtifacts(t, cacheDir, version)

	st, ok := StatusSnapshot(version)
	if !ok || st.State != StateDegraded || st.LastError == "" {
		t.Errorf("status = %+v ok=%v, want degraded with last_error", st, ok)
	}
}

// ── 场景 6：同场景 + fail → 普通错误（非哨兵）────────────────────────────────

func TestEnsureCRSAbsentFailPolicyReturnsPlainError(t *testing.T) {
	cacheDir := t.TempDir()
	version := uniqueVersion()
	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: unreachableMirrorURL(t), timeout: 2, retryCount: 1,
		goldenDir: strPtr(""), failurePolicy: config.WAFFailurePolicyFail,
		pinnedSHA256: strings.Repeat("ab", 32), // 同上：pin 兜底，失败止步于网络
	}))

	res := m.EnsureCRS(version)
	if res.Err == nil {
		t.Fatal("EnsureCRS should fail under fail policy")
	}
	if errors.Is(res.Err, ErrCRSDegraded) {
		t.Fatalf("error must NOT be degrade sentinel under fail policy: %v", res.Err)
	}
	if res.State == StateDegraded {
		t.Errorf("state = %s, want non-degraded under fail policy", res.State)
	}
	assertNoHalfWrittenArtifacts(t, cacheDir, version)
}

// ── 场景 7：下载中断 / 解压失败 / 结构校验失败 → staging 清理、原目录不变 ─────

func TestEnsureCRSFailedRefreshLeavesOriginalIntact(t *testing.T) {
	corrupt := func(t *testing.T, m *Manager, version string) {
		t.Helper()
		p := filepath.Join(m.activeDir(version), "rules", "REQUEST-910-TEST-00.conf")
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if _, err := f.WriteString("# corruption\n"); err != nil {
			t.Fatalf("append: %v", err)
		}
		f.Close()
	}

	cases := []struct {
		name   string
		mutate func(m *fakeMirror)
	}{
		{"download interrupted mid-body", func(m *fakeMirror) { m.truncateTo = len(m.tarball) / 2 }},
		{"corrupt archive (sha matches, not gzip)", func(m *fakeMirror) {
			// 与元数据 SHA256 一致的垃圾字节 → 通过哈希校验但解压失败
			m.tarball = bytes.Repeat([]byte("x"), 150*1024)
		}},
		{"structure verification failure", func(m *fakeMirror) {
			// 大 junk 文件（≥100KB tarball 阈值）但无 CRS 结构 → 结构校验失败
			junk := filepath.Join(t.TempDir(), "junk")
			if err := os.WriteFile(junk, []byte(randomHexPad(t, 200*1024)), 0644); err != nil {
				t.Fatalf("write junk: %v", err)
			}
			m.tarball = tarCRSGz(t, filepath.Dir(junk), "coreruleset-junk/")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			version := uniqueVersion()

			tree := filepath.Join(t.TempDir(), "tree")
			writeCRSTree(t, tree)
			mirror := newFakeMirror(t, tarCRSGz(t, tree, "coreruleset-"+strings.TrimPrefix(version, "v")+"/"))
			tc.mutate(mirror)
			// H2：pin 取「实际响应内容」的哈希——截断/垃圾字节用例在完整性校验处失败，
			// 结构校验用例通过完整性、精确止步于结构校验，三者的失败点由本 pin 区分
			m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
				mirrorURL: mirror.srv.URL, timeout: 3, retryCount: 1,
				goldenDir: strPtr(pinsOnlyGoldenDir(t, map[string]string{version: sha256Hex(mirror.tarball)})),
			}))
			seedValidCache(t, m, version)
			corrupt(t, m, version)
			snapshot := dirHashSnapshot(t, m.activeDir(version))

			res := m.EnsureCRS(version)
			// F10：内容被 corrupt（hash 在场不匹配）→ 严格档拒绝加载（硬失败）
			if res.Err == nil || res.State != "" || res.Dir != "" {
				t.Fatalf("state/dir/err = %q/%q/%v, want refused (tampered strict tier)", res.State, res.Dir, res.Err)
			}
			if got := dirHashSnapshot(t, m.activeDir(version)); got != snapshot {
				t.Error("original cache directory changed during failed refresh")
			}
			assertNoHalfWrittenArtifacts(t, cacheDir, version)
		})
	}
}

// ── 场景 8：并发 EnsureCRS → 无相互覆盖，最终一致 ─────────────────────────────

func TestEnsureCRSConcurrentNoMutualOverwrite(t *testing.T) {
	cacheDir := t.TempDir()
	version := uniqueVersion()

	tree := filepath.Join(t.TempDir(), "tree")
	writeCRSTree(t, tree)
	// 假镜像带 100ms 下载时延，制造并发窗口（per-version 互斥应保证 staging 串行）
	tarball := tarCRSGz(t, tree, "coreruleset-"+strings.TrimPrefix(version, "v")+"/")
	mirror := newFakeMirror(t, tarball)
	mirror.delay = 100 * time.Millisecond

	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: mirror.srv.URL, timeout: 10, retryCount: 1,
		goldenDir: strPtr(pinsOnlyGoldenDir(t, map[string]string{version: sha256Hex(tarball)})),
	}))

	const concurrency = 4
	start := make(chan struct{})
	results := make(chan Result, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- m.EnsureCRS(version)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	validCount := 0
	for res := range results {
		if res.Err != nil {
			t.Errorf("EnsureCRS error: %v", res.Err)
			continue
		}
		if res.State == StateValid {
			validCount++
		}
	}
	if validCount == 0 {
		t.Fatal("no goroutine obtained a valid CRS")
	}

	// 最终一致：生效目录存在、哈希匹配、无 staging 残留、无多余 old 目录
	newHash, err := m.hashDirectory(m.activeDir(version))
	if err != nil {
		t.Fatalf("hash active dir: %v", err)
	}
	stored, err := os.ReadFile(m.hashFilePath(version))
	if err != nil {
		t.Fatalf("read hash file: %v", err)
	}
	if !strings.EqualFold(strings.TrimSpace(string(stored)), newHash) {
		t.Error("hash file does not match active directory after concurrent EnsureCRS")
	}
	assertNoHalfWrittenArtifacts(t, cacheDir, version)

	entries, err := os.ReadDir(filepath.Join(cacheDir, "owasp_crs"))
	if err != nil {
		t.Fatalf("read cache root: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), version+".old-") {
			t.Errorf("unexpected old dir from cold start: %s", e.Name())
		}
	}
}

// ── 补充：元数据落盘顺序回归（manifest 先写、.sha256 最后写）─────────────────
// refreshCRS 中 .sha256 描述「当前生效目录」：若先写哈希、后写 manifest 失败，
// 仍生效的旧目录会被新哈希永久打成哈希不匹配（valid→stale，触发无谓回源）。
// 本测试预置 .manifest 为目录制造写入失败（rename 到目录路径返回 EISDIR），
// 断言旧 .sha256 与旧目录均未被触碰（PRD §10.2：失败路径不得破坏可用旧缓存）。

func TestRefreshCRSManifestWriteFailurePreservesValidHash(t *testing.T) {
	cacheDir := t.TempDir()
	version := uniqueVersion()

	tree := filepath.Join(t.TempDir(), "tree")
	writeCRSTree(t, tree)
	tarball := tarCRSGz(t, tree, "coreruleset-"+strings.TrimPrefix(version, "v")+"/")
	mirror := newFakeMirror(t, tarball)

	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: mirror.srv.URL, timeout: 5, retryCount: 1,
		goldenDir: strPtr(pinsOnlyGoldenDir(t, map[string]string{version: sha256Hex(tarball)})),
	}))

	seedValidCache(t, m, version)
	// F10 适配：删除 hash 文件制造宽松档 stale（触发按预算刷新；内容篡改在
	// F10 下属严格档会硬失败，manifest 目录占位不算同批落盘证据、不升级）
	if err := os.Remove(m.hashFilePath(version)); err != nil {
		t.Fatalf("remove hash file: %v", err)
	}

	// 预置 .manifest 为目录 → staging 解压/结构校验/哈希计算全部通过后，
	// manifest 原子落盘必然失败（此次刷新止步于 manifest 写入）
	if err := os.Remove(m.manifestFilePath(version)); err != nil {
		t.Fatalf("remove manifest file: %v", err)
	}
	if err := os.Mkdir(m.manifestFilePath(version), 0755); err != nil {
		t.Fatalf("mkdir manifest dir: %v", err)
	}

	res := m.EnsureCRS(version)
	if res.State != StateStale {
		t.Fatalf("state = %s, want stale (refresh must fail at manifest write)", res.State)
	}

	// 关键断言（F10 适配：hash 文件由本用例删除制造宽松档）：刷新止步于 manifest
	// 写入 → hash 文件不得先于 manifest 被写入（修复前顺序会先写哈希）
	if _, statErr := os.Stat(m.hashFilePath(version)); !os.IsNotExist(statErr) {
		t.Error("hash file was (re)written before manifest write failed (ordering regression)")
	}
	// 旧目录仍在，无 staging/tmp 残留
	if !m.dirExists(m.activeDir(version)) {
		t.Error("original cache directory missing after failed refresh")
	}
	assertNoHalfWrittenArtifacts(t, cacheDir, version)
}

// ── 补充：manifest 差异诊断日志触发（哈希不一致 + 清单在场）──────────────────

func TestEnsureCRSManifestDiffDiagnosticTriggered(t *testing.T) {
	cacheDir := t.TempDir()
	version := uniqueVersion()
	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: unreachableMirrorURL(t), timeout: 2, retryCount: 1, goldenDir: strPtr(""),
	}))

	seedValidCache(t, m, version)
	rulesDir := filepath.Join(m.activeDir(version), "rules")
	// 制造三类差异：修改、删除、新增
	if err := os.WriteFile(filepath.Join(rulesDir, "REQUEST-910-TEST-00.conf"),
		[]byte("# totally replaced\n"+randomHexPad(t, 1024)), 0644); err != nil {
		t.Fatalf("rewrite rule: %v", err)
	}
	if err := os.Remove(filepath.Join(rulesDir, "REQUEST-910-TEST-01.conf")); err != nil {
		t.Fatalf("remove rule: %v", err)
	}
	if err := os.WriteFile(filepath.Join(m.activeDir(version), "extra-file.txt"),
		[]byte("unexpected"), 0644); err != nil {
		t.Fatalf("add extra file: %v", err)
	}
	// F10 适配：hash 在场不匹配 = 严格档（疑似篡改，拒绝加载）——诊断日志
	// （logManifestDiff）在 verifyCacheIntegrity 内仍触发；本用例断言改为
	// 拒绝加载 + 目录保持完好（任何诊断失败只记日志，不影响主流程）
	before, _ := buildManifestData(m.activeDir(version))
	res := m.EnsureCRS(version)
	if res.Err == nil || res.State != "" || res.Dir != "" {
		t.Fatalf("state/dir/err = %s/%s/%v, want refused (tampered strict tier)", res.State, res.Dir, res.Err)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, "REQUEST-910-TEST-02.conf")); err != nil {
		t.Errorf("other cache files should remain untouched: %v", err)
	}
	// 目录在拒绝加载路径保持完好（与 EnsureCRS 前的清单一致）
	if after, _ := buildManifestData(m.activeDir(version)); !bytes.Equal(after, before) {
		t.Error("cache directory changed during diagnostic refusal path")
	}
}

// ── 补充：金副本显式禁用（golden_dir=""）与默认目录不存在 ────────────────────

func TestEnsureCRSGoldenExplicitlyDisabled(t *testing.T) {
	cacheDir := t.TempDir()
	goldenDir := t.TempDir()
	version := uniqueVersion()
	writeCRSTree(t, filepath.Join(goldenDir, version))
	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: unreachableMirrorURL(t), timeout: 2, retryCount: 1,
		goldenDir: strPtr(""), failurePolicy: config.WAFFailurePolicyDegrade,
	}))

	// 金副本目录存在但被显式禁用 → 不使用，走 degrade
	res := m.EnsureCRS(version)
	if !errors.Is(res.Err, ErrCRSDegraded) {
		t.Fatalf("expected degrade sentinel with golden disabled, got: %v", res.Err)
	}
	if res.Source == SourceGolden {
		t.Error("golden source must not appear when golden copy is disabled")
	}
}

func TestEnsureCRSDefaultGoldenDirMissingFallsToDownload(t *testing.T) {
	cacheDir := t.TempDir()
	version := uniqueVersion()
	// GoldenDir 不设置 → 默认 /app/crs（测试环境不存在该目录）→ 金副本跳过
	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: unreachableMirrorURL(t), timeout: 2, retryCount: 1,
		failurePolicy: config.WAFFailurePolicyDegrade,
	}))

	res := m.EnsureCRS(version)
	if !errors.Is(res.Err, ErrCRSDegraded) {
		t.Fatalf("expected degrade sentinel (default golden dir absent), got: %v", res.Err)
	}
}

// ── 补充：状态注册表与版本归一化 ─────────────────────────────────────────────

func TestResolveVersion(t *testing.T) {
	if got := ResolveVersion(""); got != DefaultCRSVersion {
		t.Errorf("ResolveVersion(\"\") = %q, want %q", got, DefaultCRSVersion)
	}
	if DefaultCRSVersion != "v4.19.0" {
		t.Errorf("DefaultCRSVersion = %q, want v4.19.0 (aligned with yamlops)", DefaultCRSVersion)
	}
	if got := ResolveVersion("v1.2.3"); got != "v1.2.3" {
		t.Errorf("ResolveVersion(v1.2.3) = %q", got)
	}
}

func TestStatusRegistrySnapshotAndAll(t *testing.T) {
	version := uniqueVersion()
	if _, ok := StatusSnapshot(version); ok {
		t.Fatal("unknown version should not be present")
	}
	PublishStatus(version, Status{State: StateValid, Source: SourceCache, Dir: "/tmp/x", CacheAgeSeconds: 7})
	st, ok := StatusSnapshot(version)
	if !ok || st.State != StateValid || st.Version != version || st.CacheAgeSeconds != 7 {
		t.Fatalf("snapshot = %+v ok=%v", st, ok)
	}
	all := AllStatuses()
	if _, ok := all[version]; !ok {
		t.Fatal("AllStatuses should contain published version")
	}
	// 快照为拷贝：修改返回值不影响注册表
	mutated := all[version]
	mutated.State = StateDegraded
	all[version] = mutated
	st2, _ := StatusSnapshot(version)
	if st2.State != StateValid {
		t.Error("StatusSnapshot must return a copy")
	}
}

// ── 补充：GetEffective* 配置解析（与 crs 行为联动）──────────────────────────

func TestEffectiveConfigResolution(t *testing.T) {
	// failure policy 默认 fail
	cfg := &config.WAFCRSConfig{}
	if got := cfg.GetEffectiveFailurePolicy(); got != config.WAFFailurePolicyFail {
		t.Errorf("default failure policy = %q, want fail", got)
	}
	cfg.FailurePolicy = config.WAFFailurePolicyDegrade
	if got := cfg.GetEffectiveFailurePolicy(); got != config.WAFFailurePolicyDegrade {
		t.Errorf("failure policy = %q, want degrade", got)
	}

	// golden dir：nil → 默认启用；空串 → 禁用；自定义值
	dir, enabled := cfg.GetEffectiveGoldenDir()
	if !enabled || dir != config.DefaultCRSGoldenDir {
		t.Errorf("default golden dir = %q enabled=%v, want %q true", dir, enabled, config.DefaultCRSGoldenDir)
	}
	cfg.GoldenDir = strPtr("")
	if _, enabled := cfg.GetEffectiveGoldenDir(); enabled {
		t.Error("explicit empty golden dir should disable golden copy")
	}
	cfg.GoldenDir = strPtr("/data/golden")
	if dir, _ := cfg.GetEffectiveGoldenDir(); dir != "/data/golden" {
		t.Errorf("golden dir = %q, want /data/golden", dir)
	}

	// retry count / timeout 缺省
	dl := &config.WAFCRSDownloadConfig{}
	if got := dl.GetEffectiveRetryCount(); got != config.DefaultCRSDownloadRetryCount {
		t.Errorf("default retry count = %d, want %d", got, config.DefaultCRSDownloadRetryCount)
	}
	dl.RetryCount = 3
	if got := dl.GetEffectiveRetryCount(); got != 3 {
		t.Errorf("retry count = %d, want 3", got)
	}
	if got := dl.GetEffectiveTimeoutSeconds(); got != config.DefaultCRSDownloadTimeoutSeconds {
		t.Errorf("default timeout = %d, want %d", got, config.DefaultCRSDownloadTimeoutSeconds)
	}
	dl.Timeout = 30
	if got := dl.GetEffectiveTimeoutSeconds(); got != 30 {
		t.Errorf("timeout = %d, want 30 (no 180s clamp)", got)
	}
}
