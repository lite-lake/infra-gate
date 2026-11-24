package crs

// H2/M2（内部PRD 迭代 2）测试：
//   - H2 CRS 供应链完整性：pin 清单/配置 pin 校验、无 pin 拒绝下载（D2）、
//     镜像自供哈希不参与判定、GitHub 官方 digest 交叉校验；
//   - M2 三级大小上限：tarball ≤100MB / 元数据 ≤1MB / 解压单文件 ≤100MB、累计 ≤300MB。
//
// 出口标准映射（PRD §10 迭代 2）：
//   ① 篡改 tarball 任一字节 → 校验失败走 stale 路径保留旧缓存；
//   ② 清单外版本且无 pin/金副本 → 拒绝下载（degrade 通知路径 = 既有状态机）；
//   ④ 模拟超限响应 → 下载/解压快速失败。

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/config"
)

// ── H2 出口标准①：篡改 tarball 任一字节 → pin 校验失败 → stale 路径保留旧缓存 ──

func TestEnsureCRSTamperedTarballRejectedByPinKeepsStaleCache(t *testing.T) {
	cacheDir := t.TempDir()
	version := uniqueVersion()

	tree := filepath.Join(t.TempDir(), "tree")
	writeCRSTree(t, tree)
	good := tarCRSGz(t, tree, "coreruleset-"+strings.TrimPrefix(version, "v")+"/")

	// 篡改 tarball 中间任一字节（等长替换，保持大小阈值通过）
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)/2] ^= 0xFF

	// 镜像自洽谎报：元数据 sha256 = 篡改内容的哈希（H2 下自供哈希不参与判定）
	mirror := newFakeMirror(t, tampered)

	// pin 来自清单 = 合法 tarball 哈希（镜像自供哈希与其脱钩）
	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: mirror.srv.URL, timeout: 5, retryCount: 1,
		goldenDir: strPtr(pinsOnlyGoldenDir(t, map[string]string{version: sha256Hex(good)})),
	}))
	seedValidCache(t, m, version)
	// F10 适配：删 hash 与 manifest 制造宽松档 stale（触发按预算刷新；内容篡改
	// 在 F10 下属严格档硬失败，不适用本用例「旧缓存可用」意图）
	if err := os.Remove(m.hashFilePath(version)); err != nil {
		t.Fatalf("remove hash file: %v", err)
	}
	if err := os.Remove(m.manifestFilePath(version)); err != nil {
		t.Fatalf("remove manifest file: %v", err)
	}
	snapshot := dirHashSnapshot(t, m.activeDir(version))

	res := m.EnsureCRS(version)
	if res.Err != nil {
		t.Fatalf("EnsureCRS must not fail in stale path, got: %v", res.Err)
	}
	if res.State != StateStale || res.Source != SourceCache || res.Dir != m.activeDir(version) {
		t.Fatalf("state/source/dir = %s/%s/%s, want stale/cache/<old dir>", res.State, res.Source, res.Dir)
	}

	// 旧缓存逐字节保留（绝不先删后下）
	if got := dirHashSnapshot(t, m.activeDir(version)); got != snapshot {
		t.Error("old cache directory changed during tampered-tarball refresh")
	}
	assertNoHalfWrittenArtifacts(t, cacheDir, version)

	// 刷新确实经过了网络（元数据 + tarball），且失败原因即 pin 完整性校验
	if n := mirror.requestCount(); n < 2 {
		t.Errorf("mirror request count = %d, want >= 2 (download attempted then rejected by pin)", n)
	}
	st, _ := StatusSnapshot(version)
	if st.State != StateStale || !strings.Contains(st.LastError, "integrity check failed") {
		t.Errorf("status = %+v, want stale with integrity-check last_error", st)
	}
}

// ── H2 出口标准②：清单外版本且无 pin/金副本 → 拒绝下载（零网络），按 failure_policy 处置 ──

func TestEnsureCRSUnpinnedVersionRefusedDownload(t *testing.T) {
	cases := []struct {
		name         string
		policy       string
		wantSentinel bool
	}{
		{"degrade policy returns sentinel", config.WAFFailurePolicyDegrade, true},
		{"fail policy returns plain error", config.WAFFailurePolicyFail, false},
		{"empty policy defaults to fail", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			version := uniqueVersion()

			// 镜像可达（提供合法 tarball）：拒绝必须发生在任何网络调用之前
			tree := filepath.Join(t.TempDir(), "tree")
			writeCRSTree(t, tree)
			mirror := newFakeMirror(t, tarCRSGz(t, tree, "coreruleset-"+strings.TrimPrefix(version, "v")+"/"))

			m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
				mirrorURL: mirror.srv.URL, timeout: 5, retryCount: 1,
				goldenDir: strPtr(""), failurePolicy: tc.policy, // 金副本禁用 = 无清单可用
			}))

			res := m.EnsureCRS(version)
			if res.Err == nil {
				t.Fatal("EnsureCRS should fail for unpinned version (D2 refusal)")
			}
			if !strings.Contains(res.Err.Error(), "download refused") {
				t.Errorf("error should be the explicit D2 refusal, got: %v", res.Err)
			}
			if tc.wantSentinel {
				if !errors.Is(res.Err, ErrCRSDegraded) {
					t.Fatalf("expected degrade sentinel, got: %v", res.Err)
				}
				if res.State != StateDegraded || res.Dir != "" {
					t.Errorf("state/dir = %s/%q, want degraded/empty", res.State, res.Dir)
				}
				st, ok := StatusSnapshot(version)
				if !ok || st.State != StateDegraded || st.LastError == "" {
					t.Errorf("status = %+v ok=%v, want degraded with last_error (waf_crs_degraded path)", st, ok)
				}
			} else {
				if errors.Is(res.Err, ErrCRSDegraded) {
					t.Fatalf("fail policy must not yield degrade sentinel: %v", res.Err)
				}
				if res.State == StateDegraded {
					t.Errorf("state = %s, want non-degraded under fail policy", res.State)
				}
			}

			// 零网络调用：拒绝发生在 pin 解析处，未发起任何请求
			if n := mirror.requestCount(); n != 0 {
				t.Errorf("mirror request count = %d, want 0 (refusal must precede any network call)", n)
			}
			assertNoHalfWrittenArtifacts(t, cacheDir, version)
		})
	}
}

// ── H2 pin 来源优先级：清单命中正例 / 配置 pin 优先于清单 / 配置 pin 在无清单时兜底 ──

func TestEnsureCRSPinSourcePriority(t *testing.T) {
	newTarball := func(t *testing.T, version string) []byte {
		t.Helper()
		tree := filepath.Join(t.TempDir(), "tree")
		writeCRSTree(t, tree)
		return tarCRSGz(t, tree, "coreruleset-"+strings.TrimPrefix(version, "v")+"/")
	}

	t.Run("manifest pin hit downloads successfully", func(t *testing.T) {
		cacheDir := t.TempDir()
		version := uniqueVersion()
		tarball := newTarball(t, version)
		mirror := newFakeMirror(t, tarball)

		m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
			mirrorURL: mirror.srv.URL, timeout: 5, retryCount: 1,
			goldenDir: strPtr(pinsOnlyGoldenDir(t, map[string]string{version: sha256Hex(tarball)})),
		}))
		res := m.EnsureCRS(version)
		if res.Err != nil || res.State != StateValid || res.Source != SourceMirror {
			t.Fatalf("result = %+v, want valid/mirror via manifest pin", res)
		}
	})

	t.Run("config pin takes precedence over manifest", func(t *testing.T) {
		cacheDir := t.TempDir()
		version := uniqueVersion()
		tarball := newTarball(t, version)
		mirror := newFakeMirror(t, tarball)

		// 配置 pin（错误值）与清单（正确值）同时存在 → 按配置判定 → 完整性失败
		m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
			mirrorURL: mirror.srv.URL, timeout: 5, retryCount: 1,
			goldenDir:     strPtr(pinsOnlyGoldenDir(t, map[string]string{version: sha256Hex(tarball)})),
			pinnedSHA256:  strings.Repeat("ef", 32),
			failurePolicy: config.WAFFailurePolicyFail,
		}))
		res := m.EnsureCRS(version)
		if res.Err == nil {
			t.Fatal("wrong config pin must fail verification even when manifest pin matches")
		}
		if !strings.Contains(res.Err.Error(), "integrity check failed") || !strings.Contains(res.Err.Error(), "source: config") {
			t.Errorf("failure should be config-pin integrity check, got: %v", res.Err)
		}
		// 下载确实发生过（pin 在场 → 不拒绝，走到校验处失败）
		if n := mirror.requestCount(); n < 2 {
			t.Errorf("mirror request count = %d, want >= 2 (config pin governs after download)", n)
		}
	})

	t.Run("config pin works without manifest (golden disabled)", func(t *testing.T) {
		cacheDir := t.TempDir()
		version := uniqueVersion()
		tarball := newTarball(t, version)
		mirror := newFakeMirror(t, tarball)

		m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
			mirrorURL: mirror.srv.URL, timeout: 5, retryCount: 1,
			goldenDir: strPtr(""), pinnedSHA256: sha256Hex(tarball),
		}))
		res := m.EnsureCRS(version)
		if res.Err != nil || res.State != StateValid {
			t.Fatalf("result = %+v, want valid via config pin without manifest", res)
		}
	})

	t.Run("config pin tolerates sha256: prefix and uppercase", func(t *testing.T) {
		cacheDir := t.TempDir()
		version := uniqueVersion()
		tarball := newTarball(t, version)
		mirror := newFakeMirror(t, tarball)

		// 与 GitHub Release digest 同款形态（sha256:<hex>，大小写混杂）应归一化后命中
		pinned := "sha256:" + strings.ToUpper(sha256Hex(tarball))
		m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
			mirrorURL: mirror.srv.URL, timeout: 5, retryCount: 1,
			goldenDir: strPtr(""), pinnedSHA256: pinned,
		}))
		res := m.EnsureCRS(version)
		if res.Err != nil || res.State != StateValid || res.Source != SourceMirror {
			t.Fatalf("result = %+v, want valid/mirror (pinned=%q)", res, pinned)
		}
		hash, source, err := m.resolvePinnedSHA256(version)
		if err != nil || hash != sha256Hex(tarball) || source != pinSourceConfig {
			t.Errorf("resolvePinnedSHA256 = (%q, %q, %v), want normalized config pin", hash, source, err)
		}
	})
}

// ── H2：镜像自供哈希不参与判定——镜像报告错误 sha，tarball 与 pin 一致 → 成功 ──

func TestEnsureCRSMirrorSelfReportedHashIgnored(t *testing.T) {
	cacheDir := t.TempDir()
	version := uniqueVersion()

	tree := filepath.Join(t.TempDir(), "tree")
	writeCRSTree(t, tree)
	tarball := tarCRSGz(t, tree, "coreruleset-"+strings.TrimPrefix(version, "v")+"/")

	mirror := newFakeMirror(t, tarball)
	// 镜像自供哈希与实际内容脱钩（错误值）；若参与判定将误拒
	mirror.reportedSHA256 = strings.Repeat("cd", 32)

	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: mirror.srv.URL, timeout: 5, retryCount: 1,
		goldenDir: strPtr(pinsOnlyGoldenDir(t, map[string]string{version: sha256Hex(tarball)})),
	}))
	res := m.EnsureCRS(version)
	if res.Err != nil || res.State != StateValid || res.Source != SourceMirror {
		t.Fatalf("result = %+v, want valid/mirror (mirror-reported hash must not participate)", res)
	}
}

// ── H2：crossCheckMetadataHash 对照矩阵（GitHub digest fail closed / 镜像仅日志） ──

func TestCrossCheckMetadataHash(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	tests := []struct {
		name       string
		metadata   string
		fromMirror bool
		wantErr    bool
	}{
		{"empty metadata skips cross-check (codeload fallback)", "", false, false},
		{"digest matches pin", pin, false, false},
		{"digest matches pin case-insensitively", strings.Repeat("AB", 32), false, false},
		{"mirror mismatch tolerated (log only)", strings.Repeat("cd", 32), true, false},
		{"github digest mismatch fails closed", strings.Repeat("cd", 32), false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := crossCheckMetadataHash("vTest", pin, pinSourceManifest, tt.metadata, tt.fromMirror, testLogger())
			if tt.wantErr && err == nil {
				t.Error("expected error for GitHub digest disagreement")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// ── H2：lookupPinManifest 清单解析表驱动 ──

func TestLookupPinManifest(t *testing.T) {
	manifest := `# pin manifest (test)
` + "v4.19.0 " + strings.Repeat("a1", 32) + `
` + "v4.20.0  " + strings.Repeat("B2", 32) + ` trailing
v4.21.0 not-hex-hash
v4.22.0 123
   # indented comment

` + "v4.23.0 " + strings.Repeat("c3", 32) + `
`
	tests := []struct {
		version string
		want    string
		ok      bool
	}{
		{"v4.19.0", strings.Repeat("a1", 32), true},
		{"v4.20.0", strings.Repeat("b2", 32), true}, // 大小写归一 + 多字段行取前两列
		{"v4.21.0", "", false},                      // 非法哈希行跳过
		{"v4.22.0", "", false},                      // 哈希过短跳过
		{"v4.23.0", strings.Repeat("c3", 32), true}, // 空行/缩进注释后仍可命中
		{"v4.24.0", "", false},                      // 未收录版本
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := lookupPinManifest([]byte(manifest), tt.version)
		if ok != tt.ok || got != tt.want {
			t.Errorf("lookupPinManifest(%q) = (%q, %v), want (%q, %v)", tt.version, got, ok, tt.want, tt.ok)
		}
	}
	if _, ok := lookupPinManifest([]byte(""), "v4.19.0"); ok {
		t.Error("empty manifest should not match")
	}
}

// ── H2：resolvePinnedSHA256 端到端（配置 > 清单 > 拒绝） ──

func TestResolvePinnedSHA256Priority(t *testing.T) {
	version := uniqueVersion()
	manifestPin := strings.Repeat("ab", 32)

	// 仅清单
	m := NewManager(t.TempDir(), testLogger(), newTestCRSConfig(t, testManagerOpts{
		goldenDir: strPtr(pinsOnlyGoldenDir(t, map[string]string{version: manifestPin})),
	}))
	hash, source, err := m.resolvePinnedSHA256(version)
	if err != nil || hash != manifestPin || source != pinSourceManifest {
		t.Fatalf("manifest-only = (%q, %q, %v), want manifest pin", hash, source, err)
	}

	// 配置 + 清单 → 配置优先
	configPin := strings.Repeat("ef", 32)
	m2 := NewManager(t.TempDir(), testLogger(), newTestCRSConfig(t, testManagerOpts{
		goldenDir:    strPtr(pinsOnlyGoldenDir(t, map[string]string{version: manifestPin})),
		pinnedSHA256: strings.ToUpper(configPin), // 配置值大小写归一
	}))
	hash, source, err = m2.resolvePinnedSHA256(version)
	if err != nil || hash != configPin || source != pinSourceConfig {
		t.Fatalf("config+manifest = (%q, %q, %v), want config pin (normalized)", hash, source, err)
	}

	// 都无（金副本禁用）→ D2 拒绝错误
	m3 := NewManager(t.TempDir(), testLogger(), newTestCRSConfig(t, testManagerOpts{goldenDir: strPtr("")}))
	if _, _, err := m3.resolvePinnedSHA256(version); err == nil || !strings.Contains(err.Error(), "download refused") {
		t.Fatalf("no-pin should return explicit D2 refusal, got: %v", err)
	}

	// 金副本启用但清单文件缺失 = 无清单（配置 pin 兜底；无配置则拒绝）
	m4 := NewManager(t.TempDir(), testLogger(), newTestCRSConfig(t, testManagerOpts{
		goldenDir: strPtr(t.TempDir()), // 目录存在但无 pins.sha256
	}))
	if _, _, err := m4.resolvePinnedSHA256(version); err == nil {
		t.Fatal("missing manifest file without config pin should be refused")
	}
}

// ── M2：readLimited 有界读取 ──

func TestReadLimited(t *testing.T) {
	tests := []struct {
		name    string
		limit   int64
		body    int
		wantErr bool
	}{
		{"within limit", 10, 5, false},
		{"exactly limit", 5, 5, false},
		{"one byte over", 5, 6, true},
		{"empty body", 5, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := readLimited(bytes.NewReader(bytes.Repeat([]byte("x"), tt.body)), tt.limit, "unit")
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "exceeds size limit") {
					t.Fatalf("expected size-limit error, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if int64(len(data)) != int64(tt.body) {
				t.Errorf("read %d bytes, want %d", len(data), tt.body)
			}
		})
	}
}

// ── M2：元数据 ≤1MB（真实 HTTP 路径，边界双侧） ──

func TestMetadataGetSizeLimit(t *testing.T) {
	// 恰好 1MB → 成功
	m := NewManager(t.TempDir(), testLogger(), nil)
	data, err := m.metadataGet(serveBytesURL(t, maxMetadataBytes), metadataDeadline())
	if err != nil {
		t.Fatalf("exactly %d bytes should succeed: %v", maxMetadataBytes, err)
	}
	if len(data) != maxMetadataBytes {
		t.Errorf("read %d bytes, want %d", len(data), maxMetadataBytes)
	}

	// 1MB+1 → 快速失败，错误指明元数据上限
	m2 := NewManager(t.TempDir(), testLogger(), nil)
	if _, err := m2.metadataGet(serveBytesURL(t, maxMetadataBytes+1), metadataDeadline()); err == nil {
		t.Fatal("metadata over 1MB should fail")
	} else if !strings.Contains(err.Error(), "metadata response exceeds size limit") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ── M2：tarball ≤100MB（超限流式响应快速失败，出口标准④） ──

func TestFetchOnceTarballSizeLimit(t *testing.T) {
	deadline := time.Now().Add(30 * time.Second)
	m := NewManager(t.TempDir(), testLogger(), nil)

	if _, err := m.fetchOnce(serveBytesURL(t, maxTarballBytes+1), false, deadline); err == nil {
		t.Fatal("tarball over 100MB should fail")
	} else if !strings.Contains(err.Error(), "tarball response exceeds size limit") {
		t.Errorf("unexpected error: %v", err)
	}
}

// serveBytesURL 启动一个流式写入 size 字节（64KB 分块）的临时服务器并返回其 URL
func serveBytesURL(t *testing.T, size int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := bytes.Repeat([]byte("a"), 64*1024)
		for written := 0; written < size; {
			n := size - written
			if n > len(buf) {
				n = len(buf)
			}
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			written += n
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// ── M2：解压限幅——单文件 ≤100MB、累计 ≤300MB（gzip 炸弹防线） ──

// bombEntrySpec 解压限幅测试的 tar 条目（内容全零，gzip 高压缩、构造内存平稳）
type bombEntrySpec struct {
	name string
	size int64
}

// buildZeroTarGz 构造含指定条目（全零内容）的 tar.gz
func buildZeroTarGz(t *testing.T, entries []bombEntrySpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	zeroChunk := bytes.Repeat([]byte{0}, 64*1024)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name:     e.name,
			Typeflag: tar.TypeReg,
			Size:     e.size,
			Mode:     0644,
		}); err != nil {
			t.Fatalf("write tar header %s: %v", e.name, err)
		}
		// 分块写入全零内容（gzip 高压缩，构造过程内存平稳）
		for remaining := e.size; remaining > 0; {
			n := int64(len(zeroChunk))
			if n > remaining {
				n = remaining
			}
			if _, err := tw.Write(zeroChunk[:n]); err != nil {
				t.Fatalf("write tar body %s: %v", e.name, err)
			}
			remaining -= n
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

func TestExtractTarGzSingleFileLimit(t *testing.T) {
	m := NewManager(t.TempDir(), testLogger(), &config.WAFCRSConfig{})
	target := t.TempDir()
	// 单文件 100MB+1 全零条目（解压前 gzip 极小）→ 快速失败于单文件上限
	data := buildZeroTarGz(t, []bombEntrySpec{{"coreruleset-test/huge.conf", maxExtractSingleFileBytes + 1}})
	err := m.extractTarGz(bytes.NewReader(data), target)
	if err == nil {
		t.Fatal("single file over 100MB should fail")
	}
	if !strings.Contains(err.Error(), "single-file extraction limit") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExtractTarGzCumulativeLimit(t *testing.T) {
	m := NewManager(t.TempDir(), testLogger(), &config.WAFCRSConfig{})
	target := t.TempDir()
	// 三个恰好 100MB 的文件（累计恰 300MB，均在上限内）+ 1 字节 → 累计超限失败
	data := buildZeroTarGz(t, []bombEntrySpec{
		{"coreruleset-test/f1.conf", maxExtractSingleFileBytes},
		{"coreruleset-test/f2.conf", maxExtractSingleFileBytes},
		{"coreruleset-test/f3.conf", maxExtractSingleFileBytes},
		{"coreruleset-test/f4.conf", 1},
	})
	err := m.extractTarGz(bytes.NewReader(data), target)
	if err == nil {
		t.Fatal("cumulative extraction over 300MB should fail")
	}
	if !strings.Contains(err.Error(), "cumulative extraction exceeds total limit") {
		t.Errorf("unexpected error: %v", err)
	}
	// 前三个文件（上限内）已落盘，第四个不得存在
	for _, name := range []string{"f1.conf", "f2.conf", "f3.conf"} {
		if _, err := os.Stat(filepath.Join(target, "coreruleset-test", name)); err != nil {
			t.Errorf("entry %s should exist before the limit trip: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(target, "coreruleset-test", "f4.conf")); !os.IsNotExist(err) {
		t.Error("entry beyond cumulative limit must not be written")
	}
}

func TestExtractTarGzWithinLimitsSucceeds(t *testing.T) {
	m := NewManager(t.TempDir(), testLogger(), &config.WAFCRSConfig{})
	target := t.TempDir()
	// 恰好单文件上限 100MB → 正常解压（上限值本身放行）
	data := buildZeroTarGz(t, []bombEntrySpec{{"coreruleset-test/ok.conf", maxExtractSingleFileBytes}})
	if err := m.extractTarGz(bytes.NewReader(data), target); err != nil {
		t.Fatalf("entry at exactly the single-file limit should succeed: %v", err)
	}
	fi, err := os.Stat(filepath.Join(target, "coreruleset-test", "ok.conf"))
	if err != nil {
		t.Fatalf("stat extracted file: %v", err)
	}
	if fi.Size() != maxExtractSingleFileBytes {
		t.Errorf("extracted size = %d, want %d", fi.Size(), maxExtractSingleFileBytes)
	}
}

// TestExtractTarGzDeclaredSizeMismatchFails M2 纵深防御：tar 头声明大小与实际流不符
// （声明 10 字节、实际尾随 600 字节垃圾）——读取核对 n==header.Size 通过后，
// 垃圾尾随在下一轮 tar.Reader.Next() 处解析失败，解压整体报错而非静默产出脏数据
func TestExtractTarGzDeclaredSizeMismatchFails(t *testing.T) {
	m := NewManager(t.TempDir(), testLogger(), &config.WAFCRSConfig{})
	target := t.TempDir()

	// 先构造原始 tar 字节流（tar.Writer 逐字节直写、不缓冲，可直接向底层追加垃圾），
	// 再整体 gzip，避免 gzip 缓冲导致字节顺序错乱
	var rawTar bytes.Buffer
	tw := tar.NewWriter(&rawTar)
	if err := tw.WriteHeader(&tar.Header{Name: "coreruleset-test/liar.conf", Typeflag: tar.TypeReg, Size: 10, Mode: 0644}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := tw.Write([]byte("0123456789")); err != nil { // 恰好声明大小
		t.Fatalf("write declared body: %v", err)
	}
	// 尾随垃圾（伪装下一条目）直接写入底层流：标准 tar.Writer 会按声明大小拦截
	// 超写，恶意 tarball 需绕过写侧校验构造
	if _, err := rawTar.Write(bytes.Repeat([]byte{0xEE}, 600)); err != nil {
		t.Fatalf("write trailing garbage: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(rawTar.Bytes()); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	if err := m.extractTarGz(bytes.NewReader(buf.Bytes()), target); err == nil {
		t.Fatal("tar with declared-size mismatch must fail extraction")
	}
}
