package crs

// F10 CRS 缓存篡改分档测试（内部PRD §4.10/§11 F10）：
// 篡改 + 断网 + 金副本在场 → 金副本启动（StateStale/SourceGolden）+ tampered 透出 + 目录原位保留；
// 删哈希（manifest 在场 → 严格档；manifest 不在场 → 宽松档 stale）；
// 篡改 + 刷新成功 → valid 但保留 tampered 证据标记。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lite-lake/infra-gate/internal/config"
)

// tamperCacheContent 向规则文件追加内容制造 hash 不匹配（篡改证据）
func tamperCacheContent(t *testing.T, m *Manager, version string) {
	t.Helper()
	p := filepath.Join(m.activeDir(version), "rules", "REQUEST-910-TEST-00.conf")
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := f.WriteString("# tampered\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	f.Close()
}

// TestTamperWithGoldenStartsGolden 篡改 + 断网 + 金副本在场 → 金副本兜底启动
// （StateStale/SourceGolden，不跨版本 substitution 由金副本目录含该版本保证），
// 被篡改目录原位保留（取证），Integrity 透出 tampered
func TestTamperWithGoldenStartsGolden(t *testing.T) {
	cacheDir := t.TempDir()
	goldenDir := t.TempDir()
	version := uniqueVersion()
	writeCRSTree(t, filepath.Join(goldenDir, version))

	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: unreachableMirrorURL(t), timeout: 2, retryCount: 1,
		goldenDir: strPtr(goldenDir),
	}))
	seedValidCache(t, m, version)
	tamperCacheContent(t, m, version)
	snapshot := dirHashSnapshot(t, m.activeDir(version))

	res := m.EnsureCRS(version)
	if res.State != StateStale || res.Source != SourceGolden {
		t.Fatalf("state/source = %s/%s, want stale/golden (tampered cache refused, golden fallback)", res.State, res.Source)
	}
	if res.Dir != filepath.Join(goldenDir, version) {
		t.Errorf("dir = %s, want golden version dir", res.Dir)
	}
	st, ok := StatusSnapshot(version)
	if !ok || st.Integrity != IntegrityStatusTampered {
		t.Errorf("status integrity = %q, want tampered", st.Integrity)
	}
	// 被篡改目录原位保留（取证 + 失败路径永不删旧缓存）
	if got := dirHashSnapshot(t, m.activeDir(version)); got != snapshot {
		t.Error("tampered cache directory must be preserved in place for forensics")
	}
}

// TestHashDeletedWithManifestIsStrictTier 删哈希 + manifest 在场 → 升级严格档
// （拒绝加载被篡改缓存，即便内容本身未变——封堵「删哈希降档」旁路）
func TestHashDeletedWithManifestIsStrictTier(t *testing.T) {
	cacheDir := t.TempDir()
	version := uniqueVersion()
	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: unreachableMirrorURL(t), timeout: 2, retryCount: 1,
		goldenDir: strPtr(""),
	}))
	seedValidCache(t, m, version)
	// 只删 hash（manifest 保留：两者同批原子落盘，hash 单独消失 = 被删）
	if err := os.Remove(m.hashFilePath(version)); err != nil {
		t.Fatalf("remove hash: %v", err)
	}

	res := m.EnsureCRS(version)
	if res.Err == nil || res.State != "" || res.Dir != "" {
		t.Fatalf("state/dir/err = %s/%s/%v, want refused (hash deleted + manifest present = strict tier)", res.State, res.Dir, res.Err)
	}
	if st, _ := StatusSnapshot(version); st.Integrity != IntegrityStatusTampered {
		t.Errorf("integrity = %q, want tampered (hash_deleted)", st.Integrity)
	}
}

// TestHashDeletedWithoutManifestIsLooseTier 删哈希 + manifest 同删 → 宽松档
// （无篡改证据：维持 D4 可用性优先，旧缓存 stale 启动）
func TestHashDeletedWithoutManifestIsLooseTier(t *testing.T) {
	cacheDir := t.TempDir()
	version := uniqueVersion()
	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: unreachableMirrorURL(t), timeout: 2, retryCount: 1,
		goldenDir: strPtr(""),
	}))
	seedValidCache(t, m, version)
	if err := os.Remove(m.hashFilePath(version)); err != nil {
		t.Fatalf("remove hash: %v", err)
	}
	if err := os.Remove(m.manifestFilePath(version)); err != nil {
		t.Fatalf("remove manifest: %v", err)
	}

	res := m.EnsureCRS(version)
	if res.State != StateStale || res.Source != SourceCache || res.Dir != m.activeDir(version) {
		t.Fatalf("state/source/dir = %s/%s/%s, want stale/cache/<old dir> (loose tier)", res.State, res.Source, res.Dir)
	}
	if st, _ := StatusSnapshot(version); st.Integrity != IntegrityStatusStaleUnver {
		t.Errorf("integrity = %q, want stale-unverified", st.Integrity)
	}
}

// TestLooseTierPrefersGoldenOverUnverifiedLegacy 宽松档 + 金副本在场 → 用金副本
// （封堵「删哈希让篡改缓存走宽松档」旁路）
func TestLooseTierPrefersGoldenOverUnverifiedLegacy(t *testing.T) {
	cacheDir := t.TempDir()
	goldenDir := t.TempDir()
	version := uniqueVersion()
	writeCRSTree(t, filepath.Join(goldenDir, version))

	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: unreachableMirrorURL(t), timeout: 2, retryCount: 1,
		goldenDir: strPtr(goldenDir),
	}))
	seedValidCache(t, m, version)
	// 宽松档形态：hash+manifest 都删 + 篡改内容（无证据可判）
	if err := os.Remove(m.hashFilePath(version)); err != nil {
		t.Fatalf("remove hash: %v", err)
	}
	if err := os.Remove(m.manifestFilePath(version)); err != nil {
		t.Fatalf("remove manifest: %v", err)
	}
	tamperCacheContent(t, m, version)

	res := m.EnsureCRS(version)
	if res.State != StateValid || res.Source != SourceGolden {
		t.Fatalf("state/source = %s/%s, want valid/golden (loose tier prefers golden)", res.State, res.Source)
	}
}

// TestTamperedThenRefreshSuccessKeepsEvidence 篡改 + 刷新成功 → valid 但保留
// tampered 证据标记（供一次性告警）
func TestTamperedThenRefreshSuccessKeepsEvidence(t *testing.T) {
	cacheDir := t.TempDir()
	version := uniqueVersion()
	// 可用镜像（提供与 seed 相同内容的新鲜 tarball）
	tree := filepath.Join(t.TempDir(), "tree")
	writeCRSTree(t, tree)
	tarball := tarCRSGz(t, tree, "coreruleset-"+strings.TrimPrefix(version, "v")+"/")
	mirror := newFakeMirror(t, tarball)

	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: mirror.srv.URL, timeout: 5, retryCount: 1,
		goldenDir: strPtr(pinsOnlyGoldenDir(t, map[string]string{version: sha256Hex(tarball)})),
	}))
	seedValidCache(t, m, version)
	tamperCacheContent(t, m, version)

	res := m.EnsureCRS(version)
	if res.State != StateValid {
		t.Fatalf("state = %s, want valid (refresh succeeded)", res.State)
	}
	st, _ := StatusSnapshot(version)
	if st.Integrity != IntegrityStatusTampered {
		t.Errorf("integrity = %q, want tampered evidence retained after successful refresh", st.Integrity)
	}
}

// TestStrictTierNoGoldenDegradePolicy 篡改 + 无金副本 + degrade（带 ack）→
// 降级哨兵（而非加载被篡改缓存）
func TestStrictTierNoGoldenDegradePolicy(t *testing.T) {
	cacheDir := t.TempDir()
	version := uniqueVersion()
	m := NewManager(cacheDir, testLogger(), newTestCRSConfig(t, testManagerOpts{
		mirrorURL: unreachableMirrorURL(t), timeout: 2, retryCount: 1,
		goldenDir: strPtr(""), failurePolicy: config.WAFFailurePolicyDegrade,
	}))
	seedValidCache(t, m, version)
	tamperCacheContent(t, m, version)

	res := m.EnsureCRS(version)
	if res.State != StateDegraded || res.Err == nil || !strings.Contains(res.Err.Error(), "tampered") {
		t.Fatalf("state/err = %s/%v, want degraded with tampered sentinel", res.State, res.Err)
	}
}
