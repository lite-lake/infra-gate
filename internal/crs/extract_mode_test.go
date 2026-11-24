package crs

// L5（内部PRD 迭代 1）：tar 解压权限固定——文件 0644、目录 0755，
// 忽略 tarball 内 header.Mode（此前恶意/异常 tarball 可落 0777 可执行位）。
// 直接对 extractTarGz 做单测：构造 mode 故意异常（文件 0777 / 目录 0700）的
// tar.gz，断言落盘权限与 tarball 内 mode 无关。

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/lite-lake/infra-gate/internal/config"
)

// buildBadModeTarGz 构造条目 mode 故意异常的 tar.gz：
// 目录 0700、文件 0777（模拟 tarball 携带激进权限位）
func buildBadModeTarGz(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	writeEntry := func(hdr *tar.Header, body []byte) {
		hdr.Size = int64(len(body))
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header %s: %v", hdr.Name, err)
		}
		if len(body) > 0 {
			if _, err := tw.Write(body); err != nil {
				t.Fatalf("write tar body %s: %v", hdr.Name, err)
			}
		}
	}

	writeEntry(&tar.Header{
		Name:     "pkg/",
		Typeflag: tar.TypeDir,
		Mode:     0700, // 异常目录权限（期望落盘 0755）
	}, nil)
	writeEntry(&tar.Header{
		Name:     "pkg/rules.conf",
		Typeflag: tar.TypeReg,
		Mode:     0777, // 异常文件权限（期望落盘 0644）
	}, []byte("SecRule ENGINE-INIT test\n"))
	writeEntry(&tar.Header{
		Name:     "top.conf",
		Typeflag: tar.TypeReg,
		Mode:     0777,
	}, []byte("top-level file\n"))

	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

func TestExtractTarGzFixedPermissions(t *testing.T) {
	m := NewManager(t.TempDir(), testLogger(), &config.WAFCRSConfig{})
	target := t.TempDir()
	if err := m.extractTarGz(bytes.NewReader(buildBadModeTarGz(t)), target); err != nil {
		t.Fatalf("extractTarGz: %v", err)
	}

	// 目录权限固定 0755（忽略 tarball 的 0700）
	dirInfo, err := os.Stat(filepath.Join(target, "pkg"))
	if err != nil {
		t.Fatalf("stat extracted dir: %v", err)
	}
	if !dirInfo.IsDir() {
		t.Fatalf("pkg is not a directory")
	}
	if got := dirInfo.Mode().Perm(); got != 0755 {
		t.Errorf("dir perm = %04o, want 0755 (fixed, tarball mode ignored)", got)
	}

	// 文件权限固定 0644（忽略 tarball 的 0777，无可执行位）
	fileInfo, err := os.Stat(filepath.Join(target, "pkg", "rules.conf"))
	if err != nil {
		t.Fatalf("stat extracted file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0644 {
		t.Errorf("file perm = %04o, want 0644 (fixed, tarball mode ignored)", got)
	}
	topInfo, err := os.Stat(filepath.Join(target, "top.conf"))
	if err != nil {
		t.Fatalf("stat extracted top-level file: %v", err)
	}
	if got := topInfo.Mode().Perm(); got != 0644 {
		t.Errorf("top-level file perm = %04o, want 0644", got)
	}
	if topInfo.Mode()&0111 != 0 {
		t.Errorf("extracted file must not carry executable bits, mode = %v", topInfo.Mode())
	}
}
