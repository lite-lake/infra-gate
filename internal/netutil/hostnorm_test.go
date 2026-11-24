package netutil

// F3 CanonicalHost 单元测试（内部PRD §4.3/§11 F3）：
// 大小写/尾点/带端口/IPv6 literal/尾点+端口变体全部归一到同一规范形态。

import "testing"

func TestCanonicalHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"EXAMPLE.com.", "example.com"},
		{"example.com.", "example.com"},
		{"example.com:443", "example.com"},
		{"Example.Com:8443", "example.com"},
		{"example.com.:443", "example.com"},
		{"[::1]", "::1"},
		{"[::1]:443", "::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"}, // 无端口 IPv6 原样（SplitHostPort 失败、无括号不剥）
		{"*.example.com", "*.example.com"},
		{"中文.example.com", "中文.example.com"}, // 非 ASCII 原样返回（不匹配任何配置名）
		{"", ""},
	}
	for _, tc := range cases {
		if got := CanonicalHost(tc.in); got != tc.want {
			t.Errorf("CanonicalHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCanonicalHostEquivalence 变体等价性：同一域名的全部变体归一后互相相等
func TestCanonicalHostEquivalence(t *testing.T) {
	variants := []string{
		"api.example.net",
		"API.Example.NET",
		"api.example.net.",
		"api.example.net:443",
		"API.EXAMPLE.NET.:8443",
	}
	base := CanonicalHost(variants[0])
	for _, v := range variants[1:] {
		if got := CanonicalHost(v); got != base {
			t.Errorf("variant %q normalized to %q, want %q", v, got, base)
		}
	}
}
