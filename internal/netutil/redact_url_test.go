package netutil

// F7 URL 脱敏测试（内部PRD §4.7/§11 F7）。

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestRedactURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"webhook key redacted", "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc123secret", "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?***"},
		{"userinfo stripped", "http://user:pass@example.com/api", "http://example.com/api"},
		{"no query unchanged", "https://example.com/api/v1", "https://example.com/api/v1"},
		{"fragment stripped", "https://example.com/p#frag", "https://example.com/p"},
		{"multiple params all gone", "https://example.com/p?a=1&token=zzz&b=2", "https://example.com/p?***"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		if got := RedactURL(tc.in); got != tc.want {
			t.Errorf("%s: RedactURL(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}

	// 幂等
	once := RedactURL("https://example.com/p?key=abc")
	if again := RedactURL(once); again != once {
		t.Errorf("idempotent: %q -> %q", once, again)
	}

	// 解析失败兜底：凭据参数值被抹
	got := RedactURL("://bad url token=zzz&x=1")
	if want := "://bad url token=***&x=1"; got != want {
		t.Errorf("fallback: RedactURL = %q, want %q", got, want)
	}
}

// sentinelErr errors.Is 链保留验证用哨兵
var sentinelErr = errors.New("dial tcp: refused")

func TestRedactURLError(t *testing.T) {
	orig := &url.Error{
		Op:  "Post",
		URL: "https://qyapi.weixin.qq.com/webhook/send?key=topsecret",
		Err: sentinelErr,
	}
	redacted := RedactURLError(orig)
	if !errors.Is(redacted, sentinelErr) {
		t.Error("errors.Is chain must be preserved through RedactURLError")
	}
	var ue *url.Error
	if !errors.As(redacted, &ue) {
		t.Fatal("errors.As(*url.Error) must still match")
	}
	if ue.URL == orig.URL || !strings.Contains(ue.URL, "***") {
		t.Errorf("url.Error.URL should be redacted, got %q", ue.URL)
	}
	// 非 url.Error 原样
	plain := errors.New("plain")
	if RedactURLError(plain) != plain {
		t.Error("non url.Error should be returned as-is")
	}
	if RedactURLError(nil) != nil {
		t.Error("nil should return nil")
	}
}
