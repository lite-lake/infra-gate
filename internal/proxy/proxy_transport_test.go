package proxy

// L2（内部PRD 迭代 1）：后端 transport 显式禁用环境代理——
// ProxyFromEnvironment 会让 HTTP_PROXY/HTTPS_PROXY 劫持全部后端出网流量，
// 改为 Proxy: nil（mesh/直连即主路径）。
// 覆盖两层：白盒字段断言（Proxy == nil）+ 行为断言（HTTP_PROXY 哨兵零命中、
// 请求直达后端）。

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// l2NewTestProxy 构造禁用健康检查的 Proxy（禁用健康检查，避免测试 goroutine）
func l2NewTestProxy(backends []string) *Proxy {
	return NewProxy(
		backends,
		"/healthz",
		10, 5,
		logger.GetDefaultLogger(),
		nil,
		nil,
		false,
		false,
		"",
		"",
		false,
		false, // 禁用健康检查，避免测试 goroutine
		false,
		"",
		defaultWSConfig(),
		UpstreamConfig{},
	)
}

// L2：后端 transport 的 Proxy 必须为 nil（非 ProxyFromEnvironment）
func TestBackendTransportDisablesEnvironmentProxy(t *testing.T) {
	p := l2NewTestProxy([]string{"http://backend.example:80"})
	if p.transport.Proxy != nil {
		t.Fatalf("backend transport Proxy must be nil (HTTP_PROXY/HTTPS_PROXY must not hijack backend egress), got non-nil proxy func")
	}
}

// L2 行为断言：HTTP_PROXY 指向哨兵 httptest 服务器时，请求经生产 transport 必须
// ① 哨兵零命中（环境代理不劫持）、② 直达后端（后端收到并应答 direct-ok）。
// 辨别力设计：目标主机名刻意取非回环 + .invalid 顶级域——ProxyFromEnvironment
// 对回环目标恒直连（loopback exemption），用回环地址会让本用例失去辨别力；
// 直连场景经白盒覆盖本用例实例的 transport DialContext 把伪主机名导流到本地
// 后端监听（仅测试实例，生产代码零改动）。
// 哨兵链路自证：主断言后另发一发经静态代理函数的对照请求，断言哨兵确实会被
// 命中——排除「哨兵接线错误导致主断言空转通过」的假绿。对照层刻意不依赖
// ProxyFromEnvironment 读环境（net/http 对其有 per-process sync.Once 缓存，
// 读值时序受测试顺序影响），静态函数保证自证确定性。
func TestBackendTransportIgnoresHTTPProxyEnv(t *testing.T) {
	var sentinelHits, backendHits atomic.Int64

	sentinel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sentinelHits.Add(1)
		http.Error(w, "sentinel proxy must not be used for backend egress", http.StatusBadGateway)
	}))
	defer sentinel.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits.Add(1)
		_, _ = w.Write([]byte("direct-ok"))
	}))
	defer backend.Close()

	// 环境哨兵（大小写双设：httpproxy.FromEnvironment 两者都读）
	t.Setenv("HTTP_PROXY", sentinel.URL)
	t.Setenv("http_proxy", sentinel.URL)

	p := l2NewTestProxy([]string{"http://l2-backend-probe.invalid"})
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	backendAddr := backend.Listener.Addr().String()
	// 白盒导流（仅测试实例，生产代码零改动）：.invalid 主机名不可解析，把目标
	// 伪主机名导流到本地后端监听；其余地址（含哨兵）原样放行——整体劫持式导流
	// 会把「发往代理的连接」也吞掉，反向架空本用例要防范的回归，故必须按地址区分
	dialOverride := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "l2-backend-probe.invalid:") {
			return dialer.DialContext(ctx, "tcp", backendAddr)
		}
		return dialer.DialContext(ctx, network, addr)
	}
	p.transport.DialContext = dialOverride

	// ① 主断言：生产 transport 直达后端，哨兵零命中
	req := httptest.NewRequest(http.MethodGet, "http://l2-backend-probe.invalid/l2probe", nil)
	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip via backend transport: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read direct response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "direct-ok" {
		t.Fatalf("direct response = %d %q, want 200 direct-ok", resp.StatusCode, body)
	}
	if n := sentinelHits.Load(); n != 0 {
		t.Errorf("sentinel proxy hits = %d, want 0 (HTTP_PROXY must not hijack backend egress)", n)
	}
	if n := backendHits.Load(); n != 1 {
		t.Errorf("backend hits = %d, want 1 (request must reach backend directly)", n)
	}

	// ② 哨兵链路自证：静态代理函数的对照 transport（复用同一份导流）应恰好
	// 命中哨兵一次——证明哨兵接线在主断言的同一条拨号链路上确实可拦截
	proxyURL, err := url.Parse(sentinel.URL)
	if err != nil {
		t.Fatalf("parse sentinel URL: %v", err)
	}
	control := &http.Transport{
		Proxy:       func(*http.Request) (*url.URL, error) { return proxyURL, nil },
		DialContext: dialOverride,
	}
	resp2, err := control.RoundTrip(req.Clone(context.Background()))
	if err != nil {
		t.Fatalf("control RoundTrip via sentinel proxy: %v", err)
	}
	resp2.Body.Close()
	if n := sentinelHits.Load(); n != 1 {
		t.Errorf("sentinel hits after control request = %d, want 1 (sentinel wiring must be provably intercepting)", n)
	}
}

// F1c（内部PRD §4.1.4）：UpstreamConfig 接线——MaxConnsPerHost 与
// ResponseHeaderTimeout 按传入值生效（缺省回落 256 / 1800s，原值 0=无上限）
func TestUpstreamConfigWired(t *testing.T) {
	p := l2NewTestProxy([]string{"http://backend.example:80"})
	if p.transport.MaxConnsPerHost != 256 {
		t.Errorf("default MaxConnsPerHost = %d, want 256", p.transport.MaxConnsPerHost)
	}
	if p.transport.ResponseHeaderTimeout != 1800*time.Second {
		t.Errorf("default ResponseHeaderTimeout = %v, want 1800s", p.transport.ResponseHeaderTimeout)
	}

	p2 := NewProxy(
		[]string{"http://backend.example:80"},
		"/healthz",
		10, 5,
		logger.GetDefaultLogger(),
		nil,
		nil,
		false,
		false,
		"",
		"",
		false,
		false,
		false,
		"",
		defaultWSConfig(),
		UpstreamConfig{MaxConnsPerHost: 512, ResponseHeaderTimeout: 30 * time.Second},
	)
	if p2.transport.MaxConnsPerHost != 512 {
		t.Errorf("override MaxConnsPerHost = %d, want 512", p2.transport.MaxConnsPerHost)
	}
	if p2.transport.ResponseHeaderTimeout != 30*time.Second {
		t.Errorf("override ResponseHeaderTimeout = %v, want 30s", p2.transport.ResponseHeaderTimeout)
	}
}
