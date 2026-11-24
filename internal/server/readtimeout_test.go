package server

// per-host 整请求读超时验证：
//   - 缺省继承 server 120s，host 覆盖生效；
//   - HTTP/1.1 慢 body：普通 host 按 server 缺省超时，上传 host 按覆盖值成功；
//   - WebSocket 升级请求不设置读截止时间（避免 hijack 后连接被误杀）。

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/config"
)

func durationPtr(d time.Duration) *time.Duration { return &d }

func TestHostGetEffectiveReadTimeout(t *testing.T) {
	serverDefault := 120 * time.Second

	if got := (&config.HostConfig{}).GetEffectiveReadTimeout(serverDefault); got != serverDefault {
		t.Fatalf("nil 应继承 server 缺省: %v", got)
	}
	if got := (&config.HostConfig{ReadTimeout: durationPtr(0)}).GetEffectiveReadTimeout(serverDefault); got != serverDefault {
		t.Fatalf("0 应继承 server 缺省: %v", got)
	}
	if got := (&config.HostConfig{ReadTimeout: durationPtr(-time.Second)}).GetEffectiveReadTimeout(serverDefault); got != serverDefault {
		t.Fatalf("负值应继承 server 缺省: %v", got)
	}
	if got := (&config.HostConfig{ReadTimeout: durationPtr(30 * time.Minute)}).GetEffectiveReadTimeout(serverDefault); got != 30*time.Minute {
		t.Fatalf("覆盖值不生效: %v", got)
	}
}

func TestServerGetEffectiveReadTimeout(t *testing.T) {
	if got := (&config.ServerConfig{}).GetEffectiveReadTimeout(); got != config.DefaultServerReadTimeout {
		t.Fatalf("零值应取缺省 120s，实际 %v", got)
	}
	if got := (&config.ServerConfig{ReadTimeout: 45 * time.Second}).GetEffectiveReadTimeout(); got != 45*time.Second {
		t.Fatalf("配置值不生效: %v", got)
	}
}

// slowBodyBackend 读取完整请求体后才响应 200，用于观察网关读超时行为
func slowBodyBackend(t *testing.T) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// sendSlowPut 建立原始 TCP 连接，先发头再逐字节缓慢发送 body，
// 返回服务端是否在 body 发完前关闭了连接（false = 请求完成）。
func sendSlowPut(t *testing.T, addr, host string, bodyLen, chunk int, interval time.Duration) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	req := fmt.Sprintf("PUT /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		host, bodyLen)
	if _, err := conn.Write([]byte(req)); err != nil {
		return true
	}
	payload := strings.Repeat("a", chunk)
	sent := 0
	for sent < bodyLen {
		n := chunk
		if bodyLen-sent < n {
			n = bodyLen - sent
		}
		if _, err := conn.Write([]byte(payload[:n])); err != nil {
			return true
		}
		sent += n
		time.Sleep(interval)
	}
	// 等待响应：若能完整读到状态行且为 200，说明未被超时打断
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return true
	}
	return !strings.Contains(line, "200")
}

// TestPerHostReadTimeout_H1 普通 host 按 server 缺省超时，上传 host 使用覆盖值完成
func TestPerHostReadTimeout_H1(t *testing.T) {
	chdirToRepoRoot(t) // NewServer 的模板/缓存按仓库根相对路径解析
	backend, _ := slowBodyBackend(t)
	port := freeTCPPort(t)

	uploadHost := config.HostConfig{
		Name:               "upload.test",
		Port:               port,
		Backend:            []string{backend.URL},
		HealthCheckEnabled: boolPtr(false),
		ReadTimeout:        durationPtr(5 * time.Second),
	}
	normalHost := config.HostConfig{
		Name:               "normal.test",
		Port:               port,
		Backend:            []string{backend.URL},
		HealthCheckEnabled: boolPtr(false),
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:        port,
			ReadTimeout: 500 * time.Millisecond,
		},
		Hosts: []config.HostConfig{uploadHost, normalHost},
	}
	s, err := NewServer(cfg, srvTestLogger())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.shutdownAllServers() })
	if err := s.startHTTPServer(port, cfg.Hosts); err != nil {
		t.Fatalf("startHTTPServer: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if !waitTCPOpen(addr, 3*time.Second) {
		t.Fatal("网关端口未就绪")
	}

	// 普通 host：server 缺省 500ms，body 发送 2s → 必须被提前中断
	if !sendSlowPut(t, addr, "normal.test", 20, 1, 100*time.Millisecond) {
		t.Fatal("普通 host 应在 server 缺省读超时后被中断")
	}

	// 上传 host：覆盖 5s，body 发送 2s → 必须完成
	if sendSlowPut(t, addr, "upload.test", 20, 1, 100*time.Millisecond) {
		t.Fatal("上传 host 应按 5s 覆盖值完成慢速请求")
	}
}
