package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lite-lake/infra-gate/internal/admin"
	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/deployinfo"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/notification"
	"github.com/lite-lake/infra-gate/internal/server"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig("configs/server.yml")
	if err != nil {
		// Use default logger for initial error
		defaultLogger := logger.GetDefaultLogger()
		defaultLogger.Fatal("Failed to load configuration", logger.NewField("error", err))
	}

	// Initialize logger with config
	log := logger.NewLogger(cfg.Logger)

	// F3（内部PRD §4.3）：LoadConfig in-place 归一化提示（config 包无
	// logger，由 main 打印）
	for _, w := range cfg.NormalizeWarnings {
		log.Warn(w)
	}

	// Log deploy environment info
	di := deployinfo.Get()
	log.Info("Deploy environment loaded",
		logger.NewField("deploy_env", di.DeployEnv),
		logger.NewField("deploy_zone", di.DeployZone),
		logger.NewField("deploy_server", di.DeployServer),
		logger.NewField("deploy_service", di.DeployService),
		logger.NewField("is_deployed", di.IsSet()),
	)

	// Initialize notification manager
	notifier := notification.NewNotifier(cfg.Notification, log, "infra-gate")

	// Send starting event
	notifier.SendNotification("starting", map[string]string{
		"端口": fmt.Sprintf("%d", cfg.Server.Port),
	})

	// Create and start server
	srv, err := server.NewServer(cfg, log)
	if err != nil {
		// H2: NewServer 返回错误而非调用 log.Fatal，允许通知和资源清理
		notifier.SendNotification("start_failed", map[string]string{
			"error": err.Error(),
		})
		notifier.Sync()
		log.Error("Failed to create server", logger.NewField("error", err))
		if cerr := log.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "Failed to close logger: %v\n", cerr)
		}
		os.Exit(1)
	}

	// 注入证书事件通知器给 Reconciler（内部PRD §7.5）：cert 包不反向依赖
	// notification 包，经 SetNotifier 以接口解耦；必须在 srv.Start() 之前完成，
	// Start 内部即会启动 Reconciler（cert_ready / cert_failed 通知依赖此注入）
	srv.GetCertManager().SetNotifier(notifier)

	// 注入网关生命周期事件通知器（内部PRD §7）：ready / waf_crs_degraded /
	// waf_crs_stale_start / waf_crs_recovered / waf_crs_refresh_failed 由 server 在
	// 全端口绑定后（notifyReady）与后台自愈循环中触发；必须在 srv.Start() 之前完成
	//（Start 阻塞直至 shutdown，ready 通知由 server 内部异步发送）
	srv.SetNotifier(notifier)

	// Load admin config from environment variables
	// M4（内部PRD §7.2）：LITE_ADMIN_ALLOWED_IPS 含非法条目时 fail-fast
	// 拒绝启动（放行畸形条目等于在管理面 ACL 上留洞）
	adminCfg, adminCfgErr := admin.LoadFromEnv()
	if adminCfgErr != nil {
		notifier.SendNotification("start_failed", map[string]string{
			"error": adminCfgErr.Error(),
		})
		notifier.Sync()
		log.Error("Failed to load admin config", logger.NewField("error", adminCfgErr))
		if cerr := log.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "Failed to close logger: %v\n", cerr)
		}
		os.Exit(1)
	}
	var adminSrv *admin.AdminServer
	if adminCfg != nil {
		adminSrv = admin.NewAdminServer(adminCfg, cfg, srv.GetCertManager(), log)
		// F13.2（内部PRD §4.13.2）：admin 锁定告警级联注入（创建后、Start 前生效）
		adminSrv.SetNotifier(notifier)
		adminSrv.SetGetBackendHealth(srv.GetBackendHealth)
		adminSrv.SetGetWAFStats(srv.GetWAFStats)
		adminSrv.SetGetWAFEvents(srv.GetWAFEvents)
		adminSrv.SetFindWAFEvent(srv.FindWAFEvent)
		adminSrv.SetGetBlacklistStats(srv.GetBlacklistStats)
		adminSrv.SetGetBlacklistEvents(srv.GetBlacklistEvents)
		// shipper 状态探针（内部PRD §6.1）：未启用时经 GetTrackerShipperStatus
		// 内部返回 DisabledStatusSnapshot，端点仍 200 + enabled:false
		adminSrv.SetGetShipperStatus(srv.GetTrackerShipperStatus)
		// CRS 状态探针（内部PRD §5.6）：/api/waf/stats 新增 crs_state /
		// crs_source / crs_cache_age_seconds / crs_last_error，从 crs 注册表读取
		adminSrv.SetGetCRSStatus(srv.GetCRSStatus)
		// F11（内部PRD §4.11.1）：degrade 观测透出
		adminSrv.SetGetDegradedWAFHosts(srv.GetDegradedWAFHosts)
		adminSrv.SetGetPendingRestartWAFHosts(srv.GetPendingRestartCRSSummary)
		// H5: 启动失败时将 adminSrv 置 nil，避免关闭时调用未启动的 server 的 Stop()
		if err := adminSrv.Start(); err != nil {
			log.Error("Failed to start admin server", logger.NewField("error", err))
			adminSrv = nil
		} else {
			log.Info("Admin server enabled", logger.NewField("admin_url", adminCfg.String()))
		}
	} else {
		// 面板拆除（内部PRD 迭代 4b）后启用条件仅剩 LITE_ADMIN_DOMAIN
		log.Info("Admin server disabled: LITE_ADMIN_DOMAIN not set")
	}

	// Setup graceful shutdown
	startErrChan := make(chan error, 1)
	gracefulDone := make(chan struct{})
	go func() {
		if err := srv.Start(); err != nil {
			startErrChan <- err
		}
	}()

	// Wait for either start error or interrupt signal
	// P2-40: 支持双击强制退出 — 第二次信号触发立即退出
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-startErrChan:
		// Send start_failed event
		notifier.SendNotification("start_failed", map[string]string{
			"error": err.Error(),
		})
		// C3: 等待通知发送完成后再关闭 logger
		notifier.Sync()
		log.Error("Server failed to start", logger.NewField("error", err))
		if cerr := log.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "Failed to close logger: %v\n", cerr)
		}
		os.Exit(1)
	case <-quit:
		// Send stopping event
		notifier.SendNotification("stopping", map[string]string{
			"signal": "SIGINT/SIGTERM",
		})

		log.Info("Shutting down server... (press Ctrl+C again to force exit)")

		// C2: 双击强制退出时仍尝试 flush logger
		// 启动后台 goroutine 监听第二次信号，实现双击强制退出
		go func() {
			<-quit
			log.Warn("Force exit signal received, exiting immediately")
			// H15: 给优雅关闭最多 3 秒完成证书文件写入，避免中断原子写入
			select {
			case <-time.After(3 * time.Second):
			case <-gracefulDone:
			}
			// C2: 强制退出前尝试 flush logger（best-effort，不等通知）
			_ = log.Close()
			os.Exit(1)
		}()

		if adminSrv != nil {
			adminSrv.Stop()
		}
		srv.Stop()
		log.Info("Server stopped")
		close(gracefulDone)
	}

	// Send stopped event
	notifier.SendNotification("stopped", nil)

	// C3: 等待 stopped 通知发送完成
	notifier.Sync()

	// Close logger
	if err := log.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to close logger: %v\n", err)
	}
}
