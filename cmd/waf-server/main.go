package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/yourcompany/commercial-waf/internal/admin"
	"github.com/yourcompany/commercial-waf/internal/api"
	"github.com/yourcompany/commercial-waf/internal/behavior"
	"github.com/yourcompany/commercial-waf/internal/config"
	"github.com/yourcompany/commercial-waf/internal/license"
	"github.com/yourcompany/commercial-waf/internal/logging"
	"github.com/yourcompany/commercial-waf/internal/proxy"
	"github.com/yourcompany/commercial-waf/internal/rules"
	middleware "github.com/yourcompany/commercial-waf/internal/middleware"
)

func main() {
	// 创建配置中心
	configCenter := config.NewMemoryConfigCenter()

	// 初始化日志系统
	logSystem := logging.NewMemoryLogger(10000) // 创建一个可以存储10000条日志的内存日志系统
	logging.InitLogger(logSystem)
	log.Println("日志系统初始化成功")

	// 创建系统设置管理器
	systemSettingsManager := config.NewSystemSettingsManager(configCenter)

	// 初始化规则引擎
	ruleEngine := rules.NewRuleEngine()

	// 为规则引擎注册配置监听器
	ruleConfigListener := rules.NewRuleConfigListener(ruleEngine)
	configCenter.RegisterChangeListener(config.ConfigTypeRules, ruleConfigListener)

	// 定期检查系统设置变更并更新日志保留天数
	go func() {
		for {
			time.Sleep(time.Minute) // 每分钟检查一次
			settings := systemSettingsManager.GetSettings()
			logSystem.SetLogRetentionDays(settings.LogRetentionDays)
		}
	}()

	log.Println("系统设置管理器初始化成功")

	// 创建行为分析器
	behaviorConfig := behavior.Config{
		TimeWindow:  60 * time.Second, // 60秒时间窗口
		MaxRequests: 100,              // 每分钟最多100个请求
		RiskScore:   50,               // 超过阈值增加50分风险分
	}
	behaviorAnalyzer := behavior.NewAnalyzer(behaviorConfig)
	behaviorAnalyzer.StartCleanupJob(5 * time.Minute)



	// 创建反向代理处理器
	proxyHandler, err := proxy.NewReverseProxy(configCenter, ruleEngine, behaviorAnalyzer)
	if err != nil {
		log.Fatalf("无法创建反向代理: %v", err)
	}

	// 创建许可证管理器
	licenseManager := license.NewMemoryLicenseManager()

	// 尝试加载许可证文件
	licensePath := "./license.json"
	if _, err := os.Stat(licensePath); err == nil {
		if err := licenseManager.LoadLicense(licensePath); err != nil {
			log.Printf("许可证加载失败: %v", err)
			log.Println("系统将在未授权模式下运行，部分功能可能不可用")
		} else {
			// 验证许可证
			status, err := licenseManager.ValidateLicense()
			if err != nil || status != license.LicenseStatusValid {
				log.Printf("许可证验证失败: %v", err)
				log.Println("系统将在未授权模式下运行，部分功能可能不可用")
			} else {
				log.Println("许可证验证成功，系统已授权")
			}
		}
	} else {
		log.Println("未找到许可证文件，系统将在未授权模式下运行，部分功能可能不可用")
	}

	// 创建管理控制台API
	adminAPI := admin.NewAdminAPI(configCenter, licenseManager)

	// 创建用户自助控制台API
	userConsoleAPI := api.NewUserConsoleAPI(configCenter)

	// 创建主路由
	mux := http.NewServeMux()

	// 注册管理控制台API路由
	adminAPI.RegisterRoutes(mux)

	// 注册用户自助控制台API路由
	userConsoleAPI.RegisterRoutes(mux)

	// 注册反向代理
	mux.HandleFunc("/", proxyHandler.Handle)

	// 注册静态文件服务（管理控制台页面）
	adminFilePath := "h:/waf/internal/admin/console.html"
	if _, err := os.Stat(adminFilePath); err == nil {
		mux.HandleFunc("/console", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, adminFilePath)
		})
	} else {
		log.Printf("管理控制台页面未找到: %v", err)
	}

	// 创建HTTP服务器
	server := &http.Server{
		Addr:    ":8080",
		Handler: middleware.LicenseMiddleware(licenseManager)(mux),
	}

	fmt.Println("WAF服务器已启动，监听端口 8080")
	fmt.Println("支持多域名动态防护，后端地址从配置中心获取")
	fmt.Println("管理控制台地址: http://localhost:8080/console")
	fmt.Println("API接口地址: http://localhost:8080/api")

	// 启动服务器
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("WAF服务器启动失败: %v", err)
	}
}