package proxy

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yourcompany/commercial-waf/internal/behavior"
	"github.com/yourcompany/commercial-waf/internal/config"
	"github.com/yourcompany/commercial-waf/internal/logging"
	"github.com/yourcompany/commercial-waf/internal/rules"
)

// DomainConfig 域名配置结构体
type DomainConfig struct {
	DomainName        string
	BackendURL        string
	Enabled           bool
	ProtectionPolicies []string
	BlockPageEnabled  bool   `json:"block_page_enabled"`
	BlockPageHTML     string `json:"block_page_html"`
}

// ReverseProxy WAF反向代理结构体
type ReverseProxy struct {
	configCenter     config.ConfigCenter
	rulesEngine      *rules.RuleEngine
	behaviorAnalyzer *behavior.Analyzer
	domainConfigs    map[string]*DomainConfig // 域名配置缓存
	domainMutex      sync.RWMutex
	pullInterval     time.Duration
}

// NewReverseProxy 创建新的反向代理实例
func NewReverseProxy(configCenter config.ConfigCenter, rulesEngine *rules.RuleEngine, behaviorAnalyzer *behavior.Analyzer) (*ReverseProxy, error) {
	proxy := &ReverseProxy{
		configCenter:     configCenter,
		rulesEngine:      rulesEngine,
		behaviorAnalyzer: behaviorAnalyzer,
		domainConfigs:    make(map[string]*DomainConfig),
		pullInterval:     30 * time.Second, // 默认30秒拉取一次配置
	}

	// 初始化时拉取一次配置
	if err := proxy.pullDomainConfigs(); err != nil {
		log.Printf("初始化拉取域名配置失败: %v", err)
	}

	// 启动定期拉取配置的协程
	go proxy.startConfigPuller()

	// 注册配置变更监听器
	proxy.configCenter.RegisterChangeListener(config.ConfigTypeDomain, proxy)
	proxy.configCenter.RegisterChangeListener(config.ConfigTypeOrigin, proxy)
	proxy.configCenter.RegisterChangeListener(config.ConfigTypeProtectionPolicy, proxy)

	return proxy, nil
}

// Handle 处理请求
func (p *ReverseProxy) Handle(w http.ResponseWriter, r *http.Request) {
	// 读取请求
	host := r.Host
	clientIP := p.getClientIP(r)

	// 动态匹配域名
	domainConfig, err := p.getDomainConfig(host)
	if err != nil {
		log.Printf("域名 %s 未配置: %v", host, err)
		
		// 记录访问日志
		logging.GetLogger().AccessLog(logging.AccessLogEntry{
			Timestamp:    time.Now(),
			TenantID:     "default", // 这里需要根据实际情况获取租户ID
			Domain:       host,
			ClientIP:     clientIP,
			Method:       r.Method,
			Path:         r.URL.Path,
			Query:        r.URL.RawQuery,
			Status:       http.StatusNotFound,
			ResponseSize: 0,
			Duration:     0,
			Error:        err.Error(),
		})
		
		http.Error(w, "域名未配置", http.StatusNotFound)
		return
	}

	if !domainConfig.Enabled {
		log.Printf("域名 %s 已禁用", host)
		
		// 记录访问日志
		logging.GetLogger().AccessLog(logging.AccessLogEntry{
			Timestamp:    time.Now(),
			TenantID:     "default", // 这里需要根据实际情况获取租户ID
			Domain:       host,
			ClientIP:     clientIP,
			Method:       r.Method,
			Path:         r.URL.Path,
			Query:        r.URL.RawQuery,
			Status:       http.StatusForbidden,
			ResponseSize: 0,
			Duration:     0,
			Error:        "域名已禁用",
		})
		
		// 使用拦截页面
		p.blockRequest(w, r, domainConfig)
		return
	}

	// 记录请求开始时间
	startTime := time.Now()

	// 安全检测
	if !p.securityCheck(r, domainConfig) {
		// 安全检测失败，访问日志已在securityCheck中记录
		p.blockRequest(w, r, domainConfig)
		return
	}

	// 行为分析
	if p.behaviorAnalyzer != nil {
		riskScore, exceeded := p.behaviorAnalyzer.AnalyzeIP(clientIP)
		if exceeded {
			log.Printf("行为分析告警: IP %s 请求频率超过阈值，风险分数: %d", clientIP, riskScore)
			
			// 记录攻击日志
			logging.GetLogger().AttackLog(logging.AttackLogEntry{
				Timestamp:      time.Now(),
				TenantID:       "default", // 这里需要根据实际情况获取租户ID
				Domain:         host,
				ClientIP:       clientIP,
				Method:         r.Method,
				Path:           r.URL.Path,
				Query:          r.URL.RawQuery,
				AttackType:     logging.AttackTypeBehavior,
				AttackName:     "请求频率异常",
				Description:    fmt.Sprintf("IP请求频率超过阈值，风险分数: %d", riskScore),
				MatchedRuleID:  "behavior-001",
				MatchedRuleName: "请求频率检测",
				RiskScore:      riskScore,
				Status:         logging.AttackStatusDetected,
			})
			// 可以根据风险分数决定是否拦截请求
			// 这里暂时不拦截，只记录日志
		}
	}

	// 转发请求
	statusCode, responseSize := p.forwardRequest(w, r, domainConfig)

	// 记录访问日志
	logging.GetLogger().AccessLog(logging.AccessLogEntry{
		Timestamp:    time.Now(),
		TenantID:     "default", // 这里需要根据实际情况获取租户ID
		Domain:       host,
		ClientIP:     clientIP,
		Method:       r.Method,
		Path:         r.URL.Path,
		Query:        r.URL.RawQuery,
		Status:       statusCode,
		ResponseSize: responseSize,
		Duration:     time.Since(startTime).Milliseconds(),
		Error:        "",
	})
}

// blockRequest 处理拦截请求并显示拦截页面
func (p *ReverseProxy) blockRequest(w http.ResponseWriter, r *http.Request, domainConfig *DomainConfig) {
	// 设置403状态码
	w.WriteHeader(http.StatusForbidden)
	
	// 设置内容类型为HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	// 默认拦截页面内容
	defaultBlockPage := `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>访问被拒绝</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            text-align: center;
            background-color: white;
            padding: 50px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #d9534f;
            font-size: 3em;
            margin-bottom: 20px;
        }
        p {
            color: #333;
            font-size: 1.2em;
            margin-bottom: 30px;
        }
        .brand {
            color: #337ab7;
            font-weight: bold;
            font-size: 1.5em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>403</h1>
        <p>您的请求已被 <span class="brand">bc-waf</span> 安全防护系统拦截</p>
    </div>
</body>
</html>
	`
	
	// 检查是否启用自定义拦截页面
	if domainConfig.BlockPageEnabled && domainConfig.BlockPageHTML != "" {
		// 使用自定义HTML内容
		w.Write([]byte(domainConfig.BlockPageHTML))
	} else {
		// 使用默认拦截页面
		w.Write([]byte(defaultBlockPage))
	}
}

// securityCheck 安全检测
func (p *ReverseProxy) securityCheck(r *http.Request, domainConfig *DomainConfig) bool {
	// 准备检查参数
	body := ""
	headers := make(map[string]string)

	// 转换请求头
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[strings.ToLower(key)] = values[0]
		}
	}

	// 检查请求
	matchedRules, totalScore := p.rulesEngine.CheckRequest(r.RequestURI, body, headers)
	if len(matchedRules) > 0 {
		log.Printf("安全检测失败: %s %s %s, 命中规则数: %d, 总风险分数: %d", r.Method, r.URL.Path, r.Host, len(matchedRules), totalScore)
  
		clientIP := p.getClientIP(r)
  
		// 记录攻击日志
		for _, rule := range matchedRules {
			logging.GetLogger().AttackLog(logging.AttackLogEntry{
				Timestamp:      time.Now(),
				TenantID:       "default", // 这里需要根据实际情况获取租户ID
				Domain:         r.Host,
				ClientIP:       clientIP,
				Method:         r.Method,
				Path:           r.URL.Path,
				Query:          r.URL.RawQuery,
				AttackType:     logging.AttackTypeSecurityRule,
				AttackName:     rule.Name,
				Description:    rule.Description,
				MatchedRuleID:  rule.ID,
				MatchedRuleName: rule.Name,
				RiskScore:      rule.RiskScore,
				Status:         logging.AttackStatusBlocked,
			})
		}
		
		// 记录访问日志
		logging.GetLogger().AccessLog(logging.AccessLogEntry{
			Timestamp:    time.Now(),
			TenantID:     "default", // 这里需要根据实际情况获取租户ID
			Domain:       r.Host,
			ClientIP:     clientIP,
			Method:       r.Method,
			Path:         r.URL.Path,
			Query:        r.URL.RawQuery,
			Status:       http.StatusForbidden,
			ResponseSize: 0,
			Duration:     0,
			Error:        fmt.Sprintf("安全规则拦截，命中规则数: %d, 总风险分数: %d", len(matchedRules), totalScore),
		})
		
		return false
	}

	return true
}

// ResponseWriterWithStatus 包装http.ResponseWriter以获取状态码
 type ResponseWriterWithStatus struct {
	 http.ResponseWriter
	 statusCode int
	 size       int
 }

 func (w *ResponseWriterWithStatus) WriteHeader(code int) {
	 w.statusCode = code
	 w.ResponseWriter.WriteHeader(code)
 }

 func (w *ResponseWriterWithStatus) Write(b []byte) (int, error) {
	 if w.statusCode == 0 {
		 w.statusCode = http.StatusOK
	 }
	 size, err := w.ResponseWriter.Write(b)
	 w.size += size
	 return size, err
 }

// forwardRequest 转发请求
func (p *ReverseProxy) forwardRequest(w http.ResponseWriter, r *http.Request, domainConfig *DomainConfig) (int, int) {
	// 解析后端URL
	backendURL, err := url.Parse(domainConfig.BackendURL)
	if err != nil {
		log.Printf("解析后端URL失败: %s %v", domainConfig.BackendURL, err)
		http.Error(w, "服务器内部错误", http.StatusInternalServerError)
		return http.StatusInternalServerError, 0
	}

	// 创建反向代理
	reverseProxy := httputil.NewSingleHostReverseProxy(backendURL)

	// 修改请求
	r.Host = backendURL.Host
	r.URL.Host = backendURL.Host
	r.URL.Scheme = backendURL.Scheme
	r.RequestURI = ""

	// 使用包装的ResponseWriter来获取状态码和响应大小
	wrapped := &ResponseWriterWithStatus{ResponseWriter: w}

	// 转发请求
	reverseProxy.ServeHTTP(wrapped, r)
	log.Printf("请求已转发: %s %s %s -> %s, 状态码: %d, 响应大小: %d", r.Method, r.URL.Path, r.Host, backendURL.Host, wrapped.statusCode, wrapped.size)
	
	return wrapped.statusCode, wrapped.size
}

// getClientIP 获取客户端IP
func (p *ReverseProxy) getClientIP(r *http.Request) string {
	// 检查X-Forwarded-For头
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// 检查X-Real-IP头
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// 返回RemoteAddr
	parts := strings.Split(r.RemoteAddr, ":")
	return parts[0]
}

// pullDomainConfigs 从配置中心拉取域名配置
func (p *ReverseProxy) pullDomainConfigs() error {
	log.Println("开始从配置中心拉取域名配置...")

	// 获取所有域名配置
	domainConfigs, err := p.configCenter.GetConfigsByType(config.ConfigTypeDomain)
	if err != nil {
		return fmt.Errorf("获取域名配置失败: %v", err)
	}

	newDomainConfigs := make(map[string]*DomainConfig)

	// 处理每个域名配置
	for _, domainConfig := range domainConfigs {
		if domainValue, ok := domainConfig.Value.(map[string]interface{}); ok {
			domainName, ok := domainValue["DomainName"].(string)
			if !ok {
				continue
			}

			backendURL, ok := domainValue["BackendURL"].(string)
			if !ok {
				continue
			}

			enabled, ok := domainValue["Enabled"].(bool)
			if !ok {
				enabled = true // 默认启用
			}

			// 获取拦截页面配置
			blockPageEnabled, ok := domainValue["BlockPageEnabled"].(bool)
			if !ok {
				blockPageEnabled = false // 默认不启用
			}

			blockPageHTML, ok := domainValue["BlockPageHTML"].(string)
			if !ok {
				blockPageHTML = "" // 默认空
			}

			// 创建域名配置
			newDomainConfigs[domainName] = &DomainConfig{
				DomainName:       domainName,
				BackendURL:       backendURL,
				Enabled:          enabled,
				BlockPageEnabled: blockPageEnabled,
				BlockPageHTML:    blockPageHTML,
			}

			log.Printf("加载域名配置: %s -> %s, 启用状态: %v, 拦截页面启用: %v", domainName, backendURL, enabled, blockPageEnabled)
		}
	}

	// 更新域名配置缓存
	p.domainMutex.Lock()
	p.domainConfigs = newDomainConfigs
	p.domainMutex.Unlock()

	log.Printf("成功拉取 %d 个域名配置", len(newDomainConfigs))
	return nil
}

// startConfigPuller 启动配置拉取器
func (p *ReverseProxy) startConfigPuller() {
	log.Printf("启动配置拉取器，间隔: %v", p.pullInterval)

	ticker := time.NewTicker(p.pullInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.pullDomainConfigs(); err != nil {
				log.Printf("定期拉取配置失败: %v", err)
			}
		}
	}
}

// getDomainConfig 获取域名配置
func (p *ReverseProxy) getDomainConfig(domainName string) (*DomainConfig, error) {
	// 移除端口号
	if idx := strings.Index(domainName, ":"); idx != -1 {
		domainName = domainName[:idx]
	}

	p.domainMutex.RLock()
	defer p.domainMutex.RUnlock()

	if config, exists := p.domainConfigs[domainName]; exists {
		return config, nil
	}

	return nil, fmt.Errorf("域名 %s 未配置", domainName)
}

// OnConfigChange 配置变更时触发
func (p *ReverseProxy) OnConfigChange(config *config.Config) {
	log.Printf("收到配置变更通知: %s %s", config.Type, config.Name)

	// 重新拉取配置
	if err := p.pullDomainConfigs(); err != nil {
		log.Printf("配置变更后拉取配置失败: %v", err)
	}
}