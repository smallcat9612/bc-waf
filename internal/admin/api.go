package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/yourcompany/commercial-waf/internal/config"
	"github.com/yourcompany/commercial-waf/internal/logging"
	"github.com/yourcompany/commercial-waf/internal/license"
)

// AdminAPI 管理控制台API处理程序
type AdminAPI struct {
	configCenter config.ConfigCenter
	licenseManager license.LicenseManager
}

// NewAdminAPI 创建管理控制台API
func NewAdminAPI(configCenter config.ConfigCenter, licenseManager license.LicenseManager) *AdminAPI {
	return &AdminAPI{
		configCenter: configCenter,
		licenseManager: licenseManager,
	}
}

// RegisterRoutes 注册路由
func (api *AdminAPI) RegisterRoutes(mux *http.ServeMux) {
	// 配置管理
	mux.HandleFunc("/api/configs", api.handleConfigs)
	mux.HandleFunc("/api/configs/", api.handleConfigByID)
	mux.HandleFunc("/api/configs/type/", api.handleConfigsByType)

	// 规则管理
	mux.HandleFunc("/api/rules", api.handleRules)
	mux.HandleFunc("/api/rules/", api.handleRuleByID)

	// 租户管理
	mux.HandleFunc("/api/tenants", api.handleTenants)
	mux.HandleFunc("/api/tenants/", api.handleTenantByID)

	// 域名管理
	mux.HandleFunc("/api/domains", api.handleDomains)
	mux.HandleFunc("/api/domains/", api.handleDomainByID)
	mux.HandleFunc("/api/domains/tenant/", api.handleDomainsByTenant)

	// 源站管理
	mux.HandleFunc("/api/origins", api.handleOrigins)
	mux.HandleFunc("/api/origins/", api.handleOriginByID)
	mux.HandleFunc("/api/origins/domain/", api.handleOriginsByDomain)

	// 证书管理
	mux.HandleFunc("/api/certificates", api.handleCertificates)
	mux.HandleFunc("/api/certificates/", api.handleCertificateByID)
	mux.HandleFunc("/api/certificates/domain/", api.handleCertificatesByDomain)

	// 防护策略管理
	mux.HandleFunc("/api/policies", api.handleProtectionPolicies)
	mux.HandleFunc("/api/policies/", api.handleProtectionPolicyByID)
	mux.HandleFunc("/api/policies/domain/", api.handleProtectionPoliciesByDomain)

	// 许可证管理
	mux.HandleFunc("/api/license", api.handleLicense)
	mux.HandleFunc("/api/license/validate", api.handleLicenseValidate)

	// 系统设置管理
	mux.HandleFunc("/api/system-settings", api.handleSystemSettings)

	// 实时配置查询（供WAF节点使用）
	mux.HandleFunc("/api/domain-config/", api.handleDomainConfigByDomainName)
	mux.HandleFunc("/api/domain-origins/", api.handleDomainOriginsByDomainName)
	mux.HandleFunc("/api/domain-certificates/", api.handleDomainCertificatesByDomainName)
	mux.HandleFunc("/api/domain-policies/", api.handleDomainPoliciesByDomainName)

	// 系统信息
	mux.HandleFunc("/api/system", api.handleSystemInfo)
}

// handleConfigs 处理配置列表请求
func (api *AdminAPI) handleConfigs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// 获取所有配置
		api.handleGetAllConfigs(w, r)
	case http.MethodPost:
		// 创建新配置
		api.handleCreateConfig(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetAllConfigs 获取所有配置
func (api *AdminAPI) handleGetAllConfigs(w http.ResponseWriter, r *http.Request) {
	// 调用配置中心获取所有配置
	// 由于ConfigCenter接口没有GetAllConfigs方法，我们需要逐个类型获取
	var allConfigs []*config.Config
	
	// 定义所有配置类型
	configTypes := []config.ConfigType{
		config.ConfigTypeServer,
		config.ConfigTypeAdmin,
		config.ConfigTypeRules,
		config.ConfigTypeAI,
		config.ConfigTypeLogging,
		config.ConfigTypeMetrics,
		config.ConfigTypeStorage,
		config.ConfigTypeTenant,
		config.ConfigTypeDomain,
		config.ConfigTypeOrigin,
		config.ConfigTypeCertificate,
		config.ConfigTypeProtectionPolicy,
	}
	
	// 遍历所有配置类型，获取配置
	for _, configType := range configTypes {
		configs, err := api.configCenter.GetConfigsByType(configType)
		if err != nil {
			// 忽略获取单个类型配置的错误，继续获取其他类型
			continue
		}
		allConfigs = append(allConfigs, configs...)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(allConfigs)
}

// handleCreateConfig 创建新配置
func (api *AdminAPI) handleCreateConfig(w http.ResponseWriter, r *http.Request) {
	var configData config.Config
	err := json.NewDecoder(r.Body).Decode(&configData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 设置创建时间和更新时间
	now := time.Now()
	configData.CreatedAt = now
	configData.UpdatedAt = now
	configData.Enabled = true

	// 保存配置
	err = api.configCenter.SetConfig(&configData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 记录审计日志
	logging.GetLogger().AuditLog(logging.AuditLogEntry{
		Timestamp:     time.Now(),
		TenantID:      "default", // 这里需要根据实际情况获取租户ID
		UserID:        "admin",   // 这里需要根据实际情况获取用户ID
		UserName:      "管理员",   // 这里需要根据实际情况获取用户名
		Operation:     logging.AuditOperationCreate,
		ResourceType:  logging.AuditResourceTypeConfig,
		ResourceID:    configData.ID,
		ResourceName:  configData.Name,
		Details:       "创建了新配置",
		Status:        logging.AuditStatusSuccess,
		ClientIP:      r.RemoteAddr,
		HTTPMethod:    r.Method,
		URL:           r.URL.Path,
	})

	// 返回创建的配置
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(configData)
}

// handleConfigByID 处理单个配置请求
func (api *AdminAPI) handleConfigByID(w http.ResponseWriter, r *http.Request) {
	// 解析配置ID
	id := r.URL.Path[len("/api/configs/"):]

	switch r.Method {
	case http.MethodGet:
		// 获取单个配置
		api.handleGetConfig(w, r, id)
	case http.MethodPut:
		// 更新配置
		api.handleUpdateConfig(w, r, id)
	case http.MethodDelete:
		// 删除配置
		api.handleDeleteConfig(w, r, id)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetConfig 获取单个配置
func (api *AdminAPI) handleGetConfig(w http.ResponseWriter, r *http.Request, id string) {
	// 由于ConfigCenter.GetConfig需要配置类型和名称，我们需要先获取所有配置并查找
	var targetConfig *config.Config
	configTypes := []config.ConfigType{
		config.ConfigTypeServer,
		config.ConfigTypeAdmin,
		config.ConfigTypeRules,
		config.ConfigTypeAI,
		config.ConfigTypeLogging,
		config.ConfigTypeMetrics,
		config.ConfigTypeStorage,
		config.ConfigTypeTenant,
		config.ConfigTypeDomain,
		config.ConfigTypeOrigin,
		config.ConfigTypeCertificate,
		config.ConfigTypeProtectionPolicy,
	}
	
	for _, configType := range configTypes {
		configs, err := api.configCenter.GetConfigsByType(configType)
		if err != nil {
			continue
		}
		for _, cfg := range configs {
			if cfg.ID == id {
				targetConfig = cfg
				break
			}
		}
		if targetConfig != nil {
			break
		}
	}

	if targetConfig == nil {
		http.Error(w, "配置不存在", http.StatusNotFound)
		return
	}

	// 返回配置
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(targetConfig)
}

// handleUpdateConfig 更新配置
func (api *AdminAPI) handleUpdateConfig(w http.ResponseWriter, r *http.Request, id string) {
	var configData config.Config
	err := json.NewDecoder(r.Body).Decode(&configData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 设置配置ID和更新时间
	configData.ID = id
	configData.UpdatedAt = time.Now()

	// 更新配置
	err = api.configCenter.UpdateConfig(&configData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 记录审计日志
	logging.GetLogger().AuditLog(logging.AuditLogEntry{
		Timestamp:     time.Now(),
		TenantID:      "default", // 这里需要根据实际情况获取租户ID
		UserID:        "admin",   // 这里需要根据实际情况获取用户ID
		UserName:      "管理员",   // 这里需要根据实际情况获取用户名
		Operation:     logging.AuditOperationUpdate,
		ResourceType:  logging.AuditResourceTypeConfig,
		ResourceID:    configData.ID,
		ResourceName:  configData.Name,
		Details:       "更新了配置",
		Status:        logging.AuditStatusSuccess,
		ClientIP:      r.RemoteAddr,
		HTTPMethod:    r.Method,
		URL:           r.URL.Path,
	})

	// 返回更新后的配置
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(configData)
}

// handleDeleteConfig 删除配置
func (api *AdminAPI) handleDeleteConfig(w http.ResponseWriter, r *http.Request, id string) {
	// 由于ConfigCenter.DeleteConfig需要配置类型和名称，我们需要先获取配置信息
	var targetConfig *config.Config
	var targetType config.ConfigType
	configTypes := []config.ConfigType{
		config.ConfigTypeServer,
		config.ConfigTypeAdmin,
		config.ConfigTypeRules,
		config.ConfigTypeAI,
		config.ConfigTypeLogging,
		config.ConfigTypeMetrics,
		config.ConfigTypeStorage,
		config.ConfigTypeTenant,
		config.ConfigTypeDomain,
		config.ConfigTypeOrigin,
		config.ConfigTypeCertificate,
		config.ConfigTypeProtectionPolicy,
	}
	
	for _, configType := range configTypes {
		configs, err := api.configCenter.GetConfigsByType(configType)
		if err != nil {
			continue
		}
		for _, cfg := range configs {
			if cfg.ID == id {
				targetConfig = cfg
				targetType = configType
				break
			}
		}
		if targetConfig != nil {
			break
		}
	}

	if targetConfig == nil {
		http.Error(w, "配置不存在", http.StatusNotFound)
		return
	}

	// 保存要删除的配置信息用于日志
	configName := targetConfig.Name

	// 删除配置
	err := api.configCenter.DeleteConfig(targetType, targetConfig.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 记录审计日志
	logging.GetLogger().AuditLog(logging.AuditLogEntry{
		Timestamp:     time.Now(),
		TenantID:      "default", // 这里需要根据实际情况获取租户ID
		UserID:        "admin",   // 这里需要根据实际情况获取用户ID
		UserName:      "管理员",   // 这里需要根据实际情况获取用户名
		Operation:     logging.AuditOperationDelete,
		ResourceType:  logging.AuditResourceTypeConfig,
		ResourceID:    id,
		ResourceName:  configName,
		Details:       "删除了配置",
		Status:        logging.AuditStatusSuccess,
		ClientIP:      r.RemoteAddr,
		HTTPMethod:    r.Method,
		URL:           r.URL.Path,
	})

	// 返回成功消息
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "配置删除成功",
		"id":      id,
	})
}

// handleConfigsByType 按类型获取配置
func (api *AdminAPI) handleConfigsByType(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析配置类型
	configType := config.ConfigType(r.URL.Path[len("/api/configs/type/"):])

	// 获取指定类型的配置
	configs, err := api.configCenter.GetConfigsByType(configType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 返回配置列表
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(configs)
}

// handleRules 处理规则列表请求
func (api *AdminAPI) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// 获取所有规则
		rules, err := api.configCenter.GetConfigsByType(config.ConfigTypeRules)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 返回规则列表
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(rules)
	case http.MethodPost:
		// 创建新规则
		var ruleData config.Config
		err := json.NewDecoder(r.Body).Decode(&ruleData)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// 设置创建时间和更新时间
		now := time.Now()
		ruleData.CreatedAt = now
		ruleData.UpdatedAt = now
		ruleData.Enabled = true
		ruleData.Type = config.ConfigTypeRules

		// 保存规则
		err = api.configCenter.SetConfig(&ruleData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 返回创建的规则
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ruleData)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRuleByID 处理单个规则请求
func (api *AdminAPI) handleRuleByID(w http.ResponseWriter, r *http.Request) {
	// 解析规则ID
	id := r.URL.Path[len("/api/rules/"):]

	switch r.Method {
	case http.MethodGet:
		// 获取单个规则 - 先获取所有规则再查找
		var targetRule *config.Config
		rules, err := api.configCenter.GetConfigsByType(config.ConfigTypeRules)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, rule := range rules {
			if rule.ID == id {
				targetRule = rule
				break
			}
		}

		if targetRule == nil {
			http.Error(w, "规则不存在", http.StatusNotFound)
			return
		}

		// 返回规则
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(targetRule)
	case http.MethodPut:
		// 更新规则
		var ruleData config.Config
		err := json.NewDecoder(r.Body).Decode(&ruleData)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// 设置规则ID和更新时间
		ruleData.ID = id
		ruleData.UpdatedAt = time.Now()
		ruleData.Type = config.ConfigTypeRules

		// 更新规则
		err = api.configCenter.UpdateConfig(&ruleData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 返回更新后的规则
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ruleData)
	case http.MethodDelete:
		// 删除规则 - 先获取规则信息
		var targetRule *config.Config
		rules, err := api.configCenter.GetConfigsByType(config.ConfigTypeRules)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, rule := range rules {
			if rule.ID == id {
				targetRule = rule
				break
			}
		}

		if targetRule == nil {
			http.Error(w, "规则不存在", http.StatusNotFound)
			return
		}

		// 删除规则
		err = api.configCenter.DeleteConfig(config.ConfigTypeRules, targetRule.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 返回成功消息
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "规则删除成功",
			"id":      id,
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}



// handleSystemInfo 处理系统信息请求
func (api *AdminAPI) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取系统信息
	systemInfo := map[string]interface{}{
		"version":    "1.0.0",
		"status":     "running",
		"time":       time.Now(),
		"uptime":     "未知",
		"go_version": "go1.20",
		"host":       "localhost",
		"port":       8080,
		"build_time": time.Now().Format("2006-01-02 15:04:05"),
	}

	// 返回系统信息
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(systemInfo)
}

// SystemSettings 系统设置结构
type SystemSettings struct {
	AISwitch        bool   `json:"ai_switch"`        // AI开关
	DefaultMode     string `json:"default_mode"`     // 默认防护模式 ("monitoring" 或 "protection")
	LogRetentionDays int    `json:"log_retention_days"` // 日志保留天数
}

// handleSystemSettings 处理系统设置请求
func (api *AdminAPI) handleSystemSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 检查是否为管理员（实际项目中应根据认证信息判断）
	// 这里简化处理，假设已通过认证中间件验证为管理员

	switch r.Method {
	case http.MethodGet:
		// 获取系统设置
		configs, err := api.configCenter.GetConfigsByType(config.ConfigTypeSystem)
		if err != nil {
			http.Error(w, "Failed to get system settings", http.StatusInternalServerError)
			return
		}

		// 默认设置
		settings := SystemSettings{
			AISwitch:        true,
			DefaultMode:     "monitoring",
			LogRetentionDays: 30,
		}

		// 从配置中加载设置
		for _, cfg := range configs {
			switch cfg.Name {
			case "ai_switch":
				if val, ok := cfg.Value.(bool); ok {
					settings.AISwitch = val
				}
			case "default_mode":
				if val, ok := cfg.Value.(string); ok {
					settings.DefaultMode = val
				}
			case "log_retention_days":
				// 同时支持int和float64类型
				switch val := cfg.Value.(type) {
				case int:
					settings.LogRetentionDays = val
				case float64:
					settings.LogRetentionDays = int(val)
				}
			}
		}

		// 返回系统设置
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(settings)

	case http.MethodPost, http.MethodPut:
		// 更新系统设置
		var settings SystemSettings
		if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// 验证默认防护模式
		if settings.DefaultMode != "monitoring" && settings.DefaultMode != "protection" {
			http.Error(w, "Invalid default mode", http.StatusBadRequest)
			return
		}

		// 验证日志保留天数
		if settings.LogRetentionDays < 1 || settings.LogRetentionDays > 365 {
			http.Error(w, "Log retention days must be between 1 and 365", http.StatusBadRequest)
			return
		}

		// 更新AI开关设置
		aiSwitchConfig := &config.Config{
			Type:        config.ConfigTypeSystem,
			Name:        "ai_switch",
			Value:       settings.AISwitch,
			Description: "AI防护开关",
			UpdatedAt:   time.Now(),
			UpdatedBy:   "admin", // 实际应从认证信息中获取
			Enabled:     true,
		}

		// 更新默认防护模式设置
		defaultModeConfig := &config.Config{
			Type:        config.ConfigTypeSystem,
			Name:        "default_mode",
			Value:       settings.DefaultMode,
			Description: "默认防护模式",
			UpdatedAt:   time.Now(),
			UpdatedBy:   "admin", // 实际应从认证信息中获取
			Enabled:     true,
		}

		// 更新日志保留天数设置
		logRetentionConfig := &config.Config{
			Type:        config.ConfigTypeSystem,
			Name:        "log_retention_days",
			Value:       settings.LogRetentionDays,
			Description: "日志保留天数",
			UpdatedAt:   time.Now(),
			UpdatedBy:   "admin", // 实际应从认证信息中获取
			Enabled:     true,
		}

		// 保存设置
		if err := api.configCenter.SetConfig(aiSwitchConfig); err != nil {
			http.Error(w, "Failed to update AI switch", http.StatusInternalServerError)
			return
		}

		if err := api.configCenter.SetConfig(defaultModeConfig); err != nil {
			http.Error(w, "Failed to update default mode", http.StatusInternalServerError)
			return
		}

		if err := api.configCenter.SetConfig(logRetentionConfig); err != nil {
			http.Error(w, "Failed to update log retention days", http.StatusInternalServerError)
			return
		}

		// 返回成功消息
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "System settings updated successfully"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLicense 处理许可证管理
func (api *AdminAPI) handleLicense(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// 获取许可证信息
		license, err := api.licenseManager.GetLicense()
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(license)

	case http.MethodPost:
		// 上传新许可证
		var license license.License
		if err := json.NewDecoder(r.Body).Decode(&license); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid license format"})
			return
		}

		// 保存许可证到文件（实际项目中应该使用配置的路径）
		if err := api.licenseManager.SaveLicense("./license.json"); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to save license"})
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"message": "License uploaded successfully"})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleLicenseValidate 处理许可证验证
func (api *AdminAPI) handleLicenseValidate(w http.ResponseWriter, r *http.Request) {
	// 仅允许GET请求
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// 验证许可证
	status, err := api.licenseManager.ValidateLicense()

	// 返回验证结果
	result := map[string]interface{}{
		"status": status,
		"valid":  status == license.LicenseStatusValid,
	}

	if err != nil {
		result["error"] = err.Error()
	}

	if err := json.NewEncoder(w).Encode(result); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// ---------------------------
// 租户管理API
// ---------------------------

// handleTenants 处理租户列表请求
func (api *AdminAPI) handleTenants(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// 获取所有租户
		api.handleGetAllTenants(w, r)
	case http.MethodPost:
		// 创建新租户
		api.handleCreateTenant(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetAllTenants 获取所有租户
func (api *AdminAPI) handleGetAllTenants(w http.ResponseWriter, r *http.Request) {
	configs, err := api.configCenter.GetConfigsByType(config.ConfigTypeTenant)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(configs)
}

// handleCreateTenant 创建新租户
func (api *AdminAPI) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var tenantConfig config.Config
	err := json.NewDecoder(r.Body).Decode(&tenantConfig)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 设置配置类型和时间
	tenantConfig.Type = config.ConfigTypeTenant
	now := time.Now()
	tenantConfig.CreatedAt = now
	tenantConfig.UpdatedAt = now
	tenantConfig.Enabled = true

	// 保存配置
	err = api.configCenter.CreateTenant(&tenantConfig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(tenantConfig)
}

// handleTenantByID 处理单个租户请求
func (api *AdminAPI) handleTenantByID(w http.ResponseWriter, r *http.Request) {
	// 解析租户ID
	id := r.URL.Path[len("/api/tenants/"):]

	switch r.Method {
	case http.MethodGet:
		// 获取单个租户
		tenant, err := api.configCenter.GetTenant(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(tenant)
	case http.MethodPut:
		// 更新租户
		var tenantConfig config.Config
		err := json.NewDecoder(r.Body).Decode(&tenantConfig)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		tenantConfig.ID = id
		tenantConfig.Type = config.ConfigTypeTenant
		tenantConfig.UpdatedAt = time.Now()
		err = api.configCenter.UpdateTenant(&tenantConfig)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(tenantConfig)
	case http.MethodDelete:
		// 删除租户
		err := api.configCenter.DeleteTenant(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Tenant deleted successfully"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---------------------------
// 域名管理API
// ---------------------------

// handleDomains 处理域名列表请求
func (api *AdminAPI) handleDomains(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// 获取所有域名配置
		configs, err := api.configCenter.GetConfigsByType(config.ConfigTypeDomain)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(configs)

	case http.MethodPost:
		// 创建新域名
		var domainConfig config.Config
		err := json.NewDecoder(r.Body).Decode(&domainConfig)
		if err != nil {
			http.Error(w, "无效的请求数据", http.StatusBadRequest)
			return
		}

		// 设置配置类型和基本信息
		domainConfig.Type = config.ConfigTypeDomain
		domainConfig.Enabled = true

		// 创建域名配置
		err = api.configCenter.CreateDomain(&domainConfig)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "域名创建成功",
			"domain":  domainConfig,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDomainByID 处理单个域名请求
func (api *AdminAPI) handleDomainByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 从URL中获取域名ID
	id := r.URL.Path[len("/api/domains/"):]
	if id == "" {
		http.Error(w, "域名ID不能为空", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// 获取单个域名
		domain, err := api.configCenter.GetDomain(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(domain)

	case http.MethodPut:
		// 更新域名
		var domainConfig config.Config
		if err := json.NewDecoder(r.Body).Decode(&domainConfig); err != nil {
			http.Error(w, "无效的请求数据", http.StatusBadRequest)
			return
		}

		// 确保ID匹配
		domainConfig.Type = config.ConfigTypeDomain
		domainConfig.Name = id // Name字段用于存储域名ID

		// 更新域名
		err := api.configCenter.UpdateDomain(&domainConfig)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "域名更新成功",
			"domain":  domainConfig,
		})

	case http.MethodDelete:
		// 删除域名
		err := api.configCenter.DeleteDomain(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "域名删除成功",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDomainsByTenant 按租户获取域名
func (api *AdminAPI) handleDomainsByTenant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析租户ID
	tenantID := r.URL.Path[len("/api/domains/tenant/"):]

	// 获取租户下的所有域名
	domains, err := api.configCenter.GetDomainsByTenant(tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(domains)
}

// ---------------------------
// 源站管理API
// ---------------------------

// handleOrigins 处理源站列表请求
func (api *AdminAPI) handleOrigins(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// 获取所有源站
		configs, err := api.configCenter.GetConfigsByType(config.ConfigTypeOrigin)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(configs)
	case http.MethodPost:
		// 创建新源站
		var originConfig config.Config
		err := json.NewDecoder(r.Body).Decode(&originConfig)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// 设置配置类型和时间
		originConfig.Type = config.ConfigTypeOrigin
		now := time.Now()
		originConfig.CreatedAt = now
		originConfig.UpdatedAt = now
		originConfig.Enabled = true

		// 保存配置
		err = api.configCenter.CreateOrigin(&originConfig)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(originConfig)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleOriginByID 处理单个源站请求
func (api *AdminAPI) handleOriginByID(w http.ResponseWriter, r *http.Request) {
	// 解析源站ID
	id := r.URL.Path[len("/api/origins/"):]

	switch r.Method {
	case http.MethodGet:
		// 获取单个源站
		origin, err := api.configCenter.GetOrigin(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(origin)
	case http.MethodPut:
		// 更新源站
		var originConfig config.Config
		err := json.NewDecoder(r.Body).Decode(&originConfig)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		originConfig.ID = id
		originConfig.Type = config.ConfigTypeOrigin
		originConfig.UpdatedAt = time.Now()
		err = api.configCenter.UpdateOrigin(&originConfig)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(originConfig)
	case http.MethodDelete:
		// 删除源站
		err := api.configCenter.DeleteOrigin(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Origin deleted successfully"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleOriginsByDomain 按域名获取源站
func (api *AdminAPI) handleOriginsByDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析域名ID
	domainID := r.URL.Path[len("/api/origins/domain/"):]

	// 获取域名下的所有源站
	origins, err := api.configCenter.GetOriginsByDomain(domainID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(origins)
}

// ---------------------------
// 证书管理API
// ---------------------------

// handleCertificates 处理证书列表请求
func (api *AdminAPI) handleCertificates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// 获取所有证书配置
		configs, err := api.configCenter.GetConfigsByType(config.ConfigTypeCertificate)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(configs)

	case http.MethodPost:
		// 创建新证书
		var certConfig config.Config
		err := json.NewDecoder(r.Body).Decode(&certConfig)
		if err != nil {
			http.Error(w, "无效的请求数据", http.StatusBadRequest)
			return
		}

		// 设置配置类型和基本信息
		certConfig.Type = config.ConfigTypeCertificate
		certConfig.Enabled = true

		// 创建证书配置
		err = api.configCenter.CreateCertificate(&certConfig)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "证书创建成功",
			"certificate":  certConfig,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleCertificateByID 处理单个证书请求
func (api *AdminAPI) handleCertificateByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 从URL中获取证书ID
	id := r.URL.Path[len("/api/certificates/"):]
	if id == "" {
		http.Error(w, "证书ID不能为空", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// 获取单个证书
		cert, err := api.configCenter.GetCertificate(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(cert)

	case http.MethodPut:
		// 更新证书
		var certConfig config.Config
		err := json.NewDecoder(r.Body).Decode(&certConfig)
		if err != nil {
			http.Error(w, "无效的请求数据", http.StatusBadRequest)
			return
		}

		// 确保ID匹配
		certConfig.Type = config.ConfigTypeCertificate
		certConfig.Name = id // Name字段用于存储证书ID

		// 更新证书配置
		err = api.configCenter.UpdateCertificate(&certConfig)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "证书更新成功",
			"certificate":  certConfig,
		})

	case http.MethodDelete:
		// 删除证书
		err := api.configCenter.DeleteCertificate(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "证书删除成功",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleCertificatesByDomain 按域名获取证书
func (api *AdminAPI) handleCertificatesByDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析域名ID
	domainID := r.URL.Path[len("/api/certificates/domain/"):]

	// 获取域名下的所有证书
	certs, err := api.configCenter.GetCertificatesByDomain(domainID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(certs)
}

// ---------------------------
// 防护策略管理API
// ---------------------------

// handleProtectionPolicies 处理防护策略列表请求
func (api *AdminAPI) handleProtectionPolicies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// 获取所有防护策略配置
		configs, err := api.configCenter.GetConfigsByType(config.ConfigTypeProtectionPolicy)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(configs)

	case http.MethodPost:
		// 创建新防护策略
		var policyConfig config.Config
		err := json.NewDecoder(r.Body).Decode(&policyConfig)
		if err != nil {
			http.Error(w, "无效的请求数据", http.StatusBadRequest)
			return
		}

		// 设置配置类型和基本信息
		policyConfig.Type = config.ConfigTypeProtectionPolicy
		policyConfig.Enabled = true

		// 创建防护策略配置
		err = api.configCenter.CreateProtectionPolicy(&policyConfig)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "防护策略创建成功",
			"policy":  policyConfig,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleProtectionPolicyByID 处理单个防护策略请求
func (api *AdminAPI) handleProtectionPolicyByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 从URL中获取防护策略ID
	id := r.URL.Path[len("/api/protection_policies/"):]
	if id == "" {
		http.Error(w, "防护策略ID不能为空", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// 获取单个防护策略
		policy, err := api.configCenter.GetProtectionPolicy(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(policy)

	case http.MethodPut:
		// 更新防护策略
		var policyConfig config.Config
		err := json.NewDecoder(r.Body).Decode(&policyConfig)
		if err != nil {
			http.Error(w, "无效的请求数据", http.StatusBadRequest)
			return
		}

		// 确保ID匹配
		policyConfig.Type = config.ConfigTypeProtectionPolicy
		policyConfig.Name = id // Name字段用于存储防护策略ID

		// 更新防护策略配置
		err = api.configCenter.UpdateProtectionPolicy(&policyConfig)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "防护策略更新成功",
			"policy":  policyConfig,
		})

	case http.MethodDelete:
		// 删除防护策略
		err := api.configCenter.DeleteProtectionPolicy(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "防护策略删除成功",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleProtectionPoliciesByDomain 按域名获取防护策略
func (api *AdminAPI) handleProtectionPoliciesByDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析域名ID
	domainID := r.URL.Path[len("/api/policies/domain/"):]

	// 获取域名下的所有防护策略
	policies, err := api.configCenter.GetProtectionPoliciesByDomain(domainID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(policies)
}

// ---------------------------
// 实时配置查询API（供WAF节点使用）
// ---------------------------

// handleDomainConfigByDomainName 按域名名称获取完整配置
func (api *AdminAPI) handleDomainConfigByDomainName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析域名名称
	domainName := r.URL.Path[len("/api/domain-config/"):]

	// 获取域名的完整配置
	domainConfig, err := api.configCenter.GetDomainConfig(domainName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(domainConfig)
}

// handleDomainOriginsByDomainName 按域名名称获取源站配置
func (api *AdminAPI) handleDomainOriginsByDomainName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析域名名称
	domainName := r.URL.Path[len("/api/domain-origins/"):]

	// 获取域名的源站配置
	origins, err := api.configCenter.GetDomainOrigins(domainName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(origins)
}

// handleDomainCertificatesByDomainName 按域名名称获取证书配置
func (api *AdminAPI) handleDomainCertificatesByDomainName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析域名名称
	domainName := r.URL.Path[len("/api/domain-certificates/"):]

	// 获取域名的证书配置
	certs, err := api.configCenter.GetDomainCertificates(domainName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(certs)
}

// handleDomainPoliciesByDomainName 按域名名称获取防护策略配置
func (api *AdminAPI) handleDomainPoliciesByDomainName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析域名名称
	domainName := r.URL.Path[len("/api/domain-policies/"):]

	// 获取域名的防护策略配置
	policies, err := api.configCenter.GetDomainProtectionPolicies(domainName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(policies)
}