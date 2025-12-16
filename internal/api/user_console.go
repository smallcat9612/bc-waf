package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/yourcompany/commercial-waf/internal/config"
	"github.com/yourcompany/commercial-waf/internal/middleware"
	"github.com/yourcompany/commercial-waf/internal/models"
)

// UserConsoleAPI 用户自助控制台API
type UserConsoleAPI struct {
	configCenter config.ConfigCenter
}

// NewUserConsoleAPI 创建用户自助控制台API实例
func NewUserConsoleAPI(configCenter config.ConfigCenter) *UserConsoleAPI {
	return &UserConsoleAPI{
		configCenter: configCenter,
	}
}

// RegisterRoutes 注册用户自助控制台路由
func (api *UserConsoleAPI) RegisterRoutes(mux *http.ServeMux) {
	// 用户认证相关路由
	mux.HandleFunc("/api/user/register", middleware.CorsMiddleware(api.handleUserRegister))
	mux.HandleFunc("/api/user/login", middleware.CorsMiddleware(api.handleUserLogin))

	// 受保护的资源路由
	mux.HandleFunc("/api/user/domains", middleware.CorsMiddleware(middleware.AuthMiddleware(api.handleUserDomains)))
	mux.HandleFunc("/api/user/domains/", middleware.CorsMiddleware(middleware.AuthMiddleware(api.handleUserDomainByID)))
	mux.HandleFunc("/api/user/origins", middleware.CorsMiddleware(middleware.AuthMiddleware(api.handleUserOrigins)))
	mux.HandleFunc("/api/user/origins/", middleware.CorsMiddleware(middleware.AuthMiddleware(api.handleUserOriginByID)))
	mux.HandleFunc("/api/user/certificates", middleware.CorsMiddleware(middleware.AuthMiddleware(api.handleUserCertificates)))
	mux.HandleFunc("/api/user/certificates/", middleware.CorsMiddleware(middleware.AuthMiddleware(api.handleUserCertificateByID)))
	mux.HandleFunc("/api/user/policies", middleware.CorsMiddleware(middleware.AuthMiddleware(api.handleUserPolicies)))
	mux.HandleFunc("/api/user/policies/", middleware.CorsMiddleware(middleware.AuthMiddleware(api.handleUserPolicyByID)))
}

// 哈希密码
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// 生成唯一ID
func generateID(prefix string) string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%s_%x", prefix, b)
}

// 处理用户注册
func (api *UserConsoleAPI) handleUserRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.UserRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	// 检查用户名是否已存在
	users, err := api.configCenter.GetConfigsByType(config.ConfigTypeTenant)
	if err == nil {
		for _, userConfig := range users {
			if user, ok := userConfig.Value.(models.User); ok && user.Username == req.Username {
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{"error": "Username already exists"})
				return
			}
		}
	}

	// 创建新用户
	tenantID := generateID("tenant")
	user := models.User{
		ID:        generateID("user"),
		Username:  req.Username,
		Password:  hashPassword(req.Password),
		Email:     req.Email,
		TenantID:  tenantID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Status:    "active",
		Role:      "user",
	}

	// 存储用户信息到配置中心
	userConfig := &config.Config{
		ID:          user.ID,
		Type:        config.ConfigTypeTenant,
		Name:        user.Username,
		Value:       user,
		Description: "User account",
		Version:     1,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		UpdatedBy:   "system",
		Enabled:     true,
	}

	if err := api.configCenter.SetConfig(userConfig); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create user"})
		return
	}

	// 返回用户信息（不包含密码）
	response := models.UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		TenantID:  user.TenantID,
		CreatedAt: user.CreatedAt,
		Status:    user.Status,
		Role:      user.Role,
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// 处理用户登录
func (api *UserConsoleAPI) handleUserLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.UserLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	// 查找用户
	users, err := api.configCenter.GetConfigsByType(config.ConfigTypeTenant)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to authenticate user"})
		return
	}

	var foundUser models.User
	found := false

	for _, userConfig := range users {
		if user, ok := userConfig.Value.(models.User); ok && user.Username == req.Username {
			foundUser = user
			found = true
			break
		}
	}

	if !found || foundUser.Password != hashPassword(req.Password) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid username or password"})
		return
	}

	// 生成JWT令牌
	token, err := middleware.GenerateToken(foundUser.ID, foundUser.Username, foundUser.TenantID, foundUser.Role)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to generate token"})
		return
	}

	// 返回令牌和用户信息
	response := map[string]interface{}{
		"token": token,
		"user": models.UserResponse{
			ID:        foundUser.ID,
			Username:  foundUser.Username,
			Email:     foundUser.Email,
			TenantID:  foundUser.TenantID,
			CreatedAt: foundUser.CreatedAt,
			Status:    foundUser.Status,
			Role:      foundUser.Role,
		},
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// 处理用户域名列表
func (api *UserConsoleAPI) handleUserDomains(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")

	switch r.Method {
	case http.MethodGet:
		// 获取用户的所有域名
		domains, err := api.configCenter.GetDomainsByTenant(tenantID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to get domains"})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(domains)

	case http.MethodPost:
		// 添加新域名
		var domainConfig config.Config
		if err := json.NewDecoder(r.Body).Decode(&domainConfig); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
			return
		}

		// 设置租户ID
		domainConfig.Type = config.ConfigTypeDomain
		domainConfig.ID = generateID("domain")
		domainConfig.Version = 1
		domainConfig.CreatedAt = time.Now()
		domainConfig.UpdatedAt = time.Now()
		domainConfig.UpdatedBy = tenantID
		domainConfig.Enabled = true

		if err := api.configCenter.CreateDomain(&domainConfig); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create domain"})
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(domainConfig)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// 处理单个用户域名
func (api *UserConsoleAPI) handleUserDomainByID(w http.ResponseWriter, r *http.Request) {
	domainID := r.URL.Path[len("/api/user/domains/"):]

	// 检查域名是否属于当前租户
	domain, err := api.configCenter.GetDomain(domainID)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Domain not found"})
		return
	}

	// TODO: 验证域名的租户ID是否匹配
	// tenantID := r.Header.Get("X-Tenant-ID")

	switch r.Method {
	case http.MethodGet:
		// 获取域名详情
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(domain)

	case http.MethodDelete:
		// 删除域名
		if err := api.configCenter.DeleteDomain(domainID); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to delete domain"})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Domain deleted successfully"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// 处理用户源站列表
func (api *UserConsoleAPI) handleUserOrigins(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")

	switch r.Method {
	case http.MethodGet:
		// 获取用户的所有源站
		// TODO: 根据租户ID过滤源站
		origins, err := api.configCenter.GetConfigsByType(config.ConfigTypeOrigin)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to get origins"})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(origins)

	case http.MethodPost:
		// 添加新源站
		var originConfig config.Config
		if err := json.NewDecoder(r.Body).Decode(&originConfig); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
			return
		}

		// 设置租户ID
		originConfig.Type = config.ConfigTypeOrigin
		originConfig.ID = generateID("origin")
		originConfig.Version = 1
		originConfig.CreatedAt = time.Now()
		originConfig.UpdatedAt = time.Now()
		originConfig.UpdatedBy = tenantID
		originConfig.Enabled = true

		if err := api.configCenter.CreateOrigin(&originConfig); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create origin"})
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(originConfig)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// 处理单个用户源站
func (api *UserConsoleAPI) handleUserOriginByID(w http.ResponseWriter, r *http.Request) {
	originID := r.URL.Path[len("/api/user/origins/"):]

	switch r.Method {
	case http.MethodGet:
		// 获取源站详情
		origin, err := api.configCenter.GetOrigin(originID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Origin not found"})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(origin)

	case http.MethodPut:
		// 更新源站配置
		var originConfig config.Config
		if err := json.NewDecoder(r.Body).Decode(&originConfig); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
			return
		}

		originConfig.ID = originID
		originConfig.Type = config.ConfigTypeOrigin
		originConfig.UpdatedAt = time.Now()
		originConfig.UpdatedBy = r.Header.Get("X-Tenant-ID")

		if err := api.configCenter.UpdateOrigin(&originConfig); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to update origin"})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(originConfig)

	case http.MethodDelete:
		// 删除源站
		if err := api.configCenter.DeleteOrigin(originID); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to delete origin"})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Origin deleted successfully"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// 处理用户证书列表
func (api *UserConsoleAPI) handleUserCertificates(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")

	switch r.Method {
	case http.MethodGet:
		// 获取用户的所有证书
		// TODO: 根据租户ID过滤证书
		certs, err := api.configCenter.GetConfigsByType(config.ConfigTypeCertificate)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to get certificates"})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(certs)

	case http.MethodPost:
		// 上传新证书
		var certConfig config.Config
		if err := json.NewDecoder(r.Body).Decode(&certConfig); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
			return
		}

		// 设置租户ID
		certConfig.Type = config.ConfigTypeCertificate
		certConfig.ID = generateID("cert")
		certConfig.Version = 1
		certConfig.CreatedAt = time.Now()
		certConfig.UpdatedAt = time.Now()
		certConfig.UpdatedBy = tenantID
		certConfig.Enabled = true

		if err := api.configCenter.CreateCertificate(&certConfig); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to upload certificate"})
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(certConfig)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// 处理单个用户证书
func (api *UserConsoleAPI) handleUserCertificateByID(w http.ResponseWriter, r *http.Request) {
	certID := r.URL.Path[len("/api/user/certificates/"):]

	switch r.Method {
	case http.MethodGet:
		// 获取证书详情
		cert, err := api.configCenter.GetCertificate(certID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Certificate not found"})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(cert)

	case http.MethodDelete:
		// 删除证书
		if err := api.configCenter.DeleteCertificate(certID); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to delete certificate"})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Certificate deleted successfully"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// 处理用户防护策略列表
func (api *UserConsoleAPI) handleUserPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")

	switch r.Method {
	case http.MethodGet:
		// 获取用户的所有防护策略
		// TODO: 根据租户ID过滤防护策略
		policies, err := api.configCenter.GetConfigsByType(config.ConfigTypeProtectionPolicy)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to get policies"})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(policies)

	case http.MethodPost:
		// 创建新防护策略
		var policyConfig config.Config
		if err := json.NewDecoder(r.Body).Decode(&policyConfig); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
			return
		}

		// 设置租户ID
		policyConfig.Type = config.ConfigTypeProtectionPolicy
		policyConfig.ID = generateID("policy")
		policyConfig.Version = 1
		policyConfig.CreatedAt = time.Now()
		policyConfig.UpdatedAt = time.Now()
		policyConfig.UpdatedBy = tenantID
		policyConfig.Enabled = true

		if err := api.configCenter.SetConfig(&policyConfig); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create policy"})
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(policyConfig)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// 处理单个用户防护策略
func (api *UserConsoleAPI) handleUserPolicyByID(w http.ResponseWriter, r *http.Request) {
	policyID := r.URL.Path[len("/api/user/policies/"):]

	switch r.Method {
	case http.MethodGet:
		// 获取防护策略详情
		policy, err := api.configCenter.GetProtectionPolicy(policyID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Policy not found"})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(policy)

	case http.MethodPut:
		// 更新防护策略（开关防护）
		var policyConfig config.Config
		if err := json.NewDecoder(r.Body).Decode(&policyConfig); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
			return
		}

		// 获取现有策略
		existingPolicy, err := api.configCenter.GetProtectionPolicy(policyID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Policy not found"})
			return
		}

		// 只允许更新Enabled字段
		existingPolicy.Enabled = policyConfig.Enabled
		existingPolicy.UpdatedAt = time.Now()
		existingPolicy.UpdatedBy = r.Header.Get("X-Tenant-ID")

		if err := api.configCenter.UpdateConfig(existingPolicy); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to update policy"})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(existingPolicy)

	case http.MethodDelete:
		// 删除防护策略
		if err := api.configCenter.DeleteConfig(config.ConfigTypeProtectionPolicy, policyID); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to delete policy"})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Policy deleted successfully"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}