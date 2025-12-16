package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/yourcompany/commercial-waf/internal/license"
)

// LicenseMiddleware 授权验证中间件
func LicenseMiddleware(licenseManager license.LicenseManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 跳过授权相关的API和系统设置API（用于测试）
			if r.URL.Path == "/api/license" || r.URL.Path == "/api/license/validate" || r.URL.Path == "/api/system-settings" {
				next.ServeHTTP(w, r)
				return
			}

			// 验证授权状态
			status, err := licenseManager.ValidateLicense()
			if err != nil || status != license.LicenseStatusValid {
				// 返回授权错误信息
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": "License validation failed",
					"status": status,
					"message": err.Error(),
				})
				return
			}

			// 验证通过，继续处理请求
			next.ServeHTTP(w, r)
		})
	}
}

// FeatureMiddleware 功能授权中间件
func FeatureMiddleware(licenseManager license.LicenseManager, feature license.FeatureType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 检查功能是否启用
			if !licenseManager.IsFeatureEnabled(feature) {
				// 返回功能未授权错误
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": "Feature not authorized",
					"status": license.LicenseStatusFeatureDisabled,
					"message": "This feature is not enabled in your license",
				})
				return
			}

			// 功能授权通过，继续处理请求
			next.ServeHTTP(w, r)
		})
	}
}