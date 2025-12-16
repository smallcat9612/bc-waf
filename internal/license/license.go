package license

import (
	"errors"
	"time"
)

// LicenseStatus 授权状态
type LicenseStatus int

const (
	// LicenseStatusValid 授权有效
	LicenseStatusValid LicenseStatus = iota
	// LicenseStatusInvalid 授权无效
	LicenseStatusInvalid
	// LicenseStatusExpired 授权已过期
	LicenseStatusExpired
	// LicenseStatusDomainLimitExceeded 超出域名数量限制
	LicenseStatusDomainLimitExceeded
	// LicenseStatusFeatureDisabled 功能未授权
	LicenseStatusFeatureDisabled
)

// FeatureType 功能类型
type FeatureType string

const (
	// FeatureTypeWAFCore WAF核心功能
	FeatureTypeWAFCore FeatureType = "waf_core"
	// FeatureTypeAIProtection AI防护功能
	FeatureTypeAIProtection FeatureType = "ai_protection"
	// FeatureTypeDDosProtection DDoS防护功能
	FeatureTypeDDosProtection FeatureType = "ddos_protection"
	// FeatureTypeAdvancedLogging 高级日志功能
	FeatureTypeAdvancedLogging FeatureType = "advanced_logging"
	// FeatureTypeAPIProtection API防护功能
	FeatureTypeAPIProtection FeatureType = "api_protection"
)

// License 授权信息
type License struct {
	ID            string            `json:"id"`              // 授权ID
	CompanyName   string            `json:"company_name"`    // 公司名称
	ExpiryDate    time.Time         `json:"expiry_date"`     // 到期时间
	DomainLimit   int               `json:"domain_limit"`    // 域名数量限制
	Features      map[FeatureType]bool `json:"features"`      // 功能开关
	Signature     string            `json:"signature"`       // 数字签名
	CreatedAt     time.Time         `json:"created_at"`      // 创建时间
	UpdatedAt     time.Time         `json:"updated_at"`      // 更新时间
}

// LicenseManager 授权管理器接口
type LicenseManager interface {
	// LoadLicense 加载授权文件
	LoadLicense(licensePath string) error
	// ValidateLicense 验证授权有效性
	ValidateLicense() (LicenseStatus, error)
	// IsFeatureEnabled 检查功能是否启用
	IsFeatureEnabled(feature FeatureType) bool
	// CheckDomainLimit 检查域名数量是否超出限制
	CheckDomainLimit(currentDomainCount int) bool
	// GetLicense 获取当前授权信息
	GetLicense() (*License, error)
	// UpdateLicense 更新授权信息
	UpdateLicense(license *License) error
	// SaveLicense 保存授权信息
	SaveLicense(licensePath string) error
}

// LicenseError 授权错误
type LicenseError struct {
	Status  LicenseStatus
	Message string
}

func (e *LicenseError) Error() string {
	return e.Message
}

// NewLicenseError 创建授权错误
func NewLicenseError(status LicenseStatus, message string) *LicenseError {
	return &LicenseError{
		Status:  status,
		Message: message,
	}
}

// Common license errors
var (
	ErrInvalidLicense     = NewLicenseError(LicenseStatusInvalid, "无效的授权文件")
	ErrExpiredLicense     = NewLicenseError(LicenseStatusExpired, "授权已过期")
	ErrDomainLimitExceed  = NewLicenseError(LicenseStatusDomainLimitExceeded, "超出域名数量限制")
	ErrFeatureDisabled    = NewLicenseError(LicenseStatusFeatureDisabled, "功能未授权")
	ErrLicenseNotFound    = errors.New("授权文件未找到")
	ErrLicenseNotLoaded   = errors.New("授权未加载")
)