package license

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"time"
)

// memoryLicenseManager 内存授权管理器实现
type memoryLicenseManager struct {
	license *License
	// 在实际生产环境中，应该使用rsa.PublicKey和rsa.PrivateKey
	// publicKey  *rsa.PublicKey
	// privateKey *rsa.PrivateKey
}

// NewMemoryLicenseManager 创建内存授权管理器
func NewMemoryLicenseManager() LicenseManager {
	return &memoryLicenseManager{
		license: nil,
		// 注意：在实际生产环境中，应该从安全的地方加载公钥和私钥
	}
}

// LoadLicense 加载授权文件
func (m *memoryLicenseManager) LoadLicense(licensePath string) error {
	file, err := os.Open(licensePath)
	if err != nil {
		return ErrLicenseNotFound
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return ErrInvalidLicense
	}

	var license License
	if err := json.Unmarshal(data, &license); err != nil {
		return ErrInvalidLicense
	}

	// 验证签名（在实际实现中需要验证）
	// if err := m.verifySignature(&license); err != nil {
	//     return ErrInvalidLicense
	// }

	m.license = &license
	return nil
}

// ValidateLicense 验证授权有效性
func (m *memoryLicenseManager) ValidateLicense() (LicenseStatus, error) {
	if m.license == nil {
		return LicenseStatusInvalid, ErrLicenseNotLoaded
	}

	// 检查是否过期
	if time.Now().After(m.license.ExpiryDate) {
		return LicenseStatusExpired, ErrExpiredLicense
	}

	return LicenseStatusValid, nil
}

// IsFeatureEnabled 检查功能是否启用
func (m *memoryLicenseManager) IsFeatureEnabled(feature FeatureType) bool {
	if m.license == nil {
		return false
	}

	// 检查功能开关
	if enabled, exists := m.license.Features[feature]; exists {
		return enabled
	}

	return false
}

// CheckDomainLimit 检查域名数量是否超出限制
func (m *memoryLicenseManager) CheckDomainLimit(currentDomainCount int) bool {
	if m.license == nil {
		return false
	}

	// 0 表示无限制
	if m.license.DomainLimit == 0 {
		return true
	}

	return currentDomainCount <= m.license.DomainLimit
}

// GetLicense 获取当前授权信息
func (m *memoryLicenseManager) GetLicense() (*License, error) {
	if m.license == nil {
		return nil, ErrLicenseNotLoaded
	}
	return m.license, nil
}

// UpdateLicense 更新授权信息
func (m *memoryLicenseManager) UpdateLicense(license *License) error {
	// 验证新授权的有效性
	if license == nil {
		return ErrInvalidLicense
	}

	// 验证签名（在实际实现中需要验证）
	// if err := m.verifySignature(license); err != nil {
	//     return ErrInvalidLicense
	// }

	m.license = license
	return nil
}

// SaveLicense 保存授权信息
func (m *memoryLicenseManager) SaveLicense(licensePath string) error {
	if m.license == nil {
		return ErrLicenseNotLoaded
	}

	data, err := json.MarshalIndent(m.license, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(licensePath, data, 0644)
}

// verifySignature 验证签名（在实际实现中需要完善）
func (m *memoryLicenseManager) verifySignature(license *License) error {
	// 实现RSA签名验证
	return nil
}

// GenerateTestLicense 生成测试授权（仅用于开发和测试）
func GenerateTestLicense(companyName string, expiryDays int, domainLimit int) *License {
	license := &License{
		ID:          "test-license-" + time.Now().Format("20060102150405"),
		CompanyName: companyName,
		ExpiryDate:  time.Now().AddDate(0, 0, expiryDays),
		DomainLimit: domainLimit,
		Features: map[FeatureType]bool{
			FeatureTypeWAFCore:        true,
			FeatureTypeAIProtection:   true,
			FeatureTypeDDosProtection: true,
			FeatureTypeAdvancedLogging: true,
			FeatureTypeAPIProtection:  true,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// 生成签名（在实际实现中需要完善）
	license.Signature = "test-signature"

	return license
}