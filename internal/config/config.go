package config

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ConfigType 配置类型
type ConfigType string

const (
	// ConfigTypeServer 服务器配置
	ConfigTypeServer ConfigType = "server"
	// ConfigTypeAdmin 管理后台配置
	ConfigTypeAdmin ConfigType = "admin"
	// ConfigTypeRules 安全规则配置
	ConfigTypeRules ConfigType = "rules"
	// ConfigTypeAI AI模块配置
	ConfigTypeAI ConfigType = "ai"
	// ConfigTypeLogging 日志系统配置
	ConfigTypeLogging ConfigType = "logging"
	// ConfigTypeMetrics 监控指标配置
	ConfigTypeMetrics ConfigType = "metrics"
	// ConfigTypeStorage 存储系统配置
	ConfigTypeStorage ConfigType = "storage"
	// ConfigTypeTenant 租户配置
	ConfigTypeTenant ConfigType = "tenant"
	// ConfigTypeDomain 域名配置
	ConfigTypeDomain ConfigType = "domain"
	// ConfigTypeOrigin 源站配置
	ConfigTypeOrigin ConfigType = "origin"
	// ConfigTypeCertificate 证书配置
	ConfigTypeCertificate ConfigType = "certificate"
	// ConfigTypeProtectionPolicy 防护策略配置
	ConfigTypeProtectionPolicy ConfigType = "protection_policy"
	// ConfigTypeSystem 系统设置配置
	ConfigTypeSystem ConfigType = "system"
)

// Config 配置项结构
type Config struct {
	ID          string      `json:"id"`
	Type        ConfigType  `json:"type"`
	Name        string      `json:"name"`
	Value       interface{} `json:"value"`
	Description string      `json:"description"`
	Version     int         `json:"version"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	UpdatedBy   string      `json:"updated_by"`
	Enabled     bool        `json:"enabled"`
}

// ConfigCenter 配置中心接口
type ConfigCenter interface {
	// 基础配置管理方法
	GetConfig(configType ConfigType, name string) (*Config, error)
	GetConfigsByType(configType ConfigType) ([]*Config, error)
	SetConfig(config *Config) error
	UpdateConfig(config *Config) error
	DeleteConfig(configType ConfigType, name string) error
	RegisterChangeListener(configType ConfigType, listener ConfigChangeListener)
	UnregisterChangeListener(configType ConfigType, listener ConfigChangeListener)

	// 租户管理方法
	GetTenant(tenantID string) (*Config, error)
	GetAllTenants() ([]*Config, error)
	CreateTenant(tenant *Config) error
	UpdateTenant(tenant *Config) error
	DeleteTenant(tenantID string) error

	// 域名管理方法
	GetDomain(domainID string) (*Config, error)
	GetDomainsByTenant(tenantID string) ([]*Config, error)
	CreateDomain(domain *Config) error
	UpdateDomain(domain *Config) error
	DeleteDomain(domainID string) error

	// 源站管理方法
	GetOrigin(originID string) (*Config, error)
	GetOriginsByDomain(domainID string) ([]*Config, error)
	CreateOrigin(origin *Config) error
	UpdateOrigin(origin *Config) error
	DeleteOrigin(originID string) error

	// 证书管理方法
	GetCertificate(certID string) (*Config, error)
	GetCertificatesByDomain(domainID string) ([]*Config, error)
	CreateCertificate(cert *Config) error
	UpdateCertificate(cert *Config) error
	DeleteCertificate(certID string) error

	// 防护策略管理方法
	GetProtectionPolicy(policyID string) (*Config, error)
	GetProtectionPoliciesByDomain(domainID string) ([]*Config, error)
	CreateProtectionPolicy(policy *Config) error
	UpdateProtectionPolicy(policy *Config) error
	DeleteProtectionPolicy(policyID string) error

	// 实时配置查询方法（供WAF节点使用）
	GetDomainConfig(domainName string) (*Config, error)
	GetDomainOrigins(domainName string) ([]*Config, error)
	GetDomainCertificates(domainName string) ([]*Config, error)
	GetDomainProtectionPolicies(domainName string) ([]*Config, error)
}

// ConfigChangeListener 配置变更监听器接口
type ConfigChangeListener interface {
	// OnConfigChange 配置变更时触发
	OnConfigChange(config *Config)
}

// memoryConfigCenter 内存配置中心实现
type memoryConfigCenter struct {
	configs      map[ConfigType]map[string]*Config
	listeners    map[ConfigType][]ConfigChangeListener
	mutex        sync.RWMutex
	nextID       int
}

// NewMemoryConfigCenter 创建内存配置中心
func NewMemoryConfigCenter() ConfigCenter {
	return &memoryConfigCenter{
		configs:   make(map[ConfigType]map[string]*Config),
		listeners: make(map[ConfigType][]ConfigChangeListener),
		nextID:    1,
	}
}

// GetConfig 获取配置
func (c *memoryConfigCenter) GetConfig(configType ConfigType, name string) (*Config, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if configs, exists := c.configs[configType]; exists {
		if config, exists := configs[name]; exists {
			return config, nil
		}
	}

	return nil, errors.New("配置不存在")
}

// GetConfigsByType 获取指定类型的所有配置
func (c *memoryConfigCenter) GetConfigsByType(configType ConfigType) ([]*Config, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var result []*Config
	if configs, exists := c.configs[configType]; exists {
		for _, config := range configs {
			result = append(result, config)
		}
	}

	return result, nil
}

// SetConfig 设置配置
func (c *memoryConfigCenter) SetConfig(config *Config) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if config.ID == "" {
		config.ID = fmt.Sprintf("%d", c.nextID)
		c.nextID++
	}

	if configs, exists := c.configs[config.Type]; exists {
		configs[config.Name] = config
	} else {
		c.configs[config.Type] = map[string]*Config{
			config.Name: config,
		}
	}

	config.CreatedAt = time.Now()
	config.UpdatedAt = time.Now()
	config.Version = 1

	// 触发配置变更事件
	c.notifyChangeListeners(config)

	return nil
}

// UpdateConfig 更新配置
func (c *memoryConfigCenter) UpdateConfig(config *Config) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if configs, exists := c.configs[config.Type]; exists {
		if oldConfig, exists := configs[config.Name]; exists {
			// 更新配置
			config.ID = oldConfig.ID
			config.CreatedAt = oldConfig.CreatedAt
			config.UpdatedAt = time.Now()
			config.Version = oldConfig.Version + 1
			configs[config.Name] = config

			// 触发配置变更事件
			c.notifyChangeListeners(config)

			return nil
		}
	}

	return errors.New("配置不存在")
}

// DeleteConfig 删除配置
func (c *memoryConfigCenter) DeleteConfig(configType ConfigType, name string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if configs, exists := c.configs[configType]; exists {
		if _, exists := configs[name]; exists {
			delete(configs, name)

			// 如果该类型没有配置了，删除整个类型
			if len(configs) == 0 {
				delete(c.configs, configType)
			}

			return nil
		}
	}

	return errors.New("配置不存在")
}

// -------------------------------
// 租户管理方法实现
// -------------------------------

// GetTenant 获取租户配置
func (c *memoryConfigCenter) GetTenant(tenantID string) (*Config, error) {
	return c.GetConfig(ConfigTypeTenant, tenantID)
}

// GetAllTenants 获取所有租户配置
func (c *memoryConfigCenter) GetAllTenants() ([]*Config, error) {
	return c.GetConfigsByType(ConfigTypeTenant)
}

// CreateTenant 创建租户配置
func (c *memoryConfigCenter) CreateTenant(tenant *Config) error {
	tenant.Type = ConfigTypeTenant
	return c.SetConfig(tenant)
}

// UpdateTenant 更新租户配置
func (c *memoryConfigCenter) UpdateTenant(tenant *Config) error {
	tenant.Type = ConfigTypeTenant
	return c.UpdateConfig(tenant)
}

// DeleteTenant 删除租户配置
func (c *memoryConfigCenter) DeleteTenant(tenantID string) error {
	return c.DeleteConfig(ConfigTypeTenant, tenantID)
}

// -------------------------------
// 域名管理方法实现
// -------------------------------

// GetDomain 获取域名配置
func (c *memoryConfigCenter) GetDomain(domainID string) (*Config, error) {
	return c.GetConfig(ConfigTypeDomain, domainID)
}

// GetDomainsByTenant 获取指定租户的所有域名配置
func (c *memoryConfigCenter) GetDomainsByTenant(tenantID string) ([]*Config, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var result []*Config
	if configs, exists := c.configs[ConfigTypeDomain]; exists {
		for _, config := range configs {
			// 假设域名配置的Value中包含TenantID字段
			if domainValue, ok := config.Value.(map[string]interface{}); ok {
				if tenantID == domainValue["TenantID"] {
					result = append(result, config)
				}
			}
		}
	}

	return result, nil
}

// CreateDomain 创建域名配置
func (c *memoryConfigCenter) CreateDomain(domain *Config) error {
	domain.Type = ConfigTypeDomain
	return c.SetConfig(domain)
}

// UpdateDomain 更新域名配置
func (c *memoryConfigCenter) UpdateDomain(domain *Config) error {
	domain.Type = ConfigTypeDomain
	return c.UpdateConfig(domain)
}

// DeleteDomain 删除域名配置
func (c *memoryConfigCenter) DeleteDomain(domainID string) error {
	return c.DeleteConfig(ConfigTypeDomain, domainID)
}

// -------------------------------
// 源站管理方法实现
// -------------------------------

// GetOrigin 获取源站配置
func (c *memoryConfigCenter) GetOrigin(originID string) (*Config, error) {
	return c.GetConfig(ConfigTypeOrigin, originID)
}

// GetOriginsByDomain 获取指定域名的所有源站配置
func (c *memoryConfigCenter) GetOriginsByDomain(domainID string) ([]*Config, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var result []*Config
	if configs, exists := c.configs[ConfigTypeOrigin]; exists {
		for _, config := range configs {
			// 假设源站配置的Value中包含DomainID字段
			if originValue, ok := config.Value.(map[string]interface{}); ok {
				if domainID == originValue["DomainID"] {
					result = append(result, config)
				}
			}
		}
	}

	return result, nil
}

// CreateOrigin 创建源站配置
func (c *memoryConfigCenter) CreateOrigin(origin *Config) error {
	origin.Type = ConfigTypeOrigin
	return c.SetConfig(origin)
}

// UpdateOrigin 更新源站配置
func (c *memoryConfigCenter) UpdateOrigin(origin *Config) error {
	origin.Type = ConfigTypeOrigin
	return c.UpdateConfig(origin)
}

// DeleteOrigin 删除源站配置
func (c *memoryConfigCenter) DeleteOrigin(originID string) error {
	return c.DeleteConfig(ConfigTypeOrigin, originID)
}

// -------------------------------
// 证书管理方法实现
// -------------------------------

// GetCertificate 获取证书配置
func (c *memoryConfigCenter) GetCertificate(certID string) (*Config, error) {
	return c.GetConfig(ConfigTypeCertificate, certID)
}

// GetCertificatesByDomain 获取指定域名的所有证书配置
func (c *memoryConfigCenter) GetCertificatesByDomain(domainID string) ([]*Config, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var result []*Config
	if configs, exists := c.configs[ConfigTypeCertificate]; exists {
		for _, config := range configs {
			// 假设证书配置的Value中包含DomainID字段
			if certValue, ok := config.Value.(map[string]interface{}); ok {
				if domainID == certValue["DomainID"] {
					result = append(result, config)
				}
			}
		}
	}

	return result, nil
}

// CreateCertificate 创建证书配置
func (c *memoryConfigCenter) CreateCertificate(cert *Config) error {
	cert.Type = ConfigTypeCertificate
	return c.SetConfig(cert)
}

// UpdateCertificate 更新证书配置
func (c *memoryConfigCenter) UpdateCertificate(cert *Config) error {
	cert.Type = ConfigTypeCertificate
	return c.UpdateConfig(cert)
}

// DeleteCertificate 删除证书配置
func (c *memoryConfigCenter) DeleteCertificate(certID string) error {
	return c.DeleteConfig(ConfigTypeCertificate, certID)
}

// -------------------------------
// 防护策略管理方法实现
// -------------------------------

// GetProtectionPolicy 获取防护策略配置
func (c *memoryConfigCenter) GetProtectionPolicy(policyID string) (*Config, error) {
	return c.GetConfig(ConfigTypeProtectionPolicy, policyID)
}

// GetProtectionPoliciesByDomain 获取指定域名的所有防护策略配置
func (c *memoryConfigCenter) GetProtectionPoliciesByDomain(domainID string) ([]*Config, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var result []*Config
	if configs, exists := c.configs[ConfigTypeProtectionPolicy]; exists {
		for _, config := range configs {
			// 假设防护策略配置的Value中包含DomainID字段
			if policyValue, ok := config.Value.(map[string]interface{}); ok {
				if domainID == policyValue["DomainID"] {
					result = append(result, config)
				}
			}
		}
	}

	return result, nil
}

// CreateProtectionPolicy 创建防护策略配置
func (c *memoryConfigCenter) CreateProtectionPolicy(policy *Config) error {
	policy.Type = ConfigTypeProtectionPolicy
	return c.SetConfig(policy)
}

// UpdateProtectionPolicy 更新防护策略配置
func (c *memoryConfigCenter) UpdateProtectionPolicy(policy *Config) error {
	policy.Type = ConfigTypeProtectionPolicy
	return c.UpdateConfig(policy)
}

// DeleteProtectionPolicy 删除防护策略配置
func (c *memoryConfigCenter) DeleteProtectionPolicy(policyID string) error {
	return c.DeleteConfig(ConfigTypeProtectionPolicy, policyID)
}

// -------------------------------
// 实时配置查询方法实现
// -------------------------------

// GetDomainConfig 根据域名名称获取域名配置
func (c *memoryConfigCenter) GetDomainConfig(domainName string) (*Config, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if configs, exists := c.configs[ConfigTypeDomain]; exists {
		for _, config := range configs {
			// 假设域名配置的Value中包含DomainName字段
			if domainValue, ok := config.Value.(map[string]interface{}); ok {
				if domainName == domainValue["DomainName"] {
					return config, nil
				}
			}
		}
	}

	return nil, errors.New("域名配置不存在")
}

// GetDomainOrigins 根据域名名称获取源站配置
func (c *memoryConfigCenter) GetDomainOrigins(domainName string) ([]*Config, error) {
	// 先根据域名名称获取域名配置
	domainConfig, err := c.GetDomainConfig(domainName)
	if err != nil {
		return nil, err
	}

	// 再根据域名ID获取源站配置
	return c.GetOriginsByDomain(domainConfig.Name)
}

// GetDomainCertificates 根据域名名称获取证书配置
func (c *memoryConfigCenter) GetDomainCertificates(domainName string) ([]*Config, error) {
	// 先根据域名名称获取域名配置
	domainConfig, err := c.GetDomainConfig(domainName)
	if err != nil {
		return nil, err
	}

	// 再根据域名ID获取证书配置
	return c.GetCertificatesByDomain(domainConfig.Name)
}

// GetDomainProtectionPolicies 根据域名名称获取防护策略配置
func (c *memoryConfigCenter) GetDomainProtectionPolicies(domainName string) ([]*Config, error) {
	// 先根据域名名称获取域名配置
	domainConfig, err := c.GetDomainConfig(domainName)
	if err != nil {
		return nil, err
	}

	// 再根据域名ID获取防护策略配置
	return c.GetProtectionPoliciesByDomain(domainConfig.Name)
}

// RegisterChangeListener 注册配置变更监听器
func (c *memoryConfigCenter) RegisterChangeListener(configType ConfigType, listener ConfigChangeListener) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.listeners[configType] = append(c.listeners[configType], listener)
}

// UnregisterChangeListener 注销配置变更监听器
func (c *memoryConfigCenter) UnregisterChangeListener(configType ConfigType, listener ConfigChangeListener) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if listeners, exists := c.listeners[configType]; exists {
		for i, l := range listeners {
			if l == listener {
				// 删除监听器
				c.listeners[configType] = append(listeners[:i], listeners[i+1:]...)
				break
			}
		}

		// 如果该类型没有监听器了，删除整个类型
		if len(c.listeners[configType]) == 0 {
			delete(c.listeners, configType)
		}
	}
}

// notifyChangeListeners 通知配置变更监听器
func (c *memoryConfigCenter) notifyChangeListeners(config *Config) {
	if listeners, exists := c.listeners[config.Type]; exists {
		for _, listener := range listeners {
			go listener.OnConfigChange(config)
		}
	}

	// 通知所有类型的监听器
	if listeners, exists := c.listeners["*"]; exists {
		for _, listener := range listeners {
			go listener.OnConfigChange(config)
		}
	}
}