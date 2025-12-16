package config

import (
	"log"
	"sync"
)

// SystemSettings 系统设置结构
type SystemSettings struct {
	AISwitch        bool   `json:"ai_switch"`        // AI开关
	DefaultMode     string `json:"default_mode"`     // 默认防护模式 ("monitoring" 或 "protection")
	LogRetentionDays int    `json:"log_retention_days"` // 日志保留天数
}

// SystemSettingsManager 系统设置管理器
type SystemSettingsManager struct {
	configCenter ConfigCenter
	settings     SystemSettings
	mutex        sync.RWMutex
}

// NewSystemSettingsManager 创建系统设置管理器
func NewSystemSettingsManager(configCenter ConfigCenter) *SystemSettingsManager {
	manager := &SystemSettingsManager{
		configCenter: configCenter,
		settings: SystemSettings{
			AISwitch:        true,
			DefaultMode:     "monitoring",
			LogRetentionDays: 30,
		},
	}

	// 加载初始设置
	manager.loadSettings()

	// 注册配置变更监听器
	configCenter.RegisterChangeListener(ConfigTypeSystem, manager)

	return manager
}

// GetSettings 获取系统设置
func (m *SystemSettingsManager) GetSettings() SystemSettings {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.settings
}

// GetAISwitch 获取AI开关状态
func (m *SystemSettingsManager) GetAISwitch() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.settings.AISwitch
}

// GetDefaultMode 获取默认防护模式
func (m *SystemSettingsManager) GetDefaultMode() string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.settings.DefaultMode
}

// GetLogRetentionDays 获取日志保留天数
func (m *SystemSettingsManager) GetLogRetentionDays() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.settings.LogRetentionDays
}

// loadSettings 从配置中心加载设置
func (m *SystemSettingsManager) loadSettings() {
	configs, err := m.configCenter.GetConfigsByType(ConfigTypeSystem)
	if err != nil {
		log.Printf("Failed to load system settings: %v", err)
		return
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, cfg := range configs {
		m.updateSettingFromConfig(cfg)
	}

	log.Printf("System settings loaded: %+v", m.settings)
}

// OnConfigChange 实现ConfigChangeListener接口，处理配置变更
func (m *SystemSettingsManager) OnConfigChange(config *Config) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// 更新单个设置
	m.updateSettingFromConfig(config)
	
	log.Printf("System settings updated: %+v", m.settings)
	log.Printf("System setting changed: %s-%s", config.Type, config.Name)
}

// updateSettingFromConfig 从配置更新单个设置项
func (m *SystemSettingsManager) updateSettingFromConfig(config *Config) {
	switch config.Name {
	case "ai_switch":
		if val, ok := config.Value.(bool); ok {
			m.settings.AISwitch = val
		}
	case "default_mode":
		if val, ok := config.Value.(string); ok {
			m.settings.DefaultMode = val
		}
	case "log_retention_days":
		// 同时支持int和float64类型
		switch val := config.Value.(type) {
		case int:
			m.settings.LogRetentionDays = val
		case float64:
			m.settings.LogRetentionDays = int(val)
		}
	}
}