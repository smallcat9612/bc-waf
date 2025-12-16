package logging

import (
	"sync"
)

// Manager 日志管理器
type Manager struct {
	logger Logger
	mutex  sync.RWMutex
}

var (
	manager *Manager
	once    sync.Once
)

// InitLogger 初始化日志系统
func InitLogger(logger Logger) {
	once.Do(func() {
		manager = &Manager{
			logger: logger,
		}
	})
}

// GetLogger 获取全局日志实例
func GetLogger() Logger {
	if manager == nil {
		// 如果未初始化，使用默认的内存日志系统
		InitLogger(NewMemoryLogger(1000))
	}
	return manager.logger
}

// SetLogger 设置全局日志实例
func SetLogger(logger Logger) {
	if manager == nil {
		InitLogger(logger)
	}

	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	manager.logger = logger
}