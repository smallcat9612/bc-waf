package behavior

import (
	"sync"
	"time"
)

// Config 行为分析器配置
type Config struct {
	TimeWindow  time.Duration // 时间窗口大小
	MaxRequests int           // 时间窗口内最大请求数
	RiskScore   int           // 超过阈值时增加的风险分数
}

// RequestRecord 请求记录
type RequestRecord struct {
	Timestamps []time.Time // 请求时间戳
	LastCheck  time.Time   // 最后检查时间
}

// Analyzer 行为分析器
type Analyzer struct {
	config  Config
	records map[string]*RequestRecord
	mutex   sync.RWMutex
}

// NewAnalyzer 创建新的行为分析器
func NewAnalyzer(config Config) *Analyzer {
	// 设置默认值
	if config.TimeWindow == 0 {
		config.TimeWindow = 60 * time.Second // 默认60秒
	}
	if config.MaxRequests == 0 {
		config.MaxRequests = 100 // 默认100次
	}
	if config.RiskScore == 0 {
		config.RiskScore = 50 // 默认50分
	}

	return &Analyzer{
		config:  config,
		records: make(map[string]*RequestRecord),
	}
}

// AnalyzeIP 分析IP的请求行为
func (a *Analyzer) AnalyzeIP(ip string) (int, bool) {
	now := time.Now()
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// 获取或创建IP记录
	record, exists := a.records[ip]
	if !exists {
		record = &RequestRecord{
			Timestamps: []time.Time{now},
			LastCheck:  now,
		}
		a.records[ip] = record
		return 0, false
	}

	// 清理过期的时间戳
	cutoff := now.Add(-a.config.TimeWindow)
	var validTimestamps []time.Time
	for _, ts := range record.Timestamps {
		if ts.After(cutoff) {
			validTimestamps = append(validTimestamps, ts)
		}
	}

	// 添加当前请求时间戳
	validTimestamps = append(validTimestamps, now)
	record.Timestamps = validTimestamps
	record.LastCheck = now

	// 检查是否超过阈值
	if len(validTimestamps) > a.config.MaxRequests {
		return a.config.RiskScore, true
	}

	return 0, false
}

// Cleanup 清理过期记录
func (a *Analyzer) Cleanup() {
	now := time.Now()
	a.mutex.Lock()
	defer a.mutex.Unlock()

	cutoff := now.Add(-a.config.TimeWindow)
	for ip, record := range a.records {
		// 如果最后检查时间超过时间窗口，删除记录
		if record.LastCheck.Before(cutoff) {
			delete(a.records, ip)
		}
	}
}

// StartCleanupJob 启动定期清理任务
func (a *Analyzer) StartCleanupJob(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			a.Cleanup()
		}
	}()
}