package logging

import (
	"sync"
	"time"
)

// memoryLogger 内存日志系统实现
type memoryLogger struct {
	entries          []LogEntry
	mutex            sync.RWMutex
	buffer           chan LogEntry
	closed           bool
	logRetentionDays int // 日志保留天数
}

// NewMemoryLogger 创建内存日志系统
func NewMemoryLogger(bufferSize int) Logger {
	logger := &memoryLogger{
		entries:          make([]LogEntry, 0),
		buffer:           make(chan LogEntry, bufferSize),
		closed:           false,
		logRetentionDays: 30, // 默认保留30天日志
	}

	// 启动后台处理协程
	go logger.processBuffer()

	return logger
}

// Log 记录日志
func (l *memoryLogger) Log(entry LogEntry) {
	if l.closed {
		return
	}

	// 设置默认值
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	// 将日志条目发送到缓冲区
	select {
	case l.buffer <- entry:
		// 成功发送到缓冲区
	default:
		// 缓冲区已满，直接写入内存
		l.writeToMemory(entry)
	}
}

// Attack 记录攻击日志
func (l *memoryLogger) Attack(tenantID, domainID, domain, message string, details map[string]interface{}) {
	entry := LogEntry{
		Type:     LogTypeAttack,
		Level:    LogLevelWarn,
		TenantID: tenantID,
		DomainID: domainID,
		Domain:   domain,
		Message:  message,
		Details:  details,
		Timestamp: time.Now(),
	}

	l.Log(entry)
}

// Access 记录访问日志
func (l *memoryLogger) Access(tenantID, domainID, domain, message string, details map[string]interface{}) {
	entry := LogEntry{
		Type:     LogTypeAccess,
		Level:    LogLevelInfo,
		TenantID: tenantID,
		DomainID: domainID,
		Domain:   domain,
		Message:  message,
		Details:  details,
		Timestamp: time.Now(),
	}

	l.Log(entry)
}

// Audit 记录审计日志
func (l *memoryLogger) Audit(tenantID, domainID, domain, message string, details map[string]interface{}) {
	entry := LogEntry{
		Type:     LogTypeAudit,
		Level:    LogLevelInfo,
		TenantID: tenantID,
		DomainID: domainID,
		Domain:   domain,
		Message:  message,
		Details:  details,
		Timestamp: time.Now(),
	}

	l.Log(entry)
}

// AttackLog 记录攻击日志（结构化）
func (l *memoryLogger) AttackLog(entry AttackLogEntry) {
	// 将结构化的攻击日志转换为通用日志条目
	logEntry := LogEntry{
		Type:      LogTypeAttack,
		Level:     LogLevelWarn,
		TenantID:  entry.TenantID,
		Domain:    entry.Domain,
		Message:   entry.AttackName,
		Timestamp: entry.Timestamp,
		Details: map[string]interface{}{
			"client_ip":        entry.ClientIP,
			"method":           entry.Method,
			"path":             entry.Path,
			"query":            entry.Query,
			"attack_type":      entry.AttackType,
			"attack_name":      entry.AttackName,
			"description":      entry.Description,
			"matched_rule_id":  entry.MatchedRuleID,
			"matched_rule_name": entry.MatchedRuleName,
			"risk_score":       entry.RiskScore,
			"status":           entry.Status,
		},
	}

	l.Log(logEntry)
}

// AccessLog 记录访问日志（结构化）
func (l *memoryLogger) AccessLog(entry AccessLogEntry) {
	// 将结构化的访问日志转换为通用日志条目
	logEntry := LogEntry{
		Type:      LogTypeAccess,
		Level:     LogLevelInfo,
		TenantID:  entry.TenantID,
		Domain:    entry.Domain,
		Message:   "HTTP访问",
		Timestamp: entry.Timestamp,
		Details: map[string]interface{}{
			"client_ip":     entry.ClientIP,
			"method":        entry.Method,
			"path":          entry.Path,
			"query":         entry.Query,
			"status":        entry.Status,
			"response_size": entry.ResponseSize,
			"duration":      entry.Duration,
			"error":         entry.Error,
		},
	}

	l.Log(logEntry)
}

// AuditLog 记录审计日志（结构化）
func (l *memoryLogger) AuditLog(entry AuditLogEntry) {
	// 将结构化的审计日志转换为通用日志条目
	logEntry := LogEntry{
		Type:      LogTypeAudit,
		Level:     LogLevelInfo,
		TenantID:  entry.TenantID,
		Message:   entry.Details,
		Timestamp: entry.Timestamp,
		Details: map[string]interface{}{
			"user_id":        entry.UserID,
			"user_name":      entry.UserName,
			"operation":      entry.Operation,
			"resource_type":  entry.ResourceType,
			"resource_id":    entry.ResourceID,
			"resource_name":  entry.ResourceName,
			"status":         entry.Status,
			"client_ip":      entry.ClientIP,
			"http_method":    entry.HTTPMethod,
			"url":            entry.URL,
		},
	}

	l.Log(logEntry)
}

// Query 查询日志
func (l *memoryLogger) Query(filter LogFilter) ([]LogEntry, error) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	// 过滤日志条目
	result := make([]LogEntry, 0)
	for _, entry := range l.entries {
		// 类型过滤
		if len(filter.Types) > 0 {
			typeMatch := false
			for _, t := range filter.Types {
				if entry.Type == t {
					typeMatch = true
					break
				}
			}
			if !typeMatch {
				continue
			}
		}

		// 级别过滤
		if len(filter.Levels) > 0 {
			levelMatch := false
			for _, level := range filter.Levels {
				if entry.Level == level {
					levelMatch = true
					break
				}
			}
			if !levelMatch {
				continue
			}
		}

		// 租户过滤
		if filter.TenantID != "" && entry.TenantID != filter.TenantID {
			continue
		}

		// 域名ID过滤
		if filter.DomainID != "" && entry.DomainID != filter.DomainID {
			continue
		}

		// 域名过滤
		if filter.Domain != "" && entry.Domain != filter.Domain {
			continue
		}

		// 时间过滤
		if !filter.Starttime.IsZero() && entry.Timestamp.Before(filter.Starttime) {
			continue
		}
		if !filter.Endtime.IsZero() && entry.Timestamp.After(filter.Endtime) {
			continue
		}

		// 匹配所有过滤条件，添加到结果集
		result = append(result, entry)
	}

	// 应用分页
	if filter.Limit > 0 {
		start := filter.Offset
		end := start + filter.Limit
		if start >= len(result) {
			return []LogEntry{}, nil
		}
		if end > len(result) {
			end = len(result)
		}
		result = result[start:end]
	}

	return result, nil
}

// Close 关闭日志系统
func (l *memoryLogger) Close() error {
	l.closed = true
	close(l.buffer)
	return nil
}

// processBuffer 处理日志缓冲区
func (l *memoryLogger) processBuffer() {
	for entry := range l.buffer {
		l.writeToMemory(entry)
	}
}

// SetLogRetentionDays 设置日志保留天数
func (l *memoryLogger) SetLogRetentionDays(days int) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.logRetentionDays = days
}

// writeToMemory 将日志写入内存
func (l *memoryLogger) writeToMemory(entry LogEntry) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.entries = append(l.entries, entry)

	// 清理过期日志
	l.cleanupExpiredLogs()
}

// cleanupExpiredLogs 清理过期日志
func (l *memoryLogger) cleanupExpiredLogs() {
	if l.logRetentionDays <= 0 {
		return // 如果保留天数为0或负数，则不清理
	}

	cutoffTime := time.Now().AddDate(0, 0, -l.logRetentionDays)
	var validEntries []LogEntry

	for _, entry := range l.entries {
		if entry.Timestamp.After(cutoffTime) {
			validEntries = append(validEntries, entry)
		}
	}

	// 更新日志条目列表
	l.entries = validEntries
}