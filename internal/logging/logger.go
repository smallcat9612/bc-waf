package logging

import (
	"time"
)

// LogType 日志类型
type LogType string

const (
	// LogTypeAttack 攻击日志
	LogTypeAttack LogType = "attack"
	// LogTypeAccess 访问日志
	LogTypeAccess LogType = "access"
	// LogTypeAudit 审计日志
	LogTypeAudit LogType = "audit"
)

// LogLevel 日志级别
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
)

// AttackType 攻击类型
type AttackType string

const (
	AttackTypeSQLi        AttackType = "sqli"
	AttackTypeXSS         AttackType = "xss"
	AttackTypeCSRF        AttackType = "csrf"
	AttackTypePathTraversal AttackType = "path_traversal"
	AttackTypeCommandInjection AttackType = "command_injection"
	AttackTypeSecurityRule AttackType = "security_rule"
	AttackTypeBehavior    AttackType = "behavior"
)

// AttackStatus 攻击状态
type AttackStatus string

const (
	AttackStatusDetected AttackStatus = "detected"
	AttackStatusBlocked AttackStatus = "blocked"
	AttackStatusAllowed AttackStatus = "allowed"
)

// AuditOperation 审计操作类型
type AuditOperation string

const (
	AuditOperationCreate AuditOperation = "create"
	AuditOperationRead   AuditOperation = "read"
	AuditOperationUpdate AuditOperation = "update"
	AuditOperationDelete AuditOperation = "delete"
)

// AuditResourceType 审计资源类型
type AuditResourceType string

const (
	AuditResourceTypeConfig AuditResourceType = "config"
	AuditResourceTypeRule   AuditResourceType = "rule"
	AuditResourceTypeTenant AuditResourceType = "tenant"
	AuditResourceTypeDomain AuditResourceType = "domain"
	AuditResourceTypeUser   AuditResourceType = "user"
)

// AuditStatus 审计状态
type AuditStatus string

const (
	AuditStatusSuccess AuditStatus = "success"
	AuditStatusFailed  AuditStatus = "failed"
)

// LogEntry 日志条目结构
type LogEntry struct {
	ID        string            `json:"id"`
	Type      LogType           `json:"type"`
	Level     LogLevel          `json:"level"`
	TenantID  string            `json:"tenant_id,omitempty"`
	DomainID  string            `json:"domain_id,omitempty"`
	Domain    string            `json:"domain,omitempty"`
	Message   string            `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// AttackLogEntry 攻击日志条目结构
type AttackLogEntry struct {
	Timestamp      time.Time     `json:"timestamp"`
	TenantID       string        `json:"tenant_id,omitempty"`
	Domain         string        `json:"domain,omitempty"`
	ClientIP       string        `json:"client_ip"`
	Method         string        `json:"method"`
	Path           string        `json:"path"`
	Query          string        `json:"query,omitempty"`
	AttackType     AttackType    `json:"attack_type"`
	AttackName     string        `json:"attack_name"`
	Description    string        `json:"description"`
	MatchedRuleID  string        `json:"matched_rule_id,omitempty"`
	MatchedRuleName string       `json:"matched_rule_name,omitempty"`
	RiskScore      int           `json:"risk_score,omitempty"`
	Status         AttackStatus  `json:"status"`
}

// AccessLogEntry 访问日志条目结构
type AccessLogEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	TenantID     string    `json:"tenant_id,omitempty"`
	Domain       string    `json:"domain,omitempty"`
	ClientIP     string    `json:"client_ip"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	Query        string    `json:"query,omitempty"`
	Status       int       `json:"status"`
	ResponseSize int       `json:"response_size"`
	Duration     int64     `json:"duration"` // 毫秒
	Error        string    `json:"error,omitempty"`
}

// AuditLogEntry 审计日志条目结构
type AuditLogEntry struct {
	Timestamp     time.Time         `json:"timestamp"`
	TenantID      string            `json:"tenant_id,omitempty"`
	UserID        string            `json:"user_id"`
	UserName      string            `json:"user_name"`
	Operation     AuditOperation    `json:"operation"`
	ResourceType  AuditResourceType `json:"resource_type"`
	ResourceID    string            `json:"resource_id,omitempty"`
	ResourceName  string            `json:"resource_name,omitempty"`
	Details       string            `json:"details,omitempty"`
	Status        AuditStatus       `json:"status"`
	ClientIP      string            `json:"client_ip"`
	HTTPMethod    string            `json:"http_method"`
	URL           string            `json:"url"`
}

// Logger 日志接口
type Logger interface {
	// 记录日志
	Log(entry LogEntry)
	
	// 记录攻击日志
	Attack(tenantID, domainID, domain, message string, details map[string]interface{})
	
	// 记录访问日志
	Access(tenantID, domainID, domain, message string, details map[string]interface{})
	
	// 记录审计日志
	Audit(tenantID, domainID, domain, message string, details map[string]interface{})
	
	// 记录攻击日志（结构化）
	AttackLog(entry AttackLogEntry)
	
	// 记录访问日志（结构化）
	AccessLog(entry AccessLogEntry)
	
	// 记录审计日志（结构化）
	AuditLog(entry AuditLogEntry)
	
	// 查询日志
	Query(filter LogFilter) ([]LogEntry, error)
	
	// 设置日志保留天数
	SetLogRetentionDays(days int)
	
	// 关闭日志系统
	Close() error
}

// LogFilter 日志查询过滤器
type LogFilter struct {
	Types     []LogType `json:"types,omitempty"`
	Levels    []LogLevel `json:"levels,omitempty"`
	TenantID  string    `json:"tenant_id,omitempty"`
	DomainID  string    `json:"domain_id,omitempty"`
	Domain    string    `json:"domain,omitempty"`
	Starttime time.Time `json:"starttime,omitempty"`
	Endtime   time.Time `json:"endtime,omitempty"`
	Limit     int       `json:"limit,omitempty"`
	Offset    int       `json:"offset,omitempty"`
}