# 规则引擎模块

## 功能特点

规则引擎是商业云WAF的核心组件之一，负责检测HTTP请求中的各种安全威胁。该模块具有以下特点：

1. **多种匹配方式**：支持`contains`（包含）和`regex`（正则表达式）两种匹配方式
2. **多位置匹配**：可以匹配请求的URI、请求体和请求头
3. **风险评分**：每条规则都有对应的风险分数，便于后续的安全决策
4. **内存存储**：规则存储在内存中，确保高效的检测性能
5. **可扩展接口**：支持动态添加和删除规则

## 核心组件

### Rule结构体

```go
// Rule 表示一条安全规则
type Rule struct {
	// ID 规则唯一标识符
	ID string
	// Name 规则名称
	Name string
	// Description 规则描述
	Description string
	// MatchType 匹配类型（contains/regex）
	MatchType MatchType
	// MatchLocation 匹配位置（URI/Body/Header）
	MatchLocation MatchLocation
	// MatchValue 匹配值
	MatchValue string
	// HeaderName 当匹配位置为Header时，指定要匹配的Header名称
	HeaderName string
	// RiskScore 风险分数
	RiskScore int
	// CompiledRegex 编译后的正则表达式（内部使用）
	CompiledRegex *regexp.Regexp
}
```

### RuleEngine结构体

```go
// RuleEngine 规则引擎
type RuleEngine struct {
	// Rules 规则列表
	Rules []*Rule
}
```

## 核心方法

### NewRuleEngine
```go
// NewRuleEngine 创建一个新的规则引擎实例
func NewRuleEngine() *RuleEngine
```

### AddRule
```go
// AddRule 添加一条规则
func (e *RuleEngine) AddRule(rule *Rule) error
```

### CheckRequest
```go
// CheckRequest 检查请求是否命中规则
func (e *RuleEngine) CheckRequest(uri, body string, headers map[string]string) ([]*Rule, int)
```

## 示例规则

规则引擎内置了7条示例规则，涵盖了常见的Web攻击：

1. **SQL注入检测**：检测UNION查询和单引号注入
2. **XSS攻击检测**：检测脚本标签和JavaScript事件
3. **命令注入检测**：检测管道符号等命令注入
4. **敏感文件访问**：检测访问/etc/passwd等敏感文件
5. **头部攻击检测**：检测伪造的X-Forwarded-For头部

## 使用方法

### 初始化规则引擎

```go
// 创建规则引擎实例
engine := rules.NewRuleEngine()

// 加载示例规则	exampleRules := rules.GetExampleRules()
for _, rule := range exampleRules {
	engine.AddRule(rule)
}
```

### 检测请求

```go
// 准备请求数据
uri := "/test?id=1' union select * from users--"
body := ""
headers := make(map[string]string)

// 检测请求
matchedRules, totalScore := engine.CheckRequest(uri, body, headers)

// 处理检测结果
if len(matchedRules) > 0 {
	log.Printf("检测到 %d 条安全规则，总风险分数: %d", len(matchedRules), totalScore)
	for _, rule := range matchedRules {
		log.Printf("- 规则ID: %s, 名称: %s, 分数: %d", rule.ID, rule.Name, rule.RiskScore)
	}
}
```

## 扩展规则

您可以根据需要添加自定义规则：

```go
// 创建自定义规则
customRule := &rules.Rule{
	ID:             "custom-001",
	Name:           "自定义规则",
	Description:    "检测特定的安全威胁",
	MatchType:      rules.MatchTypeRegex,
	MatchLocation:  rules.MatchLocationURI,
	MatchValue:     "特定的攻击模式",
	RiskScore:      50,
}

// 添加到规则引擎
engine.AddRule(customRule)
```

## 性能考虑

1. **正则表达式编译**：规则引擎会自动编译正则表达式，避免重复编译
2. **内存存储**：所有规则都存储在内存中，确保快速访问
3. **批量检测**：支持一次检测多条规则，减少上下文切换

## 测试

规则引擎包含完整的单元测试，可以通过以下命令运行：

```bash
go test ./internal/rules/ -v
```