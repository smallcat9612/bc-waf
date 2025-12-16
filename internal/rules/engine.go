package rules

import (
	"net/url"
	"regexp"
	"strings"
)

// MatchType 匹配类型
type MatchType string

const (
	// MatchTypeContains 包含匹配
	MatchTypeContains MatchType = "contains"
	// MatchTypeRegex 正则匹配
	MatchTypeRegex MatchType = "regex"
)

// MatchLocation 匹配位置
type MatchLocation string

const (
	// MatchLocationURI URI匹配
	MatchLocationURI MatchLocation = "uri"
	// MatchLocationHeader Header匹配
	MatchLocationHeader MatchLocation = "header"
	// MatchLocationBody Body匹配
	MatchLocationBody MatchLocation = "body"
)

// Rule 规则结构体
type Rule struct {
	// ID 规则ID
	ID string
	// Name 规则名称
	Name string
	// Description 规则描述
	Description string
	// MatchType 匹配类型
	MatchType MatchType
	// MatchLocation 匹配位置
	MatchLocation MatchLocation
	// MatchValue 匹配值
	MatchValue string
	// HeaderName 当MatchLocation为Header时，指定匹配的Header名称
	HeaderName string
	// RiskScore 风险分数
	RiskScore int
	// CompiledRegex 预编译的正则表达式（仅当MatchType为regex时使用）
	CompiledRegex *regexp.Regexp
}

// RuleEngine 规则引擎结构体
type RuleEngine struct {
	// Rules 规则列表
	Rules []*Rule
}

// NewRuleEngine 创建新的规则引擎
func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		Rules: make([]*Rule, 0),
	}
}

// AddRule 添加规则
func (e *RuleEngine) AddRule(rule *Rule) error {
	// 如果是正则匹配，预编译正则表达式
	if rule.MatchType == MatchTypeRegex {
		compiled, err := regexp.Compile(rule.MatchValue)
		if err != nil {
			return err
		}
		rule.CompiledRegex = compiled
	}
	
	e.Rules = append(e.Rules, rule)
	return nil
}

// CheckRequest 检查请求是否命中规则
func (e *RuleEngine) CheckRequest(uri, body string, headers map[string]string) ([]*Rule, int) {
	var matchedRules []*Rule
	totalScore := 0
	
	// 对URI进行URL解码，以便正确匹配URL编码的内容
	decodedURI, err := url.QueryUnescape(uri)
	if err != nil {
		// 如果解码失败，使用原始URI
		decodedURI = uri
	}
	
	for _, rule := range e.Rules {
		if e.matchRule(rule, decodedURI, body, headers) {
			matchedRules = append(matchedRules, rule)
			totalScore += rule.RiskScore
		}
	}
	
	return matchedRules, totalScore
}

// matchRule 匹配单个规则
func (e *RuleEngine) matchRule(rule *Rule, uri, body string, headers map[string]string) bool {
	var content string
	
	// 根据匹配位置获取要匹配的内容
	switch rule.MatchLocation {
	case MatchLocationURI:
		content = uri
	case MatchLocationBody:
		content = body
	case MatchLocationHeader:
		if rule.HeaderName == "" {
			// 如果没有指定Header名称，则检查所有Header
			for _, value := range headers {
				if e.matchContent(rule, value) {
					return true
				}
			}
			return false
		}
		content = headers[strings.ToLower(rule.HeaderName)]
	default:
		return false
	}
	
	return e.matchContent(rule, content)
}

// matchContent 根据匹配类型匹配内容
func (e *RuleEngine) matchContent(rule *Rule, content string) bool {
	if content == "" {
		return false
	}
	
	switch rule.MatchType {
	case MatchTypeContains:
		return strings.Contains(strings.ToLower(content), strings.ToLower(rule.MatchValue))
	case MatchTypeRegex:
		if rule.CompiledRegex == nil {
			return false
		}
		return rule.CompiledRegex.MatchString(content)
	default:
		return false
	}
}

// 示例规则将从examples.go文件中加载