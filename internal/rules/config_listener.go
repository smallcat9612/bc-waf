package rules

import (
	"encoding/json"
	"log"
	"regexp"
	"github.com/yourcompany/commercial-waf/internal/config"
)

// RuleConfigListener 规则配置变更监听器
type RuleConfigListener struct {
	engine *RuleEngine
}

// NewRuleConfigListener 创建规则配置变更监听器
func NewRuleConfigListener(engine *RuleEngine) *RuleConfigListener {
	return &RuleConfigListener{
		engine: engine,
	}
}

// OnConfigChange 配置变更时触发
func (l *RuleConfigListener) OnConfigChange(cfg *config.Config) {
	log.Printf("收到规则配置变更: %s-%s", cfg.Type, cfg.Name)

	// 只处理规则类型的配置
	if cfg.Type != config.ConfigTypeRules {
		return
	}

	// 如果配置是禁用状态，忽略
	if !cfg.Enabled {
		log.Printf("规则配置 %s 已禁用，忽略变更", cfg.Name)
		return
	}

	// 将配置值转换为规则
	var rule Rule
	data, err := json.Marshal(cfg.Value)
	if err != nil {
		log.Printf("规则配置解析失败: %v", err)
		return
	}

	err = json.Unmarshal(data, &rule)
	if err != nil {
		log.Printf("规则配置解析失败: %v", err)
		return
	}

	// 更新规则ID和启用状态
	rule.ID = cfg.Name

	// 检查规则是否已经存在
	existingRule := l.findRule(rule.ID)
	if existingRule != nil {
		// 更新规则
		l.updateRule(&rule)
		log.Printf("已更新规则: %s", rule.Name)
	} else {
		// 添加新规则
		err := l.engine.AddRule(&rule)
		if err != nil {
			log.Printf("添加规则失败: %v", err)
			return
		}
		log.Printf("已添加新规则: %s", rule.Name)
	}
}

// findRule 查找规则
func (l *RuleConfigListener) findRule(ruleID string) *Rule {
	for _, rule := range l.engine.Rules {
		if rule.ID == ruleID {
			return rule
		}
	}
	return nil
}

// updateRule 更新规则
func (l *RuleConfigListener) updateRule(newRule *Rule) {
	for i, rule := range l.engine.Rules {
		if rule.ID == newRule.ID {
			// 更新规则
			l.engine.Rules[i] = newRule
			// 如果是正则规则，重新编译
			if newRule.MatchType == MatchTypeRegex {
				newRule.CompileRegex()
			}
			break
		}
	}
}

// CompileRegex 编译正则表达式
func (r *Rule) CompileRegex() error {
	if r.MatchType == MatchTypeRegex {
		compiled, err := regexp.Compile(r.MatchValue)
		if err != nil {
			return err
		}
		r.CompiledRegex = compiled
	}
	return nil
}