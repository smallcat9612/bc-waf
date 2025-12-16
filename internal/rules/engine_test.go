package rules

import (
	"testing"
)

func TestRuleEngine(t *testing.T) {
	// 创建规则引擎实例
	engine := NewRuleEngine()
	
	// 加载示例规则
	exampleRules := GetExampleRules()
	for _, rule := range exampleRules {
		engine.AddRule(rule)
	}
	
	// 测试用例1: 检测SQL注入攻击
	t.Run("SQL注入检测", func(t *testing.T) {
		uri := "/test?id=1' union select * from users--"
		body := ""
		headers := make(map[string]string)
		
		matchedRules, totalScore := engine.CheckRequest(uri, body, headers)
		
		if len(matchedRules) == 0 {
			t.Error("SQL注入攻击未被检测到")
		}
		
		if totalScore <= 0 {
			t.Error("SQL注入攻击风险分数不正确")
		}
		
		t.Logf("SQL注入攻击检测成功: 命中 %d 条规则，总风险分数: %d", len(matchedRules), totalScore)
	})
	
	// 测试用例2: 检测XSS攻击
	t.Run("XSS攻击检测", func(t *testing.T) {
		uri := "/test"
		body := "name=<script>alert('xss')</script>"
		headers := make(map[string]string)
		
		matchedRules, totalScore := engine.CheckRequest(uri, body, headers)
		
		if len(matchedRules) == 0 {
			t.Error("XSS攻击未被检测到")
		}
		
		if totalScore <= 0 {
			t.Error("XSS攻击风险分数不正确")
		}
		
		t.Logf("XSS攻击检测成功: 命中 %d 条规则，总风险分数: %d", len(matchedRules), totalScore)
	})
	
	// 测试用例3: 检测正常请求
	t.Run("正常请求检测", func(t *testing.T) {
		uri := "/test?id=1"
		body := "name=test"
		headers := make(map[string]string)
		
		matchedRules, totalScore := engine.CheckRequest(uri, body, headers)
		
		if len(matchedRules) > 0 {
			t.Errorf("正常请求被误判为攻击，命中 %d 条规则", len(matchedRules))
		}
		
		if totalScore != 0 {
			t.Errorf("正常请求风险分数应为0，实际为 %d", totalScore)
		}
		
		t.Log("正常请求检测成功: 未命中任何规则")
	})
}