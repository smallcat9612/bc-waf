package rules

// GetExampleRules 获取示例规则列表
func GetExampleRules() []*Rule {
	return []*Rule{
		// SQL注入检测规则
		{
			ID:             "sql-001",
			Name:           "SQL注入检测 - UNION查询",
			Description:    "检测包含UNION的SQL注入攻击",
			MatchType:      MatchTypeContains,
			MatchLocation:  MatchLocationURI,
			MatchValue:     "union select",
			RiskScore:      100,
		},
		{
			ID:             "sql-002",
			Name:           "SQL注入检测 - 单引号",
			Description:    "检测包含单引号的SQL注入攻击",
			MatchType:      MatchTypeRegex,
			MatchLocation:  MatchLocationBody,
			MatchValue:     "'\\s*(or|and|--|#)",
			RiskScore:      80,
		},
		
		// XSS攻击检测规则
		{
			ID:             "xss-001",
			Name:           "XSS检测 - 脚本标签",
			Description:    "检测包含<script>标签的XSS攻击",
			MatchType:      MatchTypeContains,
			MatchLocation:  MatchLocationBody,
			MatchValue:     "<script",
			RiskScore:      90,
		},
		{
			ID:             "xss-002",
			Name:           "XSS检测 - JavaScript事件",
			Description:    "检测包含JavaScript事件的XSS攻击",
			MatchType:      MatchTypeRegex,
			MatchLocation:  MatchLocationURI,
			MatchValue:     "(onload|onerror|onclick)\\s*=",
			RiskScore:      85,
		},
		
		// 命令注入检测规则
		{
			ID:             "cmd-001",
			Name:           "命令注入检测 - 管道符号",
			Description:    "检测包含管道符号的命令注入攻击",
			MatchType:      MatchTypeContains,
			MatchLocation:  MatchLocationURI,
			MatchValue:     "|ls",
			RiskScore:      95,
		},
		
		// 敏感文件访问检测规则
		{
			ID:             "file-001",
			Name:           "敏感文件访问 - /etc/passwd",
			Description:    "检测尝试访问/etc/passwd文件的请求",
			MatchType:      MatchTypeContains,
			MatchLocation:  MatchLocationURI,
			MatchValue:     "/etc/passwd",
			RiskScore:      100,
		},
		
		// 头部攻击检测规则
		{
			ID:             "header-001",
			Name:           "头部攻击 - X-Forwarded-For伪造",
			Description:    "检测包含多个X-Forwarded-For的请求",
			MatchType:      MatchTypeRegex,
			MatchLocation:  MatchLocationHeader,
			MatchValue:     "(\\d+\\.\\d+\\.\\d+\\.\\d+,\\s*){2,}",
			HeaderName:     "X-Forwarded-For",
			RiskScore:      70,
		},
	}
}