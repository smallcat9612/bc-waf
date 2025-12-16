package main

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
)

// 安全规则定义
type SecurityRule struct {
	Name        string
	Pattern     *regexp.Regexp
	Description string
}

// 初始化安全规则
var securityRules = []SecurityRule{
	{
		Name:        "SQL Injection",
		Pattern:     regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|alter|create|truncate|exec|xp_)`),
		Description: "检测SQL注入攻击",
	},
	{
		Name:        "XSS Attack",
		Pattern:     regexp.MustCompile(`(?i)(<script|javascript:|onload|onerror|onclick|alert\()`),
		Description: "检测XSS跨站脚本攻击",
	},
}

func main() {
	// 创建HTTP服务器
	server := &http.Server{
		Addr:    ":8080",
		Handler: http.HandlerFunc(wafHandler),
	}

	fmt.Println("WAF启动成功，监听端口 8080")
	log.Fatal(server.ListenAndServe())
}

// WAF处理函数
func wafHandler(w http.ResponseWriter, r *http.Request) {
	// 1. 记录请求信息
	log.Printf("收到请求: %s %s", r.Method, r.URL.Path)
	
	// 2. 检查请求是否包含恶意内容
	blocked, ruleName := checkSecurityRules(r)
	if blocked {
		// 阻止恶意请求
		http.Error(w, fmt.Sprintf("请求被WAF阻止: 检测到%s攻击", ruleName), http.StatusForbidden)
		log.Printf("请求被阻止: %s %s - 原因: %s", r.Method, r.URL.Path, ruleName)
		return
	}
	
	// 3. 正常处理请求
	fmt.Fprintf(w, "WAF代理服务器\n")
	fmt.Fprintf(w, "请求URL: %s\n", r.URL.Path)
	fmt.Fprintf(w, "请求方法: %s\n", r.Method)
	fmt.Fprintf(w, "请求参数: %v\n", r.URL.Query())
}

// 检查请求是否违反安全规则
func checkSecurityRules(r *http.Request) (bool, string) {
	// 检查URL
	url := r.URL.String()
	for _, rule := range securityRules {
		if rule.Pattern.MatchString(url) {
			return true, rule.Name
		}
	}
	
	// 检查请求参数
	r.ParseForm()
	for key, values := range r.Form {
		for _, value := range values {
			checkStr := key + "=" + value
			for _, rule := range securityRules {
				if rule.Pattern.MatchString(checkStr) {
					return true, rule.Name
				}
			}
		}
	}
	
	// 检查请求头
	for key, values := range r.Header {
		for _, value := range values {
			checkStr := key + ": " + value
			for _, rule := range securityRules {
				if rule.Pattern.MatchString(checkStr) {
					return true, rule.Name
				}
			}
		}
	}
	
	return false, ""
}