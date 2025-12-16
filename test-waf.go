package main

import (
	"fmt"
	"net/http"
	"strings"
)

func main() {
	// 测试用例1: 正常请求
	fmt.Println("=== 测试1: 正常请求 ===")
	resp, err := http.Get("http://localhost:8080/test")
	if err != nil {
		fmt.Printf("请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("状态码: %d\n\n", resp.StatusCode)
	
	// 测试用例2: SQL注入攻击
	fmt.Println("=== 测试2: SQL注入攻击 ===")
	sqlInjectionURL := "http://localhost:8080/test?id=1' union select * from users--"
	resp, err = http.Get(sqlInjectionURL)
	if err != nil {
		fmt.Printf("请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("状态码: %d\n\n", resp.StatusCode)
	
	// 测试用例3: XSS攻击
	fmt.Println("=== 测试3: XSS攻击 ===")
	xssBody := "name=<script>alert('xss')</script>"
	resp, err = http.Post("http://localhost:8080/test", "application/x-www-form-urlencoded", strings.NewReader(xssBody))
	if err != nil {
		fmt.Printf("请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("状态码: %d\n\n", resp.StatusCode)
	
	fmt.Println("测试完成，请查看WAF服务器日志以验证检测结果")
}