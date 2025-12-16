package main

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func main() {
	// 测试URL
	testURL := "http://localhost:8080/test"
	
	fmt.Println("开始测试行为分析模块 - IP请求频率检测")
	fmt.Println("==================================================")
	
	// 1. 测试正常请求（单个请求）
	fmt.Println("\n1. 测试正常请求（单个请求）：")
	resp, err := http.Get(testURL)
	if err != nil {
		fmt.Printf("请求失败: %v\n", err)
	} else {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("响应状态码: %d\n", resp.StatusCode)
		fmt.Printf("响应内容: %s\n", string(body))
	}
	
	// 等待1秒
	time.Sleep(1 * time.Second)
	
	// 2. 测试频繁请求（超过阈值）
	fmt.Println("\n2. 测试频繁请求（发送150个请求，超过100个/分钟的阈值）：")
	requestCount := 150
	startTime := time.Now()
	
	for i := 0; i < requestCount; i++ {
		resp, err := http.Get(testURL)
		if err != nil {
			fmt.Printf("请求 %d 失败: %v\n", i+1, err)
		} else {
			resp.Body.Close()
			if (i+1)%20 == 0 {
				fmt.Printf("已发送 %d 个请求...\n", i+1)
			}
		}
		// 短暂间隔，避免完全阻塞
		time.Sleep(10 * time.Millisecond)
	}
	
	duration := time.Since(startTime)
	fmt.Printf("\n完成发送 %d 个请求，耗时: %v\n", requestCount, duration)
	
	// 3. 再次发送请求，检查是否被检测到
	fmt.Println("\n3. 再次发送请求，检查是否被检测到请求频率过高：")
	resp2, err2 := http.Get(testURL)
	if err2 != nil {
		fmt.Printf("请求失败: %v\n", err2)
	} else {
		defer resp2.Body.Close()
		body, _ := io.ReadAll(resp2.Body)
		fmt.Printf("响应状态码: %d\n", resp2.StatusCode)
		fmt.Printf("响应内容: %s\n", string(body))
	}
	
	fmt.Println("\n==================================================")
	fmt.Println("行为分析模块测试完成")
	fmt.Println("请查看WAF服务器日志，确认是否有行为分析告警")
}