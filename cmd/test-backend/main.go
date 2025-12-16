package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	// 注册简单的HTTP处理函数
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("[测试后端] 收到请求:")
		fmt.Printf("  方法: %s\n", r.Method)
		fmt.Printf("  URI: %s\n", r.RequestURI)
		fmt.Printf("  客户端IP: %s\n", r.RemoteAddr)
		
		// 读取请求体（如果有）
		body := make([]byte, r.ContentLength)
		if r.ContentLength > 0 {
			r.Body.Read(body)
			fmt.Printf("  请求体: %s\n", string(body))
		}
		
		// 返回响应
		fmt.Fprintf(w, "Hello from Test Backend!\n")
		fmt.Fprintf(w, "Request received: %s %s\n", r.Method, r.RequestURI)
		fmt.Fprintf(w, "Client IP: %s\n", r.RemoteAddr)
	})
	
	// 启动后端服务器，监听8081端口
	fmt.Println("测试后端服务器已启动，监听端口 8081")
	if err := http.ListenAndServe(":8081", nil); err != nil {
		log.Fatalf("后端服务器启动失败: %v", err)
	}
}