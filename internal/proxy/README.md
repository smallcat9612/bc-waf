# 流量接入 / 反向代理模块

此模块是WAF的核心组件，负责接收客户端请求并转发到后端服务器。

## 功能特点

- **请求接收**：接收HTTP请求
- **请求解析**：解析请求的method、uri、headers、body
- **日志记录**：打印请求详细信息
- **安全检测**：预留安全检测入口（可扩展）
- **请求转发**：将请求转发到后端服务器
- **响应返回**：将后端响应返回给客户端

## 主要组件

### ReverseProxy结构体
主要的反向代理处理器，实现了http.Handler接口。

### 核心方法

- `ServeHTTP(w http.ResponseWriter, r *http.Request)`：处理HTTP请求的主方法
- `logRequest(method, uri string, headers http.Header, body []byte)`：打印请求信息
- `securityCheck(r *http.Request, body []byte)`：安全检测入口（预留）
- `forwardRequest(w http.ResponseWriter, r *http.Request, body []byte)`：转发请求到后端

## 使用方法

### 1. 启动测试后端服务器

```bash
go run cmd/test-backend/main.go
```

### 2. 启动WAF服务器

```bash
go run cmd/waf-server/main.go
```

### 3. 发送测试请求

```bash
curl http://localhost:8080/test
```

## 扩展安全检测

要扩展安全检测功能，只需修改`securityCheck`方法：

```go
func (p *ReverseProxy) securityCheck(r *http.Request, body []byte) error {
    // 实现安全检测逻辑
    // 如果检测到威胁，返回错误
    // 否则返回nil
}
```

## 配置说明

- `BackendAddr`：后端服务器地址
- `EnableLogging`：是否启用请求日志记录

## 注意事项

- 目前安全检测仅做日志记录，不做实际拦截
- 生产环境使用时，建议添加更完善的错误处理和监控
- 请根据实际需求配置后端服务器地址