# API接口

此目录包含WAF对外提供的API接口定义：

## 版本管理

- **v1**：第一个API版本

每个API版本都是独立的，可以单独部署和维护。

## API类型

- **REST API**：用于管理WAF配置
- **gRPC API**：用于高性能通信（可选）

API设计遵循RESTful原则，使用JSON格式进行数据交换。