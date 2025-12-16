# 部署配置

此目录包含WAF的部署配置文件：

## 部署方式

- **docker**：Docker容器化部署配置
  - Dockerfile：构建WAF镜像
  - docker-compose.yaml：本地开发环境部署

- **kubernetes**：Kubernetes集群部署配置
  - deployment.yaml：WAF服务器部署
  - service.yaml：服务暴露
  - configmap.yaml：配置管理
  - secret.yaml：敏感信息管理
  - hpa.yaml：水平扩展配置

## 生产环境部署建议

- 使用Kubernetes进行容器编排
- 配置自动扩缩容
- 使用持久化存储保存日志和配置
- 配置监控和告警