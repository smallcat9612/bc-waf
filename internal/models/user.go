package models

import (
	"time"
)

// User 表示用户信息
type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"password,omitempty"` // 密码哈希，不返回给客户端
	Email     string    `json:"email"`
	TenantID  string    `json:"tenant_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Status    string    `json:"status"` // active, inactive, suspended
	Role      string    `json:"role"`   // admin, user
}

// UserLoginRequest 用户登录请求
type UserLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UserRegisterRequest 用户注册请求
type UserRegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// UserResponse 用户响应（不包含敏感信息）
type UserResponse struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	TenantID  string    `json:"tenant_id"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
	Role      string    `json:"role"`
}