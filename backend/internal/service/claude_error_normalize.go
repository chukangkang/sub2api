package service

import "net/http"

// 本文件实现 Claude 路径错误类型的官方归一化
// （docs/ANTHROPIC_MESSAGES_VALIDATION_SPEC.md §2.6）。
//
// /v1/messages 路径出口的任何错误，其 error.type 都必须落入官方类型集合：
// 已是官方类型则原样保留（真上游 Anthropic 错误透传），否则按状态码推导，
// 防止内部类型名（"upstream_error"、"new_api_error" 等）或 "<nil>" 泄漏给
// 客户端。handler 层的同名包装（normalizeClaudeErrorType）委托到这里。

// officialClaudeErrorTypes 是官方 Anthropic 错误类型全集。
var officialClaudeErrorTypes = map[string]bool{
	"invalid_request_error":      true,
	"authentication_error":       true,
	"permission_error":           true,
	"billing_error":              true,
	"not_found_error":            true,
	"conflict_error":             true,
	"request_too_large":          true,
	"unprocessable_entity_error": true,
	"rate_limit_error":           true,
	"overloaded_error":           true,
	"timeout_error":              true,
	"api_error":                  true,
}

// NormalizeClaudeErrorType 将任意 error.type 归一到官方集合。
// 已是官方类型 → 原样返回；否则按状态码推导；未知状态码 → api_error。
func NormalizeClaudeErrorType(status int, errType string) string {
	if officialClaudeErrorTypes[errType] {
		return errType
	}
	switch status {
	case http.StatusBadRequest:
		return "invalid_request_error"
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusPaymentRequired:
		return "billing_error"
	case http.StatusNotFound:
		return "not_found_error"
	case http.StatusConflict:
		return "conflict_error"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusUnprocessableEntity:
		return "unprocessable_entity_error"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case 529:
		return "overloaded_error"
	case http.StatusGatewayTimeout:
		return "timeout_error"
	default:
		return "api_error"
	}
}
