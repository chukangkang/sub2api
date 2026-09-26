package handler

import (
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// 本文件实现 Claude 路径错误类型的官方归一化
// （docs/ANTHROPIC_MESSAGES_VALIDATION_SPEC.md §2.6）。
//
// /v1/messages 路径出口的任何错误，其 error.type 都必须落入官方类型集合：
// 已是官方类型则原样保留（真上游 Anthropic 错误透传），否则按状态码推导，
// 防止内部类型名（"upstream_error" 等）或 "<nil>" 泄漏给客户端。
//
// 注意：流内 SSE 错误帧不走此归一化——流已开始后状态码已固化为 200，
// 帧内 type 沿用调用方传入值（与 new-api 移植版口径一致）。

// normalizeClaudeErrorType 委托到 service.NormalizeClaudeErrorType，
// 保证 handler 与 service 两层出口使用同一套官方类型表。
func normalizeClaudeErrorType(status int, errType string) string {
	return service.NormalizeClaudeErrorType(status, errType)
}
