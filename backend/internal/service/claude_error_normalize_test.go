//go:build unit

package service

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeClaudeErrorType_OfficialTypesPreserved(t *testing.T) {
	official := []string{
		"invalid_request_error", "authentication_error", "permission_error",
		"billing_error", "not_found_error", "conflict_error", "request_too_large",
		"unprocessable_entity_error", "rate_limit_error", "overloaded_error",
		"timeout_error", "api_error",
	}
	for _, et := range official {
		// 官方类型无论状态码如何都应原样保留（真上游错误透传）
		require.Equal(t, et, NormalizeClaudeErrorType(http.StatusInternalServerError, et), "type=%s", et)
	}
}

func TestNormalizeClaudeErrorType_StatusDerivation(t *testing.T) {
	cases := []struct {
		status int
		in     string
		want   string
	}{
		{http.StatusBadRequest, "upstream_error", "invalid_request_error"},
		{http.StatusUnauthorized, "new_api_error", "authentication_error"},
		{http.StatusForbidden, "<nil>", "permission_error"},
		{http.StatusPaymentRequired, "weird", "billing_error"},
		{http.StatusNotFound, "weird", "not_found_error"},
		{http.StatusConflict, "weird", "conflict_error"},
		{http.StatusRequestEntityTooLarge, "weird", "request_too_large"},
		{http.StatusUnprocessableEntity, "weird", "unprocessable_entity_error"},
		{http.StatusTooManyRequests, "weird", "rate_limit_error"},
		{529, "weird", "overloaded_error"},
		{http.StatusGatewayTimeout, "weird", "timeout_error"},
		{http.StatusInternalServerError, "weird", "api_error"},
		{500, "", "api_error"},
	}
	for i, tc := range cases {
		require.Equal(t, tc.want, NormalizeClaudeErrorType(tc.status, tc.in), "case %d", i)
	}
}
