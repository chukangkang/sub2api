//go:build unit

package handler

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// validAnthropicBody 是一个能通过全部校验的最小合法请求体。
const validAnthropicBody = `{
	"model": "claude-sonnet-4-5",
	"max_tokens": 1024,
	"messages": [{"role": "user", "content": "Hello"}]
}`

func TestValidateAnthropicRequest_ValidMinimal(t *testing.T) {
	require.NoError(t, validateAnthropicRequest([]byte(validAnthropicBody), true))
}

func TestValidateAnthropicRequest_ValidFullParams(t *testing.T) {
	body := `{
		"model": "claude-sonnet-4-5",
		"max_tokens": 4096,
		"messages": [
			{"role": "user", "content": "Hi"},
			{"role": "assistant", "content": [{"type": "text", "text": "Hello!"}]},
			{"role": "user", "content": "More"}
		],
		"system": "You are helpful.",
		"temperature": 0.7,
		"top_p": 0.9,
		"top_k": 40,
		"stop_sequences": ["END"],
		"stream": true,
		"thinking": {"type": "enabled", "budget_tokens": 2048},
		"tools": [{"name": "my_tool", "input_schema": {"type": "object"}}],
		"tool_choice": {"type": "auto"}
	}`
	require.NoError(t, validateAnthropicRequest([]byte(body), true))
}

func TestValidateAnthropicRequest_CountTokensWithoutMaxTokens(t *testing.T) {
	body := `{
		"model": "claude-sonnet-4-5",
		"messages": [{"role": "user", "content": "Hello"}]
	}`
	// count_tokens 不要求 max_tokens
	require.NoError(t, validateAnthropicRequest([]byte(body), false))
	// /v1/messages 要求 max_tokens
	require.Error(t, validateAnthropicRequest([]byte(body), true))
}

// ── model 校验 ──

func TestValidateAnthropicRequest_ModelMissing(t *testing.T) {
	body := `{"max_tokens": 100, "messages": [{"role": "user", "content": "hi"}]}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"model" is a required property`)
}

func TestValidateAnthropicRequest_ModelNotString(t *testing.T) {
	body := `{"model": 123, "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}]}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"model" is a required property`)
}

func TestValidateAnthropicRequest_ModelEmptyString(t *testing.T) {
	body := `{"model": "", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}]}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"model" is a required property`)
}

// ── max_tokens 校验 ──

func TestValidateAnthropicRequest_MaxTokensMissing(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": "hi"}]}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"max_tokens" is a required property`)
}

func TestValidateAnthropicRequest_MaxTokensZero(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 0, "messages": [{"role": "user", "content": "hi"}]}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"max_tokens" must be greater than or equal to 1`)
}

func TestValidateAnthropicRequest_MaxTokensNegative(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": -5, "messages": [{"role": "user", "content": "hi"}]}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"max_tokens" must be greater than or equal to 1`)
}

func TestValidateAnthropicRequest_MaxTokensNotNumber(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": "abc", "messages": [{"role": "user", "content": "hi"}]}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"max_tokens" must be an integer`)
}

// ── messages 校验 ──

func TestValidateAnthropicRequest_MessagesMissing(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"messages" is a required property`)
}

func TestValidateAnthropicRequest_MessagesNotArray(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": "hello"}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"messages" must be an array`)
}

func TestValidateAnthropicRequest_MessagesEmptyArray(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": []}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"messages" must be a non-empty array`)
}

func TestValidateAnthropicRequest_MessageRoleMissing(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"content": "hi"}]}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"messages[0].role" is a required property`)
}

func TestValidateAnthropicRequest_MessageRoleInvalid(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "system", "content": "hi"}]}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"messages[0].role" must be one of: "user", "assistant"`)
}

func TestValidateAnthropicRequest_MessageContentMissing(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user"}]}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"messages[0].content" is a required property`)
}

func TestValidateAnthropicRequest_SecondMessageRoleInvalid(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [
		{"role": "user", "content": "hi"},
		{"role": "tool", "content": "result"}
	]}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"messages[1].role" must be one of: "user", "assistant"`)
}

// ── temperature 校验 ──

func TestValidateAnthropicRequest_TemperatureOutOfRange_High(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "temperature": 1.5}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"temperature" must be between 0.0 and 1.0`)
}

func TestValidateAnthropicRequest_TemperatureOutOfRange_Low(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "temperature": -0.1}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"temperature" must be between 0.0 and 1.0`)
}

func TestValidateAnthropicRequest_TemperatureBoundary(t *testing.T) {
	// 0.0 和 1.0 都是合法边界值
	body0 := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "temperature": 0.0}`
	require.NoError(t, validateAnthropicRequest([]byte(body0), true))

	body1 := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "temperature": 1.0}`
	require.NoError(t, validateAnthropicRequest([]byte(body1), true))
}

func TestValidateAnthropicRequest_TemperatureNotNumber(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "temperature": "hot"}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"temperature" must be a number`)
}

// ── top_p 校验 ──

func TestValidateAnthropicRequest_TopPOutOfRange(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "top_p": 1.5}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"top_p" must be between 0.0 and 1.0`)
}

func TestValidateAnthropicRequest_TopPValid(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "top_p": 0.5}`
	require.NoError(t, validateAnthropicRequest([]byte(body), true))
}

// ── top_k 校验 ──

func TestValidateAnthropicRequest_TopKZero(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "top_k": 0}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"top_k" must be greater than or equal to 1`)
}

func TestValidateAnthropicRequest_TopKValid(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "top_k": 40}`
	require.NoError(t, validateAnthropicRequest([]byte(body), true))
}

// ── 采样参数：Opus 4.6 之后发布的模型限制 ──
// 官方规则（platform.claude.com/docs/en/api/messages）：
//   temperature 仅接受 1.0；top_p 仅接受 >= 0.99；top_k 一律拒绝。

var samplingParamModels = []struct {
	name string
	id   string
}{
	{"opus-4-7", "claude-opus-4-7"},
	{"opus-4-8", "claude-opus-4-8"},
	{"opus-5", "claude-opus-5"},
	{"sonnet-5", "claude-sonnet-5"},
	{"fable-5", "claude-fable-5"},
	{"fable-5-1", "claude-fable-5-1"},
	{"mythos-5", "claude-mythos-5"},
	{"mythos-5-1", "claude-mythos-5-1"},
	{"mythos-preview", "claude-mythos-preview"},
}

func TestValidateAnthropicRequest_SamplingTemperatureNonDefaultRejected(t *testing.T) {
	for _, m := range samplingParamModels {
		t.Run(m.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"model": %q, "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "temperature": 0.7}`, m.id)
			err := validateAnthropicRequest([]byte(body), true)
			require.Error(t, err)
			require.Equal(t, `"temperature" must be 1.0 for this model`, err.Error())
		})
	}
}

func TestValidateAnthropicRequest_SamplingTemperatureDefaultAccepted(t *testing.T) {
	for _, m := range samplingParamModels {
		t.Run(m.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"model": %q, "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "temperature": 1.0}`, m.id)
			require.NoError(t, validateAnthropicRequest([]byte(body), true))
		})
	}
}

func TestValidateAnthropicRequest_SamplingTopPLowRejected(t *testing.T) {
	for _, m := range samplingParamModels {
		t.Run(m.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"model": %q, "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "top_p": 0.7}`, m.id)
			err := validateAnthropicRequest([]byte(body), true)
			require.Error(t, err)
			require.Equal(t, `"top_p" must be >= 0.99 for this model`, err.Error())
		})
	}
}

func TestValidateAnthropicRequest_SamplingTopPNearDefaultAccepted(t *testing.T) {
	for _, m := range samplingParamModels {
		t.Run(m.name+"/0.99", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": %q, "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "top_p": 0.99}`, m.id)
			require.NoError(t, validateAnthropicRequest([]byte(body), true))
		})
		t.Run(m.name+"/1.0", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": %q, "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "top_p": 1.0}`, m.id)
			require.NoError(t, validateAnthropicRequest([]byte(body), true))
		})
	}
}

func TestValidateAnthropicRequest_SamplingTopKAlwaysRejected(t *testing.T) {
	for _, m := range samplingParamModels {
		t.Run(m.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"model": %q, "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "top_k": 5}`, m.id)
			err := validateAnthropicRequest([]byte(body), true)
			require.Error(t, err)
			require.Equal(t, `"top_k" is not supported for this model`, err.Error())
		})
	}
}

func TestValidateAnthropicRequest_SamplingOldModelsUnaffected(t *testing.T) {
	// Opus 4.6 / Sonnet 4.6 是最后支持采样参数的模型
	for _, id := range []string{"claude-opus-4-6", "claude-sonnet-4-6", "claude-sonnet-4-5", "claude-haiku-4-5", "claude-opus-4-5"} {
		t.Run(id, func(t *testing.T) {
			body := fmt.Sprintf(`{"model": %q, "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "temperature": 0.7, "top_p": 0.5, "top_k": 40}`, id)
			require.NoError(t, validateAnthropicRequest([]byte(body), true))
		})
	}
}

func TestValidateAnthropicRequest_SamplingDateSuffixNormalized(t *testing.T) {
	// 带日期后缀的模型名应归一化后同样受限
	body := `{"model": "claude-opus-4-7-20260416", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "temperature": 0.5}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Equal(t, `"temperature" must be 1.0 for this model`, err.Error())
}

// ── thinking 校验 ──

func TestValidateAnthropicRequest_ThinkingEnabledRequiresBudget(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "enabled"}}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"thinking.budget_tokens" is a required property`)
}

func TestValidateAnthropicRequest_ThinkingBudgetTooSmall(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "enabled", "budget_tokens": 512}}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"thinking.budget_tokens" must be greater than or equal to 1024`)
}

func TestValidateAnthropicRequest_ThinkingDisabledNoBudgetNeeded(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "disabled"}}`
	require.NoError(t, validateAnthropicRequest([]byte(body), true))
}

func TestValidateAnthropicRequest_ThinkingInvalidType(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "on"}}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"thinking.type" must be one of:`)
}

func TestValidateAnthropicRequest_ThinkingAdaptiveNoBudgetNeeded(t *testing.T) {
	// claude-opus-4-8 接受 adaptive（Sonnet 4.5 反而拒绝 adaptive）
	body := `{"model": "claude-opus-4-8", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "adaptive"}}`
	require.NoError(t, validateAnthropicRequest([]byte(body), true))
}

// ── 按模型区分的 thinking.type 校验 ──

func TestValidateAnthropicRequest_Thinking_AdaptiveOnlyModels(t *testing.T) {
	// Fable 5.1 / Mythos 5.1 / Opus 5: 仅 adaptive
	adaptiveOnlyModels := []string{
		"claude-fable-5-1", "claude-mythos-5-1",
		"claude-fable-5", "claude-mythos-5",
		"claude-opus-5",
	}
	for _, model := range adaptiveOnlyModels {
		t.Run(model+"_adaptive_ok", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "adaptive"}}`, model)
			require.NoError(t, validateAnthropicRequest([]byte(body), true))
		})
		t.Run(model+"_enabled_rejected", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "enabled", "budget_tokens": 2048}}`, model)
			err := validateAnthropicRequest([]byte(body), true)
			require.Error(t, err)
			require.Equal(t, `"thinking.type.enabled" is not supported for this model. Use "thinking.type.adaptive" and "output_config.effort" to control thinking behavior.`, err.Error())
		})
		t.Run(model+"_disabled_rejected", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "disabled"}}`, model)
			err := validateAnthropicRequest([]byte(body), true)
			require.Error(t, err)
			require.Equal(t, `"thinking.type.disabled" is not supported for this model. Use "thinking.type.adaptive" and "output_config.effort" to control thinking behavior.`, err.Error())
		})
	}
}

func TestValidateAnthropicRequest_Thinking_Opus48_Sonnet5(t *testing.T) {
	// Opus 4.8 / 4.7 / Sonnet 5: adaptive + disabled（仅 enabled 被拒绝）
	models := []string{"claude-opus-4-8", "claude-opus-4-7", "claude-sonnet-5"}
	for _, model := range models {
		t.Run(model+"_adaptive_ok", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "adaptive"}}`, model)
			require.NoError(t, validateAnthropicRequest([]byte(body), true))
		})
		t.Run(model+"_disabled_ok", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "disabled"}}`, model)
			require.NoError(t, validateAnthropicRequest([]byte(body), true))
		})
		t.Run(model+"_enabled_rejected", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "enabled", "budget_tokens": 2048}}`, model)
			err := validateAnthropicRequest([]byte(body), true)
			require.Error(t, err)
			require.Equal(t, `"thinking.type.enabled" is not supported for this model. Use "thinking.type.adaptive" and "output_config.effort" to control thinking behavior.`, err.Error())
		})
	}
}

func TestValidateAnthropicRequest_Thinking_MythosPreview(t *testing.T) {
	// Mythos Preview: adaptive + enabled（仅 disabled 被拒绝）
	model := "claude-mythos-preview"
	bodyAdaptive := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "adaptive"}}`, model)
	require.NoError(t, validateAnthropicRequest([]byte(bodyAdaptive), true))

	bodyEnabled := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "enabled", "budget_tokens": 2048}}`, model)
	require.NoError(t, validateAnthropicRequest([]byte(bodyEnabled), true))

	bodyDisabled := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "disabled"}}`, model)
	err := validateAnthropicRequest([]byte(bodyDisabled), true)
	require.Error(t, err)
	// Mythos Preview 有专属文案（它是这些模型中唯一接受 extended thinking 的）
	require.Equal(t, `"thinking.type.disabled" is not supported for this model. Thinking defaults to adaptive mode when not specified; use "thinking.type.enabled" with "budget_tokens" for extended thinking.`, err.Error())
}

func TestValidateAnthropicRequest_Thinking_ExtendedOnlyModels(t *testing.T) {
	// Opus 4.5 / Haiku 4.5 / Sonnet 4.5: enabled + disabled（adaptive 被拒绝）
	models := []string{"claude-opus-4-5", "claude-haiku-4-5", "claude-sonnet-4-5"}
	for _, model := range models {
		t.Run(model+"_enabled_ok", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "enabled", "budget_tokens": 2048}}`, model)
			require.NoError(t, validateAnthropicRequest([]byte(body), true))
		})
		t.Run(model+"_disabled_ok", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "disabled"}}`, model)
			require.NoError(t, validateAnthropicRequest([]byte(body), true))
		})
		t.Run(model+"_adaptive_rejected", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "adaptive"}}`, model)
			err := validateAnthropicRequest([]byte(body), true)
			require.Error(t, err)
			require.Equal(t, `adaptive thinking is not supported on this model`, err.Error())
		})
	}
}

func TestValidateAnthropicRequest_Thinking_UnrestrictedModels(t *testing.T) {
	// Opus 4.6 / Sonnet 4.6: 已弃用，不限制
	models := []string{"claude-opus-4-6", "claude-sonnet-4-6"}
	for _, model := range models {
		for _, tt := range []string{"enabled", "disabled", "adaptive"} {
			t.Run(fmt.Sprintf("%s_%s_ok", model, tt), func(t *testing.T) {
				bt := ""
				if tt == "enabled" {
					bt = `, "budget_tokens": 2048`
				}
				body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "%s"%s}}`, model, tt, bt)
				require.NoError(t, validateAnthropicRequest([]byte(body), true))
			})
		}
	}
}

func TestValidateAnthropicRequest_Thinking_DateSuffixNormalization(t *testing.T) {
	// 带日期后缀的模型应能正确归一化
	body := `{"model": "claude-sonnet-4-5-20250929", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "adaptive"}}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err) // sonnet-4-5 不接受 adaptive

	body2 := `{"model": "claude-sonnet-4-5-20250929", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "thinking": {"type": "enabled", "budget_tokens": 2048}}`
	require.NoError(t, validateAnthropicRequest([]byte(body2), true))
}

func TestNormalizeThinkingModelFamily(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"claude-sonnet-4-5-20250929", "claude-sonnet-4-5"},
		{"claude-opus-4-5-20251101", "claude-opus-4-5"},
		{"claude-haiku-4-5-20251001", "claude-haiku-4-5"},
		{"claude-opus-4-6-thinking", "claude-opus-4-6"},
		{"claude-fable-5-1", "claude-fable-5-1"},
		{"claude-opus-5", "claude-opus-5"},
		{"unknown-model", "unknown-model"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			require.Equal(t, tc.want, normalizeThinkingModelFamily(tc.input))
		})
	}
}

// ── 组合场景 ──

func TestValidateAnthropicRequest_ContentAsStringOrArray(t *testing.T) {
	// content 可以是字符串
	bodyStr := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "plain text"}]}`
	require.NoError(t, validateAnthropicRequest([]byte(bodyStr), true))

	// content 也可以是数组
	bodyArr := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": [{"type": "text", "text": "block"}]}]}`
	require.NoError(t, validateAnthropicRequest([]byte(bodyArr), true))
}

func TestValidateAnthropicRequest_SystemAsStringOrArray(t *testing.T) {
	bodyStr := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "system": "You are helpful.", "messages": [{"role": "user", "content": "hi"}]}`
	require.NoError(t, validateAnthropicRequest([]byte(bodyStr), true))

	bodyArr := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "system": [{"type": "text", "text": "You are helpful."}], "messages": [{"role": "user", "content": "hi"}]}`
	require.NoError(t, validateAnthropicRequest([]byte(bodyArr), true))
}

// ── prefill 校验（4.6+ / Mythos Preview 必须以 user 消息结尾）──

func TestValidateAnthropicRequest_PrefillRejected(t *testing.T) {
	// 4.6+ 模型与 Mythos Preview 拒绝 assistant 结尾
	rejectModels := []string{
		"claude-opus-4-6", "claude-sonnet-4-6",
		"claude-opus-4-7", "claude-opus-4-8", "claude-opus-5",
		"claude-sonnet-5",
		"claude-fable-5", "claude-fable-5-1",
		"claude-mythos-5", "claude-mythos-5-1",
		"claude-mythos-preview",
	}
	for _, model := range rejectModels {
		t.Run(model+"_assistant_end_rejected", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}]}`, model)
			err := validateAnthropicRequest([]byte(body), true)
			require.Error(t, err)
			require.Equal(t, `This model does not support assistant message prefill. The conversation must end with a user message.`, err.Error())
		})
		t.Run(model+"_user_end_ok", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "assistant", "content": "hello"}, {"role": "user", "content": "hi"}]}`, model)
			require.NoError(t, validateAnthropicRequest([]byte(body), true))
		})
	}
}

func TestValidateAnthropicRequest_PrefillAllowedOnOlderModels(t *testing.T) {
	// 4.5 系列不受 prefill 限制
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}]}`
	require.NoError(t, validateAnthropicRequest([]byte(body), true))
}

func TestValidateAnthropicRequest_Prefill_ToolUseEndingNotPrefill(t *testing.T) {
	// 工具调用流程：assistant 消息仅含 tool_use 块（无文本），不应被视为 prefill
	body := `{"model": "claude-opus-4-6", "max_tokens": 100, "messages": [
		{"role": "user", "content": "weather?"},
		{"role": "assistant", "content": [{"type": "tool_use", "id": "tu_1", "name": "get_weather", "input": {}}]}
	]}`
	require.NoError(t, validateAnthropicRequest([]byte(body), true))

	// assistant 消息同时含文本 + tool_use → 仍是 prefill，应拒绝
	bodyMixed := `{"model": "claude-opus-4-6", "max_tokens": 100, "messages": [
		{"role": "user", "content": "weather?"},
		{"role": "assistant", "content": [{"type": "text", "text": "Let me check"}, {"type": "tool_use", "id": "tu_1", "name": "get_weather", "input": {}}]}
	]}`
	err := validateAnthropicRequest([]byte(bodyMixed), true)
	require.Error(t, err)
	require.Equal(t, `This model does not support assistant message prefill. The conversation must end with a user message.`, err.Error())
}

// ── tool_choice 强制工具调用校验（Fable 5.1 / Mythos 5.1）──

func TestValidateAnthropicRequest_ForcedToolChoiceRejected(t *testing.T) {
	rejectModels := []string{"claude-fable-5-1", "claude-mythos-5-1"}
	for _, model := range rejectModels {
		t.Run(model+"_tool_rejected", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "tool_choice": {"type": "tool", "name": "get_weather"}}`, model)
			err := validateAnthropicRequest([]byte(body), true)
			require.Error(t, err)
			require.Equal(t, `tool_choice: type "tool" and "any" are not supported for this model.`, err.Error())
		})
		t.Run(model+"_any_rejected", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "tool_choice": {"type": "any"}}`, model)
			err := validateAnthropicRequest([]byte(body), true)
			require.Error(t, err)
			require.Equal(t, `tool_choice: type "tool" and "any" are not supported for this model.`, err.Error())
		})
		t.Run(model+"_auto_ok", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "tool_choice": {"type": "auto"}}`, model)
			require.NoError(t, validateAnthropicRequest([]byte(body), true))
		})
		t.Run(model+"_none_ok", func(t *testing.T) {
			body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "tool_choice": {"type": "none"}}`, model)
			require.NoError(t, validateAnthropicRequest([]byte(body), true))
		})
	}
}

func TestValidateAnthropicRequest_ForcedToolChoiceAllowedElsewhere(t *testing.T) {
	// 其他模型允许 tool/any
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "tool_choice": {"type": "any"}}`
	require.NoError(t, validateAnthropicRequest([]byte(body), true))
}

// ── max_tokens 上限校验 ──

func TestValidateAnthropicRequest_MaxTokensAboveCapRejected(t *testing.T) {
	// 128K 上限模型：cap+1 应 400
	body := `{"model": "claude-opus-5", "max_tokens": 131073, "messages": [{"role": "user", "content": "hi"}]}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"max_tokens" must be less than or equal to 131072`)
}

func TestValidateAnthropicRequest_MaxTokensAtCapAccepted(t *testing.T) {
	// 恰好等于上限应放行
	body := `{"model": "claude-opus-5", "max_tokens": 131072, "messages": [{"role": "user", "content": "hi"}]}`
	require.NoError(t, validateAnthropicRequest([]byte(body), true))
}

func TestValidateAnthropicRequest_MaxTokensHaikuCap(t *testing.T) {
	// Haiku 4.5 上限 64K
	body := `{"model": "claude-haiku-4-5", "max_tokens": 65537, "messages": [{"role": "user", "content": "hi"}]}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"max_tokens" must be less than or equal to 65536`)
}

func TestValidateAnthropicRequest_MaxTokensUnknownModelUntouched(t *testing.T) {
	// 未知模型不设上限，超大值也放行（交给上游）
	body := `{"model": "some-unknown-model", "max_tokens": 999999, "messages": [{"role": "user", "content": "hi"}]}`
	require.NoError(t, validateAnthropicRequest([]byte(body), true))
}

// ── output_config.effort 校验 ──

func TestValidateAnthropicRequest_EffortInvalidValueRejected(t *testing.T) {
	body := `{"model": "claude-opus-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "output_config": {"effort": "ultra"}}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"output_config.effort" must be one of`)
}

func TestValidateAnthropicRequest_EffortValidValuesAccepted(t *testing.T) {
	for _, e := range []string{"low", "medium", "high", "xhigh", "max"} {
		body := fmt.Sprintf(`{"model": "claude-opus-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "output_config": {"effort": "%s"}}`, e)
		require.NoError(t, validateAnthropicRequest([]byte(body), true), "effort %s should be accepted on opus-5", e)
	}
}

func TestValidateAnthropicRequest_EffortXHighRejectedOnOpus46(t *testing.T) {
	// opus-4-6 支持 low/medium/high/max，但不支持 xhigh
	body := `{"model": "claude-opus-4-6", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "output_config": {"effort": "xhigh"}}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `value "xhigh" is not supported for this model`)
}

func TestValidateAnthropicRequest_EffortMaxAcceptedOnOpus46(t *testing.T) {
	// opus-4-6 支持 max
	body := `{"model": "claude-opus-4-6", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "output_config": {"effort": "max"}}`
	require.NoError(t, validateAnthropicRequest([]byte(body), true))
}

func TestValidateAnthropicRequest_EffortNotStringRejected(t *testing.T) {
	body := `{"model": "claude-opus-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "output_config": {"effort": 3}}`
	err := validateAnthropicRequest([]byte(body), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"output_config.effort" must be a string`)
}

// ── speed=fast 校验 ──

func TestValidateAnthropicRequest_SpeedFastSupportedModelsAccepted(t *testing.T) {
	for _, model := range []string{"claude-opus-5", "claude-opus-4-8", "claude-opus-4.8"} {
		body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "speed": "fast"}`, model)
		require.NoError(t, validateAnthropicRequest([]byte(body), true), "model %s should accept speed=fast", model)
	}
}

func TestValidateAnthropicRequest_SpeedFastUnsupportedModelsRejected(t *testing.T) {
	for _, model := range []string{
		"claude-opus-4-7",  // fast mode 已移除
		"claude-opus-4-6",
		"claude-opus-4-5",  // 不能被 "opus-5" 规则误判
		"claude-sonnet-5",
		"claude-haiku-4-5",
	} {
		body := fmt.Sprintf(`{"model": "%s", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "speed": "fast"}`, model)
		err := validateAnthropicRequest([]byte(body), true)
		require.Error(t, err, "model %s should reject speed=fast", model)
		require.Equal(t, `"speed" value "fast" is not supported for this model`, err.Error())
	}
}

func TestValidateAnthropicRequest_SpeedStandardAlwaysAccepted(t *testing.T) {
	body := `{"model": "claude-sonnet-4-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}], "speed": "standard"}`
	require.NoError(t, validateAnthropicRequest([]byte(body), true))
}
