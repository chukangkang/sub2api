//go:build unit

package service

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestSignaturePairFingerprint_DeterministicAndDistinct(t *testing.T) {
	a1 := SignaturePairFingerprint("sigA", "thinkA")
	a2 := SignaturePairFingerprint("sigA", "thinkA")
	require.Equal(t, a1, a2, "same pair must yield identical fingerprint")

	// 换 thinking 文本（换绑攻击）→ 不同指纹
	require.NotEqual(t, a1, SignaturePairFingerprint("sigA", "thinkB"))
	// 换签名 → 不同指纹
	require.NotEqual(t, a1, SignaturePairFingerprint("sigB", "thinkA"))

	// redacted_thinking（空文本）退化为裸签名指纹
	bare := SignaturePairFingerprint("sigA", "")
	require.Equal(t, bare, SignaturePairFingerprint("sigA", ""))
	require.NotEqual(t, a1, bare)
}

func TestSignatureRegistry_InMemory_ColdThenHot(t *testing.T) {
	ctx := context.Background()
	reg := NewSignatureRegistry(nil)

	// 冷态：从未登记 → IsWarm=false
	require.False(t, reg.IsWarm(ctx))

	// 登记后进入热态
	reg.Register(ctx, 42, "claude-opus-5", [][2]string{{"sigA", "thinkA"}})
	require.True(t, reg.IsWarm(ctx))

	fp := SignaturePairFingerprint("sigA", "thinkA")
	require.True(t, reg.Contains(ctx, 42, "claude-opus-5", fp))

	// 换绑：同签名不同 thinking → 未命中
	require.False(t, reg.Contains(ctx, 42, "claude-opus-5", SignaturePairFingerprint("sigA", "thinkB")))
	// 跨用户：其他用户桶为空 → 未命中
	require.False(t, reg.Contains(ctx, 43, "claude-opus-5", fp))
	// 跨模型：其他模型桶为空 → 未命中
	require.False(t, reg.Contains(ctx, 42, "claude-sonnet-4-5", fp))
}

func TestSignatureRegistry_Redis_WarmMarkerAndMembership(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	ctx := context.Background()
	reg := NewSignatureRegistry(rdb)

	require.False(t, reg.IsWarm(ctx), "fresh redis must be cold")

	reg.Register(ctx, 7, "claude-opus-5", [][2]string{{"sigX", "thinkX"}})
	require.True(t, reg.IsWarm(ctx), "registration must flip warm marker")

	fp := SignaturePairFingerprint("sigX", "thinkX")
	require.True(t, reg.Contains(ctx, 7, "claude-opus-5", fp))
	require.False(t, reg.Contains(ctx, 8, "claude-opus-5", fp), "cross-user must miss")
}

func TestSignatureRegistry_RedactedUsesBareFingerprint(t *testing.T) {
	ctx := context.Background()
	reg := NewSignatureRegistry(nil)

	reg.Register(ctx, 1, "claude-opus-5", [][2]string{{"redactedSig", ""}})
	require.True(t, reg.IsWarm(ctx))
	require.True(t, reg.Contains(ctx, 1, "claude-opus-5", SignaturePairFingerprint("redactedSig", "")))
}

func TestHarvestSignaturesFromBody_ExtractsPairs(t *testing.T) {
	body := []byte(`{
	  "content": [
	    {"type":"text","text":"hello"},
	    {"type":"thinking","thinking":"step by step","signature":"SIG_THINK"},
	    {"type":"redacted_thinking","signature":"SIG_REDACTED"},
	    {"type":"thinking","signature":""}
	  ]
	}`)
	pairs := HarvestSignaturesFromBody(body)
	require.Len(t, pairs, 2)
	require.Equal(t, [2]string{"SIG_THINK", "step by step"}, pairs[0])
	require.Equal(t, [2]string{"SIG_REDACTED", ""}, pairs[1])
}

func TestHarvestSignaturesFromBody_NoContent(t *testing.T) {
	require.Empty(t, HarvestSignaturesFromBody([]byte(`{"stop_reason":"end_turn"}`)))
	require.Empty(t, HarvestSignaturesFromBody(nil))
}

func TestStreamThinkingAccumulator_FeedRegistersOnSignatureDelta(t *testing.T) {
	ctx := context.Background()
	reg := NewSignatureRegistry(nil)

	acc := newStreamThinkingAccumulator()
	acc.bindRegistry(reg, 99, "claude-opus-5")

	// thinking_delta 分片累积
	acc.Feed(ctx, []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"Hello "}}`))
	acc.Feed(ctx, []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"world"}}`))
	// signature_delta 触发登记
	acc.Feed(ctx, []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"STREAM_SIG"}}`))

	require.True(t, reg.IsWarm(ctx))
	require.True(t, reg.Contains(ctx, 99, "claude-opus-5", SignaturePairFingerprint("STREAM_SIG", "Hello world")))
}

func TestRegisterHarvestedSignatures_RespectsSettingAndCtx(t *testing.T) {
	ctx := context.Background()
	body := []byte(`{"content":[{"type":"thinking","thinking":"t","signature":"S"}]}`)

	// 开关关闭（默认）→ 不登记
	InitSignatureRegistry(nil)
	ssOff := NewSettingService(&settingRepoStub{values: map[string]string{}}, nil)
	RegisterHarvestedSignatures(withSigRegCtx(ctx), ssOff, body)
	require.False(t, GetSignatureRegistry().IsWarm(ctx), "disabled setting must not register")

	// 开关开启 + ctx 携带 userID/model → 登记
	InitSignatureRegistry(nil)
	ssOn := NewSettingService(&settingRepoStub{values: map[string]string{SettingKeyThinkingSignatureRegistry: "true"}}, nil)
	RegisterHarvestedSignatures(withSigRegCtx(ctx), ssOn, body)
	require.True(t, GetSignatureRegistry().IsWarm(ctx), "enabled setting must register")
	require.True(t, GetSignatureRegistry().Contains(ctx, 55, "claude-opus-5", SignaturePairFingerprint("S", "t")))
}

func withSigRegCtx(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, ctxkey.UserID, int64(55))
	ctx = context.WithValue(ctx, ctxkey.Model, "claude-opus-5")
	return ctx
}
