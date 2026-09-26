package service

// 本文件实现 thinking 签名发放注册表
// （docs/ANTHROPIC_MESSAGES_VALIDATION_SPEC.md §2.5b）。
//
// 背景：§2.5 的结构+深度指纹校验对"密文主体内部单字符篡改"无效（签名是
// 密钥化 MAC，无 Anthropic 私钥不可真验签）。注册表用"只认自己见过的签名"
// 补齐这一环：
//
//   - 登记侧：上游 200 响应中出现 thinking/redacted_thinking 签名即登记
//     （非流式 Content[] 块；流式 signature_delta 事件；兜底 content_block_start）。
//   - 配对绑定：Anthropic 的签名覆盖 thinking 内容本身，因此 thinking 块不按
//     裸签名而是按配对指纹记账：
//     SignaturePairFingerprint(sig, thinking) = hex(sha256(sig ‖ "\x00" ‖ thinking))
//     拿到真签名但换了 thinking 文本（换绑攻击）也会因指纹不匹配而被拒。
//     redacted_thinking 无可见文本，仍按裸签名记账。
//   - 校验侧：结构校验通过后，若开关开启，要求签名命中注册表，否则 400
//     "signature not recognized"。
//   - 冷启动宽限：全局"热标记"（24h TTL，每次登记刷新）。标记不存在或已过期
//     → 冷态 → 成员检查 fail-open，只做结构校验；进入热态后，一切未命中
//     （含其他用户/模型的空桶）都是拒绝——堵住跨用户重放。
//
// 存储：优先 Redis（anthropic:sigreg:<uid>:<model> hash + 24h TTL +
// anthropic:sigreg:warm 热标记）；未启用 Redis 降级进程内 map（桶上限 4096、
// 每桶签名上限 512）。存储异常只记日志，不影响转发。
//
// 配置开关：settings 键 thinking_signature_registry，默认关（仅显式 "true"
// 开启）——它是增强校验，开启前需确认客户端签名均来自本网关转发的上游响应。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tidwall/gjson"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

// 注册表容量与 TTL 常量。
const (
	sigRegBucketTTL        = 24 * time.Hour
	sigRegWarmTTL          = 24 * time.Hour
	sigRegMaxBuckets       = 4096 // 进程内降级：最多多少个 (uid, model) 桶
	sigRegMaxPerBucket     = 512  // 进程内降级：每桶最多多少条签名
	sigRegRedisKeyPrefix   = "anthropic:sigreg:"
	sigRegRedisWarmKey     = "anthropic:sigreg:warm"
	sigRegRedisMemberTTLMS = int64(24 * time.Hour / time.Millisecond)
)

// SignaturePairFingerprint 计算签名↔thinking 文本的配对指纹：
// hex(sha256(sig ‖ "\x00" ‖ thinking))。thinking 为空（redacted_thinking）
// 时退化为裸签名指纹 hex(sha256(sig))。
func SignaturePairFingerprint(sig, thinking string) string {
	h := sha256.Sum256([]byte(sig))
	if thinking != "" {
		h = sha256.Sum256(append(append([]byte(hex.EncodeToString(h[:])), 0), []byte(thinking)...))
	}
	return hex.EncodeToString(h[:])
}

// SignatureRegistry 是 thinking 签名发放注册表。
// nil 指针表示未启用（所有方法 nil-safe）。
type SignatureRegistry struct {
	rdb *redis.Client

	mu     sync.Mutex
	buckets map[string]map[string]int64 // key(uid\x00model) → fingerprint → 登记时间(unix ms)
}

// NewSignatureRegistry 创建注册表。rdb 为 nil 时使用进程内 map 降级。
func NewSignatureRegistry(rdb *redis.Client) *SignatureRegistry {
	return &SignatureRegistry{
		rdb:     rdb,
		buckets: make(map[string]map[string]int64),
	}
}

var (
	globalSigRegistryMu sync.RWMutex
	globalSigRegistry   *SignatureRegistry
)

// InitSignatureRegistry 初始化全局注册表单例（由 wire 注入 Redis 后调用一次）。
// 幂等：重复调用以最后一次为准。
func InitSignatureRegistry(rdb *redis.Client) *SignatureRegistry {
	reg := NewSignatureRegistry(rdb)
	globalSigRegistryMu.Lock()
	globalSigRegistry = reg
	globalSigRegistryMu.Unlock()
	return reg
}

// GetSignatureRegistry 返回全局注册表单例（未初始化时为 nil，nil-safe）。
func GetSignatureRegistry() *SignatureRegistry {
	globalSigRegistryMu.RLock()
	defer globalSigRegistryMu.RUnlock()
	return globalSigRegistry
}

func sigRegBucketKey(userID int64, model string) string {
	return strconv.FormatInt(userID, 10) + "\x00" + model
}

// Register 登记一批来自上游 200 响应的签名。
// pairs 是 (签名, thinking 文本) 对；thinking 为空表示 redacted_thinking。
// 存储异常只记日志，不返回错误（不影响转发）。
func (r *SignatureRegistry) Register(ctx context.Context, userID int64, model string, pairs [][2]string) {
	if r == nil || userID <= 0 || strings.TrimSpace(model) == "" || len(pairs) == 0 {
		return
	}
	now := time.Now().UnixMilli()
	fingerprints := make([]string, 0, len(pairs))
	seen := make(map[string]struct{}, len(pairs))
	for _, p := range pairs {
		if p[0] == "" {
			continue
		}
		fp := SignaturePairFingerprint(p[0], p[1])
		if _, dup := seen[fp]; dup {
			continue
		}
		seen[fp] = struct{}{}
		fingerprints = append(fingerprints, fp)
	}
	if len(fingerprints) == 0 {
		return
	}

	if r.rdb != nil {
		key := sigRegRedisKeyPrefix + strconv.FormatInt(userID, 10) + ":" + model
		fields := make(map[string]interface{}, len(fingerprints))
		for _, fp := range fingerprints {
			fields[fp] = now
		}
		pipe := r.rdb.Pipeline()
		pipe.HSet(ctx, key, fields)
		pipe.Expire(ctx, key, sigRegBucketTTL)
		pipe.Set(ctx, sigRegRedisWarmKey, "1", sigRegWarmTTL)
		if _, err := pipe.Exec(ctx); err != nil {
			logger.LegacyPrintf("service.sigreg", "register redis failed uid=%d model=%s: %v", userID, model, err)
			return
		}
		return
	}

	// 进程内降级
	r.mu.Lock()
	defer r.mu.Unlock()
	bucket, ok := r.buckets[sigRegBucketKey(userID, model)]
	if !ok {
		if len(r.buckets) >= sigRegMaxBuckets {
			// 粗淘汰：清空一半桶（登记是低频事件，精度不重要）
			n := 0
			for k := range r.buckets {
				delete(r.buckets, k)
				if n++; n >= len(r.buckets)/2 {
					break
				}
			}
			bucket = make(map[string]int64)
		} else {
			bucket = make(map[string]int64)
		}
		r.buckets[sigRegBucketKey(userID, model)] = bucket
	}
	for _, fp := range fingerprints {
		if len(bucket) >= sigRegMaxPerBucket {
			// 桶满：清掉最老的一半后继续
			cutoff := now - int64(sigRegBucketTTL/time.Millisecond/2)
			for k, ts := range bucket {
				if ts < cutoff {
					delete(bucket, k)
				}
			}
			if len(bucket) >= sigRegMaxPerBucket {
				return
			}
		}
		bucket[fp] = now
	}
}

// IsWarm 返回注册表是否处于热态（近期有过登记）。
// Redis 模式下热标记缺失/过期 → 冷态；进程内模式下有任何桶 → 热态。
func (r *SignatureRegistry) IsWarm(ctx context.Context) bool {
	if r == nil {
		return false
	}
	if r.rdb != nil {
		val, err := r.rdb.Get(ctx, sigRegRedisWarmKey).Result()
		if err != nil {
			return false
		}
		return val == "1"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets) > 0
}

// Contains 检查 (userID, model) 桶中是否存在给定指纹。
// 桶不存在（其他用户/模型的空桶）返回 false。
func (r *SignatureRegistry) Contains(ctx context.Context, userID int64, model string, fingerprint string) bool {
	if r == nil || userID <= 0 || strings.TrimSpace(model) == "" || fingerprint == "" {
		return false
	}
	if r.rdb != nil {
		key := sigRegRedisKeyPrefix + strconv.FormatInt(userID, 10) + ":" + model
		exists, err := r.rdb.HExists(ctx, key, fingerprint).Result()
		if err != nil {
			logger.LegacyPrintf("service.sigreg", "contains redis failed uid=%d model=%s: %v", userID, model, err)
			return false
		}
		return exists
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	bucket, ok := r.buckets[sigRegBucketKey(userID, model)]
	if !ok {
		return false
	}
	_, ok = bucket[fingerprint]
	return ok
}

// HarvestSignaturesFromBody 从非流式 Anthropic 200 响应体收割
// thinking/redacted_thinking 块的 (signature, thinking) 对。
func HarvestSignaturesFromBody(body []byte) [][2]string {
	var pairs [][2]string
	content := gjson.GetBytes(body, "content")
	if !content.IsArray() {
		return pairs
	}
	for _, block := range content.Array() {
		btype := block.Get("type").Str
		if btype != "thinking" && btype != "redacted_thinking" {
			continue
		}
		sig := block.Get("signature").Str
		if sig == "" {
			continue
		}
		text := ""
		if btype == "thinking" {
			text = block.Get("thinking").Str
		}
		pairs = append(pairs, [2]string{sig, text})
	}
	return pairs
}

// streamThinkingAccumulator 按 content block index 累积流式 thinking 文本，
// 直到 signature_delta 到达时取出完整 (signature, thinking) 对。
type streamThinkingAccumulator struct {
	mu       sync.Mutex
	thinking map[int]*strings.Builder

	reg    *SignatureRegistry
	userID int64
	model  string
}

func newStreamThinkingAccumulator() *streamThinkingAccumulator {
	return &streamThinkingAccumulator{thinking: make(map[int]*strings.Builder)}
}

// bindRegistry 绑定登记上下文；未绑定时 Feed 只做观察不登记。
func (a *streamThinkingAccumulator) bindRegistry(reg *SignatureRegistry, userID int64, model string) {
	a.reg = reg
	a.userID = userID
	a.model = model
}

// Feed 供流式泵逐条 SSE data 行调用：累积 thinking_delta，并在
// signature_delta 到达时登记 (signature, thinking) 对。
func (a *streamThinkingAccumulator) Feed(ctx context.Context, data []byte) {
	if a == nil {
		return
	}
	a.observe(data)
	if a.reg == nil {
		return
	}
	_, sig, thinking, ok := a.ObserveStreamSignatureEvent(data)
	if !ok {
		return
	}
	a.reg.Register(ctx, a.userID, a.model, [][2]string{{sig, thinking}})
}

// observe 解析一条 SSE data 行（JSON），累积 thinking_delta 文本。
func (a *streamThinkingAccumulator) observe(data []byte) {
	ev := gjson.GetBytes(data, "type").Str
	if ev != "content_block_delta" {
		return
	}
	idxVal := gjson.GetBytes(data, "index")
	deltaType := gjson.GetBytes(data, "delta.type").Str
	if deltaType != "thinking_delta" || !idxVal.Exists() {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	idx := int(idxVal.Int())
	b, ok := a.thinking[idx]
	if !ok {
		b = &strings.Builder{}
		a.thinking[idx] = b
	}
	b.WriteString(gjson.GetBytes(data, "delta.thinking").Str)
}

// takeSignature 在 signature_delta 到达时取出该 index 的累积文本并清除。
func (a *streamThinkingAccumulator) takeSignature(index int) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.thinking[index]
	if !ok {
		return ""
	}
	delete(a.thinking, index)
	return b.String()
}

// ObserveStreamSignatureEvent 解析流式 SSE data 行，若为 signature_delta 则
// 返回 (index, signature, 累积的 thinking 文本)；否则返回 ok=false。
func (acc *streamThinkingAccumulator) ObserveStreamSignatureEvent(data []byte) (index int, sig, thinking string, ok bool) {
	if gjson.GetBytes(data, "type").Str != "content_block_delta" {
		return 0, "", "", false
	}
	if gjson.GetBytes(data, "delta.type").Str != "signature_delta" {
		return 0, "", "", false
	}
	idxVal := gjson.GetBytes(data, "index")
	if !idxVal.Exists() {
		return 0, "", "", false
	}
	sig = gjson.GetBytes(data, "delta.signature").Str
	if sig == "" {
		return 0, "", "", false
	}
	index = int(idxVal.Int())
	thinking = acc.takeSignature(index)
	return index, sig, thinking, true
}

// RegisterFromStreamEvents 供流式泵调用：observe 累积 + signature_delta 收割。
// 返回收割到的 (signature, thinking) 对（通常 0 或 1 个）。
func (acc *streamThinkingAccumulator) RegisterFromStreamEvents(reg *SignatureRegistry, ctx context.Context, userID int64, model string, data []byte) {
	acc.observe(data)
	_, sig, thinking, ok := acc.ObserveStreamSignatureEvent(data)
	if !ok || reg == nil {
		return
	}
	reg.Register(ctx, userID, model, [][2]string{{sig, thinking}})
}

// RegisterHarvestedSignatures 是登记侧的统一入口（§2.5b）：
// 开关开启时，从上游 200 响应体收割 thinking/redacted_thinking 签名并按
// (userID, 客户端视角模型名) 登记。任何一步不满足条件都静默跳过，
// 绝不影响主流程。
//
// userID 取自 ctxkey.UserID（API Key 认证中间件设置）；model 优先取
// ctxkey.Model（handler 在 setOpsRequestContext 设置的客户端请求模型），
// 保证与校验侧的桶键一致。
func RegisterHarvestedSignatures(ctx context.Context, settingService *SettingService, body []byte) {
	if settingService == nil || !settingService.IsThinkingSignatureRegistryEnabled(ctx) {
		return
	}
	reg := GetSignatureRegistry()
	if reg == nil {
		return
	}
	userID, _ := ctx.Value(ctxkey.UserID).(int64)
	model, _ := ctx.Value(ctxkey.Model).(string)
	if userID <= 0 || strings.TrimSpace(model) == "" {
		return
	}
	pairs := HarvestSignaturesFromBody(body)
	if len(pairs) == 0 {
		return
	}
	reg.Register(ctx, userID, model, pairs)
}
