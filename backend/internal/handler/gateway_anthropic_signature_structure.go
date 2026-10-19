package handler

// 本文件实现 thinking 签名的第 2 层（骨架校验），
// 对齐 docs/ANTHROPIC_MESSAGES_VALIDATION_SPEC.md §2.5 / §2.5a。
//
// 沿革：原第 3 层“深度指纹”（元数据尺寸/"thinking" 常量/UUID/模型名一致）
// 已于 2026-10-19 移除——渠道模型映射或会话中途切换模型时，合法的历史签名
// 会被误判为跨模型重放，导致 Claude Code 等长历史客户端大量 400。
// 跨模型重放的防御交由可选的签名发放注册表（§2.5b）承担。
//
// 背景（2026-09-21 五份真实样本逆向结论）：
//
//	signature base64 解码后是嵌套 protobuf：
//
//	outer
//	├─ field1  varint = 2            版本标记（★ 非恒定：sonnet-5 / 早期 opus-4-8
//	│                                 样本外层直接从 field2 起，无此字段）
//	├─ field2  bytes = inner         内层容器（占绝大部分）
//	│   ├─ field1  bytes(~168)       元数据容器（明文区）：模型名 ASCII +
//	│   │                             "thinking" 常量 + 每次签发变化的标准 UUID
//	│   ├─ field2  bytes(12)         签发时间戳①（LE64 ≈ unix 秒）
//	│   ├─ field3  bytes(12)         签发时间戳②
//	│   ├─ field4  bytes(48)         中熵块（疑似 MAC 分量）
//	│   └─ field5  bytes(1.1k~4.3k)  AEAD 密文主体（长度 ∝ thinking 文本长度）
//	└─ field3  varint = 1            尾随标记
//
// 签名是密钥化 MAC，无 Anthropic 私钥不可真验签；本层是纯结构校验：
// 骨架层拦"头部/tag 区篡改"（首字节等）——tag 损坏使外层解析失败或 field2 丢失。
//
// 骨架层只作用于 type=thinking 块；redacted_thinking 的签名结构尚未取样确认，
// 只做第 1 层（base64+长度），避免误杀。

import (
	"encoding/base64"
	"errors"
)

// thinkingSigMalformed 是骨架层的统一失败文案（逐字对齐官方风格）。
const thinkingSigMalformed = "Invalid `signature` in `thinking` block: signature is malformed"

// decodeSignatureBase64 解码签名 base64（StdEncoding 优先，失败再试 URLEncoding）。
// 容忍边界与第 1 层一致：只接受带 padding 的两种编码（RawStd/RawURL 曾尝试并已回滚）。
func decodeSignatureBase64(sig string) ([]byte, bool) {
	if decoded, err := base64.StdEncoding.DecodeString(sig); err == nil {
		return decoded, true
	}
	if decoded, err := base64.URLEncoding.DecodeString(sig); err == nil {
		return decoded, true
	}
	return nil, false
}

// pbField 是一个极简 protobuf wire-format 字段。
type pbField struct {
	fieldNum int32
	wireType int32
	data     []byte // wire type 0/1 时为 varint/64-bit 值的原始字节
}

// parseProtoFields 极简 protobuf 解析：完整消费 buf，返回字段序列。
// 任一位置出现坏 tag / 越界 / 长度不符即返回 false（视为 malformed）。
// 不识别的 wire type 一律拒绝——真实签名只用 0(varint)/2(bytes)。
func parseProtoFields(buf []byte) ([]pbField, bool) {
	var fields []pbField
	pos := 0
	for pos < len(buf) {
		tag, n := protoDecodeVarint(buf[pos:])
		if n <= 0 {
			return nil, false
		}
		pos += n
		fn := int32(tag >> 3)
		wt := int32(tag & 0x7)
		if fn <= 0 || wt > 5 {
			return nil, false
		}
		switch wt {
		case 0: // varint
			_, n := protoDecodeVarint(buf[pos:])
			if n <= 0 {
				return nil, false
			}
			fields = append(fields, pbField{fieldNum: fn, wireType: wt, data: buf[pos : pos+n]})
			pos += n
		case 1: // 64-bit
			if pos+8 > len(buf) {
				return nil, false
			}
			fields = append(fields, pbField{fieldNum: fn, wireType: wt, data: buf[pos : pos+8]})
			pos += 8
		case 2: // length-delimited
			l, n := protoDecodeVarint(buf[pos:])
			if n <= 0 || l < 0 || pos+n+int(l) > len(buf) {
				return nil, false
			}
			pos += n
			fields = append(fields, pbField{fieldNum: fn, wireType: wt, data: buf[pos : pos+int(l)]})
			pos += int(l)
		case 5: // 32-bit
			if pos+4 > len(buf) {
				return nil, false
			}
			fields = append(fields, pbField{fieldNum: fn, wireType: wt, data: buf[pos : pos+4]})
			pos += 4
		default: // wire type 3/4（group start/end）不出现在扁平结构中
			return nil, false
		}
	}
	return fields, true
}

// protoDecodeVarint 解码一个 varint，返回值与消耗的字节数（0 表示失败）。
func protoDecodeVarint(buf []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(buf) && i < 10; i++ {
		b := buf[i]
		v |= uint64(b&0x7f) << (7 * uint(i))
		if b&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}

// checkThinkingSignatureStructure 执行第 2 层（骨架）校验。
// 调用前提：sig 已通过第 1 层（合法 base64 且解码 ≥32 字节）。
//
// 骨架层：外层良构（可完整消费、无坏 tag/越界），且含 field2（wire 2）且其内容
// 本身良构；外层 field1 版本标记非必需（部分真签名没有）。首字节篡改仍可拦
// （tag 损坏使外层解析失败或 field2 丢失）。
//
// 历史：原第 3 层“深度指纹”（元数据/密文尺寸 + "thinking" 常量 + UUID + 模型名
// 一致）已于 2026-10-19 移除——渠道模型映射或会话中途切换模型时，合法的历史
// 签名会被误判为跨模型重放（Claude Code 长历史会话大量 400）；跨模型重放防御
// 交由可选的签名发放注册表（§2.5b，异模型桶未命中 → not recognized）。
func checkThinkingSignatureStructure(sig string) error {
	decoded, ok := decodeSignatureBase64(sig)
	if !ok {
		return errors.New(thinkingSigMalformed)
	}

	// ── 第 2 层：骨架 ──
	outer, ok := parseProtoFields(decoded)
	if !ok {
		return errors.New(thinkingSigMalformed)
	}
	var inner []byte
	foundInner := false
	for _, f := range outer {
		if f.fieldNum == 2 && f.wireType == 2 {
			inner = f.data
			foundInner = true
		}
	}
	if !foundInner {
		return errors.New(thinkingSigMalformed)
	}
	if _, ok := parseProtoFields(inner); !ok {
		return errors.New(thinkingSigMalformed)
	}
	return nil
}

