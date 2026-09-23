# Fork 同步与功能分支维护指南

> 适用对象：`chukangkang/sub2api`（fork）相对上游 `Wei-Shaw/sub2api` 的自有功能分支。
> 本文档描述如何在上游持续更新时，低成本地把自有功能同步到新版本基线上。
> 最后更新：2026-09-23

## 1. 仓库与远程布局

| 远程 | 地址 | 用途 |
|---|---|---|
| `origin` | https://github.com/chukangkang/sub2api.git | 自己的 fork，日常推送目标 |
| `upstream` | https://github.com/Wei-Shaw/sub2api.git | 原始仓库，版本源头 |

### 分支角色

| 分支 | 基点 | 状态 |
|---|---|---|
| `main` | 始终跟随 `upstream/main` | 只接受 fast-forward，不做本地提交 |
| `anthropic-api-style-v0.2.4` | 0.2.4（分叉点 `bdb42e2`） | **存档分支**，不再更新，仅作移植来源参照 |
| `anthropic-api-style-v0.2.7` | 上游最新 main（≥ v0.2.7） | **活跃功能分支**，承载全部自有功能 |

### 分支命名约定

`anthropic-api-style-v<基础版本号>`，后缀是该分支所基于的上游版本（不是下一个发布版本）。
例：基于 v0.2.7 之后的 main → `anthropic-api-style-v0.2.7`；下次上游出 v0.2.8 后重建 → `anthropic-api-style-v0.2.8`。

## 2. 自有功能清单（当前在 v0.2.7 分支上）

| 功能 | 主要文件 | 备注 |
|---|---|---|
| License 机器码绑定 | `backend/cmd/server/main.go` | ed25519 校验（`-sn` 参数）、`-machine-code` 打印注册码、DMI 四项标识必填、内置 `LicensePublicKey`。**只动这一个文件**，是与上游冲突的唯一高风险点 |
| Anthropic `/v1/messages` 官方对齐 | `backend/internal/handler/gateway_anthropic_validation*.go`、`gateway_handler.go`、`openai_gateway_handler*.go`、`backend/internal/pkg/claude/constants.go`、`backend/internal/service/{domain_constants,setting_features}.go` | 请求校验、thinking 签名校验、max_tokens 上限表、错误 wire 类型对齐 |
| 杂项 | `.gitignore`（`backend/sub2api-linux*`）、`frontend/package.json`（pnpm `onlyBuiltDependencies`） | 低冲突风险 |

> 原则：**每个功能尽量收敛在自己的文件集合内**，这样 rebase 冲突面可控、可按功能独立提 PR。

## 3. 常规更新流程（上游出了新版本 / main 前进后）

### 3.1 同步 main

```powershell
git fetch upstream --tags --force
git checkout main
git merge --ff-only upstream/main   # 必须是 ff，否则说明 main 被污染，需排查
git push origin main
```

### 3.2 功能分支 rebase

```powershell
git checkout anthropic-api-style-v0.2.7
git rebase main
```

预期冲突点（按概率排序）：

1. **`backend/cmd/server/main.go`**（license 区）
   - 上游改了 import 区 / `var (...)` 构建变量区 / `main()` 开头的 flag 解析时必冲突。
   - 解决口诀：保留上游的新增内容 + 叠加 license 的四块代码：
     - import：`crypto/ed25519`、`crypto/sha256`、`encoding/base64`、`encoding/hex`、`fmt`
     - `var` 块：`LicensePublicKey` 常量
     - `const` 块 + `licenseIdentity` 结构体
     - `main()` 中 `-machine-code` / `-sn` flag 及其处理逻辑
     - 文件尾部的 license 函数群（`verifyLicense` … `isASCIISpace`）
2. **`backend/internal/handler/*.go`**（Anthropic 对齐区）
   - 常见于 `gateway_handler.go`、`openai_gateway_handler.go` 的同区域并行修改。
   - 解决原则：以上游新逻辑为底，把校验调用点（validate 入口、request_id 对齐、错误类型映射）重新挂回去。
3. **wire 相关文件**（`backend/cmd/server/wire.go`、`wire_gen.go`）
   - 若上游改了 DI 图，rebase 后需重新生成：`cd backend && go generate ./cmd/server`（wire）。
4. **测试文件**：多为「双方都在文件尾部追加测试」型冲突，两边都保留即可。

### 3.3 验证（每次 rebase 后必做）

```powershell
cd backend
go build ./...
go test -tags unit ./internal/handler/ ./internal/server/routes/ ./internal/pkg/claude/ -count=1
go test -tags unit ./internal/service/ -count=1
```

注意事项：
- `internal/service` 整包跑存在**上游预存的 flaky 测试**（`TestOllamaProbeCallback_StaleLongDoesNotOverrideNewShort`、`TestRecordCyberPolicyEvent_RuntimeSnapshotRefreshFailureKeepsStaleScope`，时序/CAS 敏感）。判定时先在纯净 `main` 上整包跑一遍作对照，失败集合相同即为预存问题，不算回归。
- Windows 下 Go 环境与坑见 `docs/FORK_SYNC_WORKFLOW.md` §5 与仓库记忆 `build-env.md`。

### 3.4 推送

```powershell
git push --force-with-lease origin anthropic-api-style-v0.2.7
```

rebase 改写历史，必须强推；用 `--force-with-lease` 防覆盖他人提交。

### 3.5 提 PR

- 每个功能独立一个 PR（license 一个、Anthropic 对齐一个），便于上游风格审查与回滚。
- PR 目标：`chukangkang/sub2api:main`。

## 4. 大版本跳跃时的重建流程（可选，替代长期 rebase）

当上游跨度太大（数百提交）、rebase 成本高于重建时：

1. 新建分支：`git checkout -b anthropic-api-style-v<新版本> main`
2. **License 功能**：取旧分支 license 提交的净 diff 应用
   ```powershell
   # 假设旧分支 license 区间为 A..B（只动 main.go）
   cmd /c "git diff A^..B -- backend\cmd\server\main.go > tmp_license.patch"
   git apply -3 tmp_license.patch   # 有冲突则手工按 §3.2-1 口诀解决
   git add backend/cmd/server/main.go
   git commit -m "feat(license): ..."
   ```
3. **其余功能**：`git cherry-pick <提交列表>`（按时间序），逐个解冲突。
4. 验证（§3.3）→ 强推新分支 → 旧分支留档。

> 2026-09-23 的 v0.2.4 → v0.2.7 迁移就是按本节执行的，全程仅 2 处实质冲突（main.go license 区、一个测试文件尾部追加）。

## 5. Windows 环境备忘

- Go 1.27.0 临时 SDK：`%TEMP%\gosdk-parent\go`（`tar -xf` 解压，勿用 Expand-Archive）；
  损坏特征 `package unsafe is not in std` → 重新下载解压，验证 `Test-Path "%TEMP%\gosdk-parent\go\src\unsafe\unsafe.go"`。
- 环境变量：`$env:GOROOT`、`$env:GOPATH="%TEMP%\gopath"`、`$env:GOPROXY="https://goproxy.cn,direct"`（proxy.golang.org 直连不通）。
- **PowerShell 编码陷阱**：`git diff ... > file` 会写成 UTF-16 导致 `git apply` 报 corrupt patch；
  一律用 `cmd /c "git diff ... > file"`。管道 `git diff | git apply` 同样会被 PS 编码破坏。
- 终端 cwd 可能在 `backend/` 或仓库根之间漂移，git 路径报错（`did not match any files`）时先 `pwd` 确认。

## 6. 快速检查清单（每次更新照做）

- [ ] `git fetch upstream --tags --force`
- [ ] `main` fast-forward 到 `upstream/main` 并推送 origin
- [ ] 功能分支 `git rebase main`（或按 §4 重建）
- [ ] 冲突解决后 `go build ./...` 通过
- [ ] 四组单元测试通过（flaky 对照法排除预存失败）
- [ ] `git push --force-with-lease`
- [ ] 按功能拆分 PR
