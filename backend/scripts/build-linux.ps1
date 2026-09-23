# 在 Windows PowerShell 中交叉编译 Linux release 版 sub2api（嵌入前端，静态链接）
#
# 用法:
#   cd E:\sd\sub2api\backend; .\scripts\build-linux.ps1
#
# 可选参数:
#   -Version 0.2.7              手动指定版本号（默认读 cmd/server/VERSION）
#   -LicensePublicKey <key>     手动指定公钥（默认用内置值）
#   -Out bin\sub2api            输出路径
param(
    [string]$Version = "",
    [string]$LicensePublicKey = "qnmdBw9L6pEU7QLuiHvbDk-va7XOLDdljDjVGUOJr-M",
    [string]$Out = "bin\sub2api"
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")   # -> backend/

# Go 环境（临时 SDK，见 docs/FORK_SYNC_WORKFLOW.md §5）
$env:GOROOT = "$env:TEMP\gosdk-parent\go"
$env:GOPATH = "$env:TEMP\gopath"
$env:PATH = "$env:GOROOT\bin;$env:PATH"
$env:GOPROXY = "https://goproxy.cn,direct"

# 交叉编译目标
$env:CGO_ENABLED = "0"
$env:GOOS = "linux"
$env:GOARCH = "amd64"

if ([string]::IsNullOrEmpty($Version)) {
    $Version = (Get-Content cmd/server/VERSION).Trim()
}

# 前置检查：embed 需要前端产物
if (-not (Test-Path internal/web/dist)) {
    Write-Error "internal/web/dist 不存在，请先构建前端: cd ..\frontend; pnpm install; pnpm build; Copy-Item -Recurse dist ..\backend\internal\web\"
}

New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
$commit = git rev-parse --short HEAD
$date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

go build -tags=embed -trimpath `
    "-ldflags=-s -w -X main.Version=$Version -X main.Commit=$commit -X main.Date=$date -X main.BuildType=release -X main.LicensePublicKey=$LicensePublicKey" `
    -o $Out ./cmd/server

if ($LASTEXITCODE -ne 0) { throw "go build failed" }

# 校验 ELF 魔数（7F 45），防止漏设 GOOS 编成 PE
$bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $Out))[0..1]
$magic = "{0:X2} {1:X2}" -f $bytes[0], $bytes[1]
if ($magic -ne "7F 45") { throw "unexpected binary magic: $magic (expect 7F 45 ELF)" }

Write-Host "built: $Out ($('{0:N1} MB' -f ((Get-Item $Out).Length / 1MB))), version=$Version"
