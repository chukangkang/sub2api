#!/usr/bin/env bash
# 编译 Linux release 版 sub2api（嵌入前端，静态链接）
#
# 用法（在 WSL 或 Linux 中）:
#   cd backend && ./scripts/build-linux.sh
#
# 可选环境变量:
#   VERSION=0.2.7          手动指定版本号（默认走 resolve-version.sh）
#   LICENSE_PUBLIC_KEY=... 手动指定公钥（默认用内置值）
#   OUT=bin/sub2api        输出路径
set -euo pipefail

cd "$(dirname "$0")/.."   # -> backend/

VERSION=${VERSION:-$(./scripts/resolve-version.sh)}
LICENSE_PUBLIC_KEY=${LICENSE_PUBLIC_KEY:-"qnmdBw9L6pEU7QLuiHvbDk-va7XOLDdljDjVGUOJr-M"}   # 64字节公钥
OUT=${OUT:-bin/sub2api}

# 前置检查：embed 需要前端产物
if [ ! -d internal/web/dist ]; then
  echo "ERROR: internal/web/dist 不存在，请先构建前端:" >&2
  echo "  cd ../frontend && pnpm install && pnpm build && cp -r dist ../backend/internal/web/" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"

CGO_ENABLED=0 go build \
  -tags=embed \
  -trimpath \
  -ldflags="-s -w \
    -X main.Version=${VERSION} \
    -X main.Commit=$(git rev-parse --short HEAD) \
    -X main.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
    -X main.BuildType=release \
    -X main.LicensePublicKey=${LICENSE_PUBLIC_KEY}" \
  -o "$OUT" ./cmd/server

echo "built: $OUT ($(du -h "$OUT" | cut -f1)), version=${VERSION}"
