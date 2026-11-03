#!/bin/sh
# 交叉编译 Linux 发布产物（CGO_ENABLED=0 静态二进制，amd64 + arm64）。
# 用法：sh deploy/build-release.sh [版本号]   → dist/atomcode2api-linux-{amd64,arm64}.tar.gz
set -eu
cd "$(dirname "$0")/.."
VERSION="${1:-dev}"
mkdir -p dist
for TARGET in "linux amd64" "linux arm64"; do
  set -- $TARGET
  GOOS="$1"
  GOARCH="$2"
  OUT="dist/atomcode2api-${GOOS}-${GOARCH}"
  echo "==> ${OUT} (version=${VERSION})"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -ldflags="-s -w" -o "$OUT" .
  tar czf "${OUT}.tar.gz" -C dist "atomcode2api-${GOOS}-${GOARCH}"
done
echo "完成：ls dist/"
