#!/usr/bin/env bash
# 构建扫描节点镜像——正规 Dockerfile 路径，替代之前的 docker commit。
#
# 为什么要换掉 docker commit：commit 会把容器可写层整层打包，包括 /apps/data 里的
# pebbledb、日志、临时文件，镜像从 2.94GB 涨到 4.63GB，而且不可复现——
# 同一份代码在不同时间提交出来的镜像内容不同。
#
# 用法：
#   scripts/build-image.sh                 # 用 git sha + 时间戳打 tag
#   scripts/build-image.sh mytag:1.0       # 指定 tag
#   REBUILD=0 scripts/build-image.sh       # 复用已编译好的二进制（CI 里分阶段构建用）
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

SHA=$(git rev-parse --short HEAD 2>/dev/null || echo nogit)
TS=$(date +%Y%m%d-%H%M)
TAG=${1:-scopesentry-scan-jp:docker-${SHA}-${TS}}
BIN_DIR=dist/ScopeSentry-Scan_linux_amd64_v1
BIN=$BIN_DIR/ScopeSentry-Scan

if [ "${REBUILD:-1}" = "1" ] || [ ! -x "$BIN" ]; then
  echo "== [1/2] 编译 linux/amd64 二进制 =="
  mkdir -p "$BIN_DIR"
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags "-s -w" -o "$BIN" ./cmd/ScopeSentry/main.go
else
  echo "== [1/2] 复用已有二进制：$BIN =="
  ls -la "$BIN"
fi

echo "== [2/2] docker build -> $TAG =="
docker build -f dockerfile -t "$TAG" .

echo "== 完成 =="
docker images "$TAG" --format "{{.Repository}}:{{.Tag}}  {{.Size}}"
echo
echo "切换 compose 指向该镜像：须先 docker cp 冒烟通过再改。"
