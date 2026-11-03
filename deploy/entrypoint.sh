#!/bin/sh
# AtomCode2api 容器入口：种子账号导入 + 启动。
#
# /seed 只读挂载（宿主机 deploy/seed-accounts/），启动时把其中的
# *.toml / *.json 拷进 $STATE_DIR/import/（可写卷），网关的扫描导入会
# 消费它们（成功移入 import/imported/）。重启时种子会再拷一遍，
# 但 RT 查重会判重跳过，不会重复建账号。
set -eu
STATE_DIR="${STATE_DIR:-/app/data}"
if [ -d /seed ]; then
  mkdir -p "$STATE_DIR/import"
  for f in /seed/*.toml /seed/*.json; do
    [ -e "$f" ] || continue
    cp "$f" "$STATE_DIR/import/" 2>/dev/null || true
  done
fi
exec /app/atomcode2api "$@"
