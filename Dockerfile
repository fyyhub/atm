# AtomCode2api 镜像：多阶段构建、非 root 运行、可写状态卷。
#
# 部署缺陷修复说明（2026-11-03）：
#   1. 旧版 /app 整目录 chmod 555 只读，StateDir=exe 目录写不进
#      server.log / accounts/ / pool-state.json —— 现拆为 /app 只读（二进制）
#      + /app/data 可写（0700, appuser），并用 ENV STATE_DIR=/app/data 显式指定。
#   2. 旧 compose 注释声称凭据经 -auth 挂到 /app/data/auth.toml，但 CMD 没传
#      -auth，容器实际找未挂载的 ~/.atomcode/auth.toml —— 现改为种子导入：
#      entrypoint 把只读挂载的 /seed/*.{toml,json} 拷进 STATE_DIR/import/，
#      由网关扫描导入（accounts/ 持久化在 data 卷，重启不重复导入）。
FROM golang:1.24-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /build
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w" -o atomcode2api .

FROM alpine:3.21
RUN apk --no-cache add ca-certificates wget \
    && adduser -D -u 10001 appuser
WORKDIR /app
COPY --from=builder /build/atomcode2api .
COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod 555 /app/atomcode2api && chmod 755 /entrypoint.sh \
    && mkdir -p /app/data && chown -R appuser:appuser /app/data && chmod 700 /app/data
USER appuser
# 状态目录显式指向可写卷（accounts/pool-state/import/server.log 全在这里）。
ENV STATE_DIR=/app/data
EXPOSE 8788
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:8788/health || exit 1
ENTRYPOINT ["/entrypoint.sh"]
