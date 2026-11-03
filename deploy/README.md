# AtomCode2api 部署指南

把 AtomCode CodingPlan 账号池包装成 OpenAI / Anthropic 兼容 API 的自托管网关。
两种部署方式：Docker（推荐）与裸机 systemd。

## 目录结构（宿主机）

```
仓库根/
├── data/                    # 持久化状态卷（账号池、统计、日志）—— 备份就备它
│   ├── accounts/<id>.json   #   每账号凭据（RT 链独立）
│   ├── pool-state.json      # 池状态与统计快照
│   ├── import/              # 投放新账号到这里，服务自动扫描导入
│   │   └── imported/        # 已导入的种子会挪进来
│   └── server.log           # 运行日志（2MB×3 轮转）
├── deploy/
│   ├── docker-compose.yml   # Docker 编排
│   ├── .env.example         # 环境变量模板
│   ├── atomcode2api.service # systemd unit
│   ├── build-release.sh     # Linux 交叉编译（amd64+arm64）
│   ├── build-release.ps1    # Windows 宿主机交叉编译
│   ├── entrypoint.sh        # 容器入口（种子导入 + 启动）
│   └── seed-accounts/       # 初始账号种子（⚠️ 含真实凭据，已被 .gitignore 排除，勿提交）
└── .env                     # 实际配置（不入库）
```

## 方式一：Docker（推荐）

```bash
cp deploy/.env.example .env       # 编辑：公网/局域网暴露必须设 API_KEY
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml ps   # healthy 即就绪
```

- 种子账号：`deploy/seed-accounts/*.json`（或 `.toml`）会在首次启动自动导入到
  `data/accounts/`。导入后种子目录可清空（RT 查重保证重启不重复导入）。
- 权限：容器以非 root（uid 10001）运行；`data/` 属主需可被其写入
  （`sudo chown -R 10001:10001 data` 或让 entrypoint 首次自建）。
- 健康检查：`GET /health`（compose 与镜像双层声明）。

## 方式二：裸机 systemd

```bash
sh deploy/build-release.sh          # 产出 dist/atomcode2api-linux-amd64
sudo useradd -r -s /usr/sbin/nologin atomcode
sudo install -d -o atomcode -g atomcode -m 700 /var/lib/atomcode2api
sudo install -d -o atomcode -g atomcode /opt/atomcode2api
sudo install -o atomcode -g atomcode -m 555 dist/atomcode2api-linux-amd64 /opt/atomcode2api/atomcode2api
sudo cp deploy/atomcode2api.service /etc/systemd/system/
echo 'API_KEY=<强随机串>' | sudo tee /etc/atomcode2api.env && sudo chmod 600 /etc/atomcode2api.env
sudo systemctl daemon-reload && sudo systemctl enable --now atomcode2api
```

种子账号放 `/var/lib/atomcode2api/import/`（属主 atomcode、0600），一分钟内自动导入。

## 账号管理（运行时，无需重启）

| 操作 | 入口 |
|---|---|
| 添加（粘贴 auth.toml / 批量 `---` 分隔） | `http://<host>:8788/admin` → 账号页 |
| OAuth 登录入池 | `GET /login` 或面板提示 |
| 投放文件导入 | 拷 `*.toml`/`*.json` 到 `data/import/`（≤60s 生效） |
| 禁用/重置冷却/删除 | /admin 账号页按钮 |
| 池状态 | `GET /pool/status`（带 API_KEY） |

## 排障入口

- 面板：`/admin`（账号状态、last_error、冷却剩余、下次领取时间；诊断页可管理 API 密钥）
- 日志：`data/server.log`（Docker：`docker compose -f deploy/docker-compose.yml logs -f`），
  关键词：`换人重试` / `quota` / `[claim]` / `[revive]` / `[import]`
- 单账号状态：`GET /status`；池全览：`GET /pool/status`
- 调试指定账号：请求头 `X-Account-Id: <id>`（仅在配置了 API_KEY 时生效）

## API 鉴权（API_KEY）

优先级：**面板显式设置（`data/settings.json`）> 环境变量 API_KEY > 未启用**，
面板诊断页实时显示「当前生效来源」。面板上可生成强随机密钥/保存/清除/禁用，
保存即热生效无需重启。「清除面板值」只回落到环境变量；「禁用鉴权」连 env 也压过
（有二次确认）。密钥写入接口仅允许回环地址调用。

⚠️ `/admin` 面板本身无鉴权——任何能访问 8788 的人都能打开它。仅回环监听是
默认安全姿态；确需公网暴露时务必在反向代理层加访问控制，并设置 API_KEY。

### 应急恢复（被密钥锁在门外时）

面板与密钥管理端点**永远不挂 API_KEY 闸门**（密钥生效后仍可打开 /admin →
诊断页 → 清除面板值），写操作仅校验回环地址。若面板也不可用，本机兜底：

```bash
# 方式一：回环 curl 直接清除（服务运行中即可）
curl -X POST http://127.0.0.1:8788/admin/api/auth -d '{"api_key":""}'

# 方式二：停服务后删/改设置文件，再启动
#   Docker: docker compose exec atomcode2api sh -c 'rm /app/data/settings.json'（或卷上删 data/settings.json）
#   裸机:   rm /var/lib/atomcode2api/settings.json
# 删除后回落到环境变量 API_KEY；env 也没有 = 不鉴权
```

注意：回环上的任何本机进程都能调这个清除接口（与「本机可直接改 settings.json」
等权）。这是刻意的自救设计，不是漏洞——不要把 8788 暴露给不可信网络。

## 升级与回滚

```bash
# 升级
git pull && docker compose -f deploy/docker-compose.yml up -d --build   # Docker
# 或裸机：重跑 build-release.sh → 替换 /opt/atomcode2api/atomcode2api → systemctl restart

# 回滚：检出旧版本重新构建即可。data/ 目录向前兼容（凭据与状态文件不会因
# 新版回旧版而损坏；多余字段旧版会忽略）。
```

## 备份

只需备份 `data/`（其中 `accounts/*.json` 是凭据本体，`pool-state.json` 是统计）。
`deploy/seed-accounts/` 导入完成后可不再备份（内容已入 data/）。
⚠️ 两者都含敏感凭据：备份文件同样按 0600 保护，勿提交公开仓库。

## 凭据安全

- `deploy/seed-accounts/`、`data/`、`.env` 均已加入 .gitignore
- 文件权限：凭据 0600，目录 0700
- 追加/替换账号：直接替换 `deploy/seed-accounts/*.json` 后重启（已存在的账号会被查重跳过；
  要更新凭据请用 /admin 删除旧账号再放行新种子），或运行中走 /admin 在线操作
