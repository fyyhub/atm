// Package config 装配 atomcode2api 的运行配置：.env 加载 + 上游常量 + OpenRouter 反代清单。
//
// 与 Python 版 server.py 的模块级常量一一对应：
//
//	HOST / PORT / API_KEY    —— 监听与本地鉴权
//	LLM_BASE / CONTROL_BASE  —— 数据面 / 控制面基址
//	UPSTREAM_UA              —— 关键：绝不能以 atomcode 开头（UA 门按前缀匹配）
//	OPENROUTER_*             —— 免费模型反代配置（从 ~/.atomcode/config.toml 取 key）
//
// 配置一律从环境变量 / .env 读取；.env 语义对齐 python-dotenv（不覆盖已有 env）。
package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	ListenHost  = "127.0.0.1"
	DefaultPort = 8788

	// LLMBase 数据面（免签名，非 atomcode UA）。见 docs/atomcode-03-数据面与UA门.md：
	// 必须同时换主机和换 UA，只换一个都不行。
	LLMBase = "https://api-ai.gitcode.com/v1"
	// ControlBase 控制面：models-v2 / status-v2 / claim-v2，仅需 Bearer，免签名。
	ControlBase = "https://api.gitcode.com/api/v5/coding-plan"
	// UpstreamUA 绝不能以 atomcode 开头——UA 门按前缀匹配，atomcode/* 触发签名/套餐强校验 403。
	UpstreamUA = "ac2api/0.1.0"

	// OpenRouterBase 免费模型反代，不走 CodingPlan 额度。
	OpenRouterBase = "https://openrouter.ai/api/v1"
)

// Config 运行期配置。
type Config struct {
	APIKey           string
	Host             string
	Port             int
	OpenRouterAPIKey string
	StateDir         string // server.log 所在（对应 Python dirname(abspath(__file__))）
}

// StateFilePath 返回状态目录下的文件路径。
func (c *Config) StateFilePath(name string) string { return filepath.Join(c.StateDir, name) }

// ModelEntry OpenRouter 反代模型：对外 id（带 openrouter/ 前缀）与上游真实 model。
type ModelEntry struct {
	ID       string
	Upstream string
}

// OpenRouterModels OpenRouter 免费模型（从用户 config.toml 提取 2026-10-09，对齐 Python 版清单）。
var OpenRouterModels = []ModelEntry{
	{"openrouter/stealth/space-bunny-alpha", "stealth/space-bunny-alpha"},
	{"openrouter/nvidia/nemotron-3-ultra-550b-a55b:free", "nvidia/nemotron-3-ultra-550b-a55b:free"},
	{"openrouter/nvidia/nemotron-3.5-lightning:free", "nvidia/nemotron-3.5-lightning:free"},
	{"openrouter/thinkingmachines/inkling-small:free", "thinkingmachines/inkling-small:free"},
	{"openrouter/thinkingmachines/inkling:free", "thinkingmachines/inkling:free"},
}

// IsOpenRouterModel 判定 model_id 是否走 OpenRouter 分支。
func IsOpenRouterModel(modelID string) bool {
	return strings.HasPrefix(modelID, "openrouter/")
}

// OpenRouterUpstreamModel openrouter/stealth/space-bunny-alpha → stealth/space-bunny-alpha。
// 命中清单用映射值；未命中则剥前缀兜底（与 Python 版 _openrouter_upstream_model 一致）。
func OpenRouterUpstreamModel(modelID string) string {
	for _, m := range OpenRouterModels {
		if m.ID == modelID {
			return m.Upstream
		}
	}
	if strings.HasPrefix(modelID, "openrouter/") {
		return strings.TrimPrefix(modelID, "openrouter/")
	}
	return modelID
}

// Load 读取配置。优先级：环境变量 > .env > 默认值。
// .env 从 exe 所在目录和工作目录两处尝试（与 python-dotenv load_dotenv 语义近似）。
func Load() *Config {
	c := &Config{Host: ListenHost, Port: DefaultPort}

	// 状态目录：exe 所在目录（server.log 落这里，对齐 Python）
	if exe, err := os.Executable(); err == nil {
		c.StateDir = filepath.Dir(exe)
	} else {
		wd, _ := os.Getwd()
		c.StateDir = wd
	}

	// .env：exe 目录优先，其次工作目录；两处都有的键先到先得
	for _, dir := range []string{c.StateDir, mustWd()} {
		loadDotEnv(filepath.Join(dir, ".env"))
	}

	// STATE_DIR 显式覆盖状态目录（server.log / auth.json / accounts/ /
	// pool-state.json / import/ 全在这里）。Docker/裸机部署把它指到可写卷——
	// 默认的 exe 目录在容器里是只读的。放在 .env 加载之后，.env 里也可写。
	if v := strings.TrimSpace(os.Getenv("STATE_DIR")); v != "" {
		c.StateDir = v
	}

	if h := strings.TrimSpace(os.Getenv("HOST")); h != "" {
		c.Host = h
	}
	if p, err := strconv.Atoi(strings.TrimSpace(os.Getenv("PORT"))); err == nil && p > 0 {
		c.Port = p
	}
	c.APIKey = strings.TrimSpace(os.Getenv("API_KEY"))
	c.OpenRouterAPIKey = loadOpenRouterKey()
	return c
}

func mustWd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

// loadOpenRouterKey 从环境变量或 ~/.atomcode/config.toml 取 OpenRouter key。
//
// 语义对齐 Python 版 _load_openrouter_key：env OPENROUTER_API_KEY 优先；否则读
// config.toml 的 [provider_accounts.*]，取 provider == "openrouter" 的 api_key。
// Go 无 tomllib，这里用最小行解析（只认顶层 [provider_accounts.X] 段内的
// provider / api_key 两行），够覆盖官方 CLI 写出的形状；解析失败返回空串。
func loadOpenRouterKey() string {
	if k := strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")); k != "" {
		return k
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	f, err := os.Open(filepath.Join(home, ".atomcode", "config.toml"))
	if err != nil {
		return ""
	}
	defer f.Close()

	inAccounts := false
	segProvider := ""
	segKey := ""
	flush := func() string {
		if segProvider == "openrouter" && segKey != "" {
			return segKey
		}
		return ""
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			// 进入新 section 前，先看上一段是否命中 openrouter
			if v := flush(); v != "" {
				return v
			}
			inAccounts = strings.HasPrefix(line, "[provider_accounts")
			segProvider, segKey = "", ""
			continue
		}
		if !inAccounts {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "provider":
			segProvider = v
		case "api_key":
			segKey = v
		}
	}
	return flush()
}

// loadDotEnv 极简 .env 解析：KEY=VALUE 行，# 注释，不展开变量，不覆盖已有 env。
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if k != "" && os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
}
