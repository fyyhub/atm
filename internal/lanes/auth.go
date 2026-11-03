// Package lanes 对应 Python 版 lanes/auth.py：凭据装载与自动续期。
//
// 凭据依赖官方 CLI 的当前凭证：~/.atomcode/auth.toml。
//   - 读：mtime 热加载——官方 CLI 刷新/重登后，网关下一次取 Headers() 即自动跟随。
//   - 写：401 触发 RT 轮换刷新后，原子写回 auth.toml（仅改顶层凭据键，[user] 表原样保留）。
//   - /login 路由（自建 OAuth）产出的凭据同样写入 auth.toml。
//
// RT 轮换语义：/oauth/refresh 每次返回新 RT、旧 RT 立即作废，因此刷新成功后必须
// 原子写回 auth.toml；写回后官方 CLI 读到的也是新凭据，两边互不破坏。
//
// auth.toml 不存在时返回 ErrNotLoggedIn（先跑官方 `atomcode login`，或走网关 GET /login）。
//
// 关于签名：llm-api.atomgit.com 端点强制 X-AtomCode-* 签名（2026-10-28 抓包实证，
// 算法已逐字节还原，见 AtomCode/signing/ 与 docs/atomcode-signing-v1.md）。本网关走
// api-ai.gitcode.com + 中性 UA，该端点不强制签名，故暂无 signer 模块；
// 若改走 llm-api.atomgit.com，按 signing/atomgit_sign.py 产出 5 个头即可。
package lanes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// RefreshURL RT 轮换端点：每次返回新 AT + 新 RT，旧 RT 立即作废。
	RefreshURL = "https://acs.atomgit.com/oauth/refresh"
	// UpstreamUA 绝不能以 atomcode 开头——UA 门按前缀匹配（同 config.UpstreamUA）。
	UpstreamUA = "ac2api/0.1.0"

	// defaultExpiresIn 官方 CLI 缺省有效期（7 天），与 Python 版 604800 一致。
	defaultExpiresIn = 604800
	// expireMargin 提前 1 小时判定临期（Python: time.time() > expires_at - 3600）。
	expireMargin = 3600 * time.Second

	reqTimeout = 30 * time.Second
)

// ErrNotLoggedIn auth.toml 不存在——先跑官方 `atomcode login`，或网关 GET /login。
var ErrNotLoggedIn = errors.New("未找到 ~/.atomcode/auth.toml：先跑官方 `atomcode login`，或网关 GET /login")

// AuthTOMLPath 返回 ~/.atomcode/auth.toml。
func AuthTOMLPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".atomcode", "auth.toml")
}

// User 对应 auth.toml 的 [user] 表。
type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// creds auth.toml 解析结果（顶层凭据键 + 可选 user 表）。
type creds struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	ExpiresIn    int64 // 键缺失时保持 defaultExpiresIn（Python data.get(..., 604800)）
	CreatedAt    int64
	HasUser      bool
	User         User
}

// Credential 当前凭证：读 ~/.atomcode/auth.toml，mtime 变化自动热加载
// （跟随官方 CLI 的刷新/重登）。401 时调 /oauth/refresh 换新 token 并原子写回。
//
// 进程内加锁串行 + 锁内重读文件：若官方 CLI 已抢先刷新（RT 轮换），直接用文件里的
// 新凭据，不再重复刷新，避免并发双刷互杀。
type Credential struct {
	path     string // auth.toml（IDE 共享源，只读迁移用）
	jsonPath string // 网关自己的凭据文件（StateDir/auth.json，刷新产物落这里）

	accessToken  string
	refreshToken string
	userID       string
	username     string
	expiresAt    int64 // unix 秒

	mu    sync.RWMutex
	mtime time.Time
	log   *slog.Logger
	HTTP  *http.Client
	// gen 凭据代次：内存态 AT 每被替换一次（自身刷新成功、或热加载到外部新凭据）+1。
	// Refresh 取锁前的非阻塞快照就取它——Go 没有 GIL，RLock 快照会排队等写锁，
	// 拿到的已是刷新后的值，跳过检查恒不触发（Python 的锁前 token() 读在这里等价于原子读）。
	gen atomic.Int64
	// RefreshURL 非空时覆盖 /oauth/refresh 端点（httptest 注入用）。
	RefreshURL string
}

// refreshURL 当前刷新端点。
func (c *Credential) refreshURL() string {
	if c.RefreshURL != "" {
		return c.RefreshURL
	}
	return RefreshURL
}

// NewCredential 装载 auth.toml；文件缺失返回 ErrNotLoggedIn。
func NewCredential(path, jsonPath string, logger *slog.Logger) (*Credential, error) {
	if path == "" {
		path = AuthTOMLPath()
	}
	if logger == nil {
		logger = slog.Default()
	}
	c := &Credential{
		path:     path,
		jsonPath: jsonPath,
		log:      logger,
		HTTP:     &http.Client{Timeout: reqTimeout},
	}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

// load 读并解析 auth.toml；读坏（非缺失/非解析错）时保留当前内存凭据。
// 对应 Python _load + _parse_auth_toml：文件缺失→ErrNotLoggedIn，读坏→保留旧值。
func (c *Credential) load() error {
	// 统一后网关凭据源 = StateDir/auth.json（独立 RT 链）；auth.toml 降级为首次迁移源
	if c.jsonPath != "" {
		if raw, err := os.ReadFile(c.jsonPath); err == nil {
			if data, perr := parseAuthJSON(raw); perr == nil {
				c.accessToken = data.AccessToken
				c.refreshToken = data.RefreshToken
				c.expiresAt = data.CreatedAt + data.ExpiresIn
				c.userID = data.User.ID
				c.username = data.User.Username
				if mt, err := os.Stat(c.jsonPath); err == nil {
					c.mtime = mt.ModTime()
				}
				return nil
			}
		}
	}
	raw, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotLoggedIn
		}
		c.log.Warn("auth.toml 暂时读坏/占用中，保留当前内存凭据")
		return nil
	}
	data, perr := parseAuthTOML(raw)
	if perr != nil {
		c.log.Warn("auth.toml 解析失败，保留当前内存凭据", slog.String("err", perr.Error()))
		return nil
	}
	c.accessToken = data.AccessToken
	c.refreshToken = data.RefreshToken
	c.expiresAt = data.CreatedAt + data.ExpiresIn
	// Python: user = data.get("user", {}); self.user_id = str(user.get("id", ""))
	// —— 解析成功即覆盖，文件里没有 [user] 时清空内存里的账号信息（不是保留）。
	c.userID = data.User.ID
	c.username = data.User.Username
	if mt, err := c.modTime(); err == nil {
		c.mtime = mt
	} else {
		c.mtime = time.Time{}
	}
	return nil
}

func (c *Credential) modTime() (time.Time, error) {
	st, err := os.Stat(c.path)
	if err != nil {
		return time.Time{}, err
	}
	return st.ModTime(), nil
}

// reloadIfChanged 文件 mtime 变了就重读——官方 CLI 刷新/重登后网关自动跟随。
func (c *Credential) reloadIfChanged() {
	m, err := c.modTime()
	if err != nil {
		return
	}
	if !m.Equal(c.mtime) {
		old := c.accessToken
		_ = c.load()
		if c.accessToken != old {
			c.gen.Add(1)
			c.log.Info("auth.toml 已被外部更新，凭据已热加载",
				slog.String("账号", orQ(c.username)), slog.String("uid", orQ(c.userID)))
		}
	}
}

// IsExpired token 临期（提前 1 小时）。对应 Python is_expired。
func (c *Credential) IsExpired() bool {
	return time.Now().Unix() > c.expiresAt-int64(expireMargin.Seconds())
}

// Headers 组装上游身份头（每次现取，刷新后拿到的是新 token）。
// 对应 Python headers()：Authorization / Content-Type / User-Agent 三件套。
func (c *Credential) Headers() http.Header {
	c.reloadIfChanged()
	h := http.Header{}
	h.Set("Authorization", "Bearer "+c.accessToken)
	h.Set("Content-Type", "application/json")
	h.Set("User-Agent", UpstreamUA)
	return h
}

// AccessToken 当前 AT（测试/日志用）。
func (c *Credential) AccessToken() string { return c.accessToken }

// RefreshToken 当前 RT。
func (c *Credential) RefreshToken() string { return c.refreshToken }

// UserID 账号 uid（字符串化）。
func (c *Credential) UserID() string { return c.userID }

// Username 账号名。
func (c *Credential) Username() string { return c.username }

// ExpiresAt token 过期 unix 秒。
func (c *Credential) ExpiresAt() int64 { return c.expiresAt }

// Refresh POST /oauth/refresh，RT 轮换并写回 auth.toml（与官方 CLI/并发请求互斥）。
// 对应 Python refresh()。
func (c *Credential) Refresh() error {
	// 顺序关键（照抄 Python）：快照在**取锁之前**捕获。并发 401 时后进入锁的请求
	// 若发现凭据已变（gen 增了），直接跳过刷新；若在锁内捕获，比较恒等，会导致每个
	// 等待者都用同一个（已作废的）RT 再刷一次。锁必须释放：此前整个文件只有
	// Lock 没有 Unlock，第二个并发刷新者会永久卡死。
	genBefore := c.gen.Load()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reloadIfChanged()
	// 锁等待期间若凭据已被换掉（官方 CLI 热加载，或并发请求已刷），
	// 直接用现凭据，不再重复刷新（RT 已轮换，旧 RT 刷必失败/互杀）。
	if c.gen.Load() != genBefore {
		c.log.Info("凭据已被其他路径刷新，跳过本次重复刷新")
		return nil
	}

	expiresIn := int64(defaultExpiresIn)
	newAT, newRT, err := c.doRefresh(&expiresIn)
	if err != nil {
		return err
	}
	c.accessToken = newAT
	c.refreshToken = newRT
	c.expiresAt = time.Now().Unix() + expiresIn
	c.gen.Add(1)

	if err := c.save(SaveCreds{
		AccessToken:  c.accessToken,
		TokenType:    "Bearer",
		RefreshToken: c.refreshToken,
		ExpiresIn:    expiresIn,
		CreatedAt:    time.Now().Unix(),
		User:         User{ID: c.userID, Username: c.username},
		HasUser:      c.userID != "", // 对齐 Python：user.id 为空则不写 [user] 键
	}); err != nil {
		return fmt.Errorf("刷新结果写回 auth.toml 失败：%w", err)
	}
	c.log.Info("token 已刷新并写回 auth.toml",
		slog.String("新过期", time.Unix(c.expiresAt, 0).Format("2006-01-02 15:04:05")))
	return nil
}

// doRefresh 发一次 /oauth/refresh，返回 (新 AT, 新 RT, expiresIn)。
// expiresIn 出参覆盖（响应无该字段时保留传入默认值）。抽出来便于测试打桩。
func (c *Credential) doRefresh(expiresIn *int64) (string, string, error) {
	body, _ := json.Marshal(map[string]string{"refresh_token": c.refreshToken})
	ctx, cancel := context.WithTimeout(context.Background(), reqTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.refreshURL(), bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UpstreamUA)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("刷新请求失败：%w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("刷新失败 HTTP %d: %s", resp.StatusCode, trunc(string(raw), 200))
	}
	var data struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    *int64 `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", "", fmt.Errorf("刷新响应解析失败：%w", err)
	}
	if data.AccessToken == "" {
		return "", "", errors.New("刷新响应缺少 access_token")
	}
	if data.ExpiresIn != nil {
		*expiresIn = *data.ExpiresIn
	}
	return data.AccessToken, data.RefreshToken, nil
}

// SaveCreds 一份待写入 auth.toml 的凭据（对应 Python save_credentials 的入参 dict）。
type SaveCreds struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	ExpiresIn    int64
	CreatedAt    int64
	User         User
	HasUser      bool
}

// Save 原子写 StateDir/auth.json（网关独立凭据文件，0600）。
// 不再回写 auth.toml：RT 轮换后写回会让官方 CLI 的旧 RT 作废（双杀）。
// IDE 掉线时重登官方 CLI 即可，网关凭据不受影响。
func (c *Credential) save(sc SaveCreds) error {
	if c.jsonPath == "" {
		return SaveAuthTOML(c.path, sc)
	}
	return SaveAuthJSON(c.jsonPath, sc)
}

// SaveCredentials 独立写凭据到 auth.toml（/login/poll 完成交换后用，无需已装载的 Credential）。
// 对应模块级 save_credentials(creds)。
func SaveCredentials(path string, sc SaveCreds) error {
	if path == "" {
		path = AuthTOMLPath()
	}
	return SaveAuthTOML(path, sc)
}

// SaveAuthJSON 网关独立凭据文件（0600，原子替换）。
// 带 [user] 信息（HasUser 时）——账号池的种子/凭据文件需要自描述，
// 否则跨机器导入后丢 username/uid（2026-11-03 种子导入实测暴露）。
func SaveAuthJSON(path string, sc SaveCreds) error {
	m := map[string]any{
		"access_token":  sc.AccessToken,
		"token_type":    orDefault(sc.TokenType, "Bearer"),
		"refresh_token": sc.RefreshToken,
		"expires_in":    sc.ExpiresIn,
		"created_at":    sc.CreatedAt,
		"saved_at":      time.Now().Format(time.RFC3339),
	}
	if sc.HasUser {
		m["user"] = sc.User
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// parseAuthJSON 解析 auth.json。
func parseAuthJSON(raw []byte) (creds, error) {
	var data struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		CreatedAt    int64  `json:"created_at"`
		User         User   `json:"user"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return creds{}, err
	}
	return creds{AccessToken: data.AccessToken, TokenType: data.TokenType,
		RefreshToken: data.RefreshToken, ExpiresIn: data.ExpiresIn,
		CreatedAt: data.CreatedAt, HasUser: data.User.ID != "", User: data.User}, nil
}

// SaveAuthTOML 行级替换 auth.toml 顶层凭据键，保留其它一切（含 [user] 表原样）。
//
// 语义严格对齐 Python _write_auth_toml：
//   - 只在顶层（非 [user] 段内）匹配 `key = ...` 行，替换这五个键的值；
//   - 段头 `[user...]` 起的行进入/退出 in_user_table 状态；
//   - 缺失的键按固定顺序追加到末尾；
//   - 若给了 user 且原文件没有 [user] 表，则追加一个 [user] 表；
//   - 先写 .tmp 再 os.Rename，原子替换。
func SaveAuthTOML(path string, sc SaveCreds) error {
	text := ""
	if raw, err := os.ReadFile(path); err == nil {
		text = string(raw)
	}

	updates := map[string]string{
		"access_token":  tomlString(sc.AccessToken),
		"token_type":    tomlString(orDefault(sc.TokenType, "Bearer")),
		"refresh_token": tomlString(sc.RefreshToken),
		"expires_in":    strconv.FormatInt(sc.ExpiresIn, 10),
		"created_at":    strconv.FormatInt(sc.CreatedAt, 10),
	}

	// 逐行处理，保留原行尾（含 \r\n 差异）。用 splitLinesKeepEnds 精确复刻 Python splitlines(keepends=True)。
	var out bytes.Buffer
	seen := map[string]bool{}
	inUserTable := false
	for _, line := range splitLinesKeepEnds(text) {
		stripped := strings.TrimSpace(line)
		if strings.HasPrefix(stripped, "[") {
			inUserTable = strings.HasPrefix(strings.ToLower(stripped), "[user")
			out.WriteString(line)
			continue
		}
		var key string
		if !inUserTable && strings.Contains(stripped, "=") {
			key = strings.TrimSpace(strings.SplitN(stripped, "=", 2)[0])
		}
		if val, ok := updates[key]; ok && key != "" {
			// 复用原行尾（若无则补 \n），只替换值部分
			out.WriteString(key + " = " + val + eolOf(line))
			seen[key] = true
		} else {
			out.WriteString(line)
		}
	}
	for _, key := range []string{"access_token", "token_type", "refresh_token", "expires_in", "created_at"} {
		if _, ok := updates[key]; ok && !seen[key] {
			out.WriteString(key + " = " + updates[key] + "\n")
		}
	}
	if sc.HasUser && !strings.Contains(text, "[user]") {
		u := sc.User
		out.WriteString(fmt.Sprintf("\n[user]\nid = %s\nusername = %s\nname = %s\nemail = %s\navatar_url = %s\n",
			tomlString(u.ID), tomlString(u.Username), tomlString(u.Name), tomlString(u.Email), tomlString(u.AvatarURL)))
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// parseAuthTOML 极简 TOML 解析，只取 auth.toml 关心的顶层标量与 [user] 表。
// 官方 CLI 写出的 auth.toml 是扁平的 `key = value` + 一个 [user] 表，不需要完整 TOML。
// parseAuthTOML 极简 TOML 解析，只取 auth.toml 关心的顶层标量与 [user] 表。
// 与 Python tomllib 同严：残缺表头、无 = 的行、未闭合字符串、裸词值一律报错——
// 报错时 load() 走「保留内存凭据」分支，半截写坏的文件才不会把好凭据冲掉
// （宽容解析会接受 torn write，正是 tomllib 要拦的）。
func parseAuthTOML(raw []byte) (creds, error) {
	// ExpiresIn 预置默认值：Python 用 data.get("expires_in", 604800)，键缺失时
	// 不是 0（否则 expiresAt=created_at，凭据一装载就判过期）。
	c := creds{ExpiresIn: defaultExpiresIn}
	inUser := false
	sc := bufioLines(string(raw))
	for line := range sc {
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		if strings.HasPrefix(stripped, "[") {
			if !strings.HasSuffix(stripped, "]") {
				return creds{}, fmt.Errorf("残缺表头: %q", stripped)
			}
			inUser = strings.HasPrefix(strings.ToLower(stripped), "[user")
			if inUser {
				c.HasUser = true
			}
			continue
		}
		k, v, ok := strings.Cut(stripped, "=")
		if !ok {
			// tomllib 语义：既非表头也无 = 的行是语法错误（截断文件的常见形态）
			return creds{}, fmt.Errorf("非法行: %q", stripped)
		}
		k = strings.TrimSpace(k)
		s, n, err := tomlScalar(strings.TrimSpace(v))
		if err != nil {
			return creds{}, err
		}
		str := s
		if s == "" {
			str = strconv.FormatInt(n, 10) // 裸整数按 Python str() 语义转字符串
		}
		if inUser {
			switch k {
			case "id":
				c.User.ID = str
			case "username":
				c.User.Username = str
			case "name":
				c.User.Name = str
			case "email":
				c.User.Email = str
			case "avatar_url":
				c.User.AvatarURL = str
			}
			continue
		}
		switch k {
		case "access_token":
			c.AccessToken = str
		case "token_type":
			c.TokenType = str
		case "refresh_token":
			c.RefreshToken = str
		case "expires_in":
			if s != "" {
				return creds{}, fmt.Errorf("expires_in 应为整数: %q", v)
			}
			c.ExpiresIn = n
		case "created_at":
			if s != "" {
				return creds{}, fmt.Errorf("created_at 应为整数: %q", v)
			}
			c.CreatedAt = n
		}
	}
	return c, nil
}

// ParseAuthTOML 解析 auth.toml 字节为 SaveCreds（账号池录入/迁移用）。
// 与内部 parseAuthTOML 同严：残缺表头、无 = 行、未闭合字符串、裸词值一律报错。
func ParseAuthTOML(raw []byte) (SaveCreds, error) {
	c, err := parseAuthTOML(raw)
	if err != nil {
		return SaveCreds{}, err
	}
	return SaveCreds{
		AccessToken:  c.AccessToken,
		TokenType:    orDefault(c.TokenType, "Bearer"),
		RefreshToken: c.RefreshToken,
		ExpiresIn:    c.ExpiresIn,
		CreatedAt:    c.CreatedAt,
		User:         c.User,
		HasUser:      c.HasUser,
	}, nil
}

// ParseAuthJSON 解析 auth.json 字节为 SaveCreds（账号池迁移用）。
func ParseAuthJSON(raw []byte) (SaveCreds, error) {
	c, err := parseAuthJSON(raw)
	if err != nil {
		return SaveCreds{}, err
	}
	return SaveCreds{
		AccessToken:  c.AccessToken,
		TokenType:    orDefault(c.TokenType, "Bearer"),
		RefreshToken: c.RefreshToken,
		ExpiresIn:    c.ExpiresIn,
		CreatedAt:    c.CreatedAt,
		User:         c.User,
		HasUser:      c.HasUser,
	}, nil
}

// tomlScalar 解析单值：带引号字符串（必须闭合）或裸整数；残缺值报错。
// 半截写坏的 auth.toml 最常见形态就是值被截成未闭合字符串（"unterminated），
// tomllib 在这里抛错，本函数必须同样抛而不是把裸词当值收下。
func tomlScalar(v string) (s string, n int64, err error) {
	if v == "" {
		return "", 0, errors.New("空值")
	}
	if q := v[0]; q == '"' || q == '\'' {
		end := strings.IndexByte(v[1:], q)
		if end < 0 {
			return "", 0, fmt.Errorf("未闭合字符串: %q", v)
		}
		s = v[1 : 1+end]
		rest := strings.TrimSpace(v[2+end:])
		if rest != "" && !strings.HasPrefix(rest, "#") {
			return "", 0, fmt.Errorf("字符串后有多余内容: %q", v)
		}
		return s, 0, nil
	}
	// 裸值：去行尾注释后必须能按整数解析（本文件裸值只有 expires_in/created_at/user.id）
	if i := strings.IndexByte(v, '#'); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	n, err = strconv.ParseInt(strings.ReplaceAll(v, "_", ""), 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("非法裸值: %q", v)
	}
	return "", n, nil
}

// ── 辅助 ─────────────────────────────────────────────────────────────────────

func tomlString(s string) string { return `"` + s + `"` }

// splitLinesKeepEnds 复刻 Python str.splitlines(keepends=True)：
// 每行含其行尾（\n、\r\n、\r），末行若无行尾则不补。
func splitLinesKeepEnds(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i+1])
			start = i + 1
		} else if s[i] == '\r' {
			if i+1 < len(s) && s[i+1] == '\n' {
				lines = append(lines, s[start:i+2])
				i++
			} else {
				lines = append(lines, s[start:i+1])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// eolOf 取一行的行尾（\r\n / \n / \r / 空）。
func eolOf(line string) string {
	if strings.HasSuffix(line, "\r\n") {
		return "\r\n"
	}
	if strings.HasSuffix(line, "\n") {
		return "\n"
	}
	if strings.HasSuffix(line, "\r") {
		return "\r"
	}
	return ""
}

func bufioLines(s string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for _, l := range strings.Split(s, "\n") {
			l = strings.TrimSuffix(l, "\r")
			if !yield(l) {
				return
			}
		}
	}
}

func orQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func orDefault(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
