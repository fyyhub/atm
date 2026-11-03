// Package handler 对应 Python 版 server.py + routes/：路由调度、鉴权闸门、rid、
// in:/done: 日志、控制面与登录端点。上游协议细节在 adapters 与 upstream 包里。
package handler

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"atomcode2api/internal/config"
	"atomcode2api/internal/control"
	"atomcode2api/internal/lanes"
	"atomcode2api/internal/pool"
	"atomcode2api/internal/upstream"
)

// Server 聚合全部依赖；Handler() 挂到 http.ServeMux。
//
// 凭据状态与 Python 的全局 cred 等价：cred 为 nil = 未登录（CodingPlan 路由 401，
// OpenRouter 分支不受影响）。三协议路由与 /status、/v1/models 都经 s 取身份头，
// 所以 Server 本身实现 upstream.Cred（Headers/Refresh 转发给当前凭据）。
type Server struct {
	Cfg   *config.Config
	Con   *control.Client
	Up    *upstream.Client
	OAuth *lanes.OAuthLogin
	Log   *slog.Logger

	cred    atomic.Pointer[lanes.Credential]
	hasCred atomic.Bool

	// Pool 多账号池（P1）。New 总是创建；调度走 Pool.Acquire()，
	// Headers/Refresh/credOrNil 经 Pool.Default() 兼容单账号语义。
	Pool *pool.Pool

	// 面板设置与当前生效的鉴权状态（P4：settings.json 持久化 + 热更新）。
	settings   *Settings
	authMu     sync.RWMutex
	authKey    string // 当前生效密钥（"" = 不鉴权）
	authSource string // panel / env / off（面板禁用）/ none

	// loginRate 面板登录限速（P5）。
	loginRate *loginRateLimiter

	reqSeq atomic.Int64

	// OrKey OpenRouter API key。Python 版在模块导入时一次性读取，路由请求期
	// 经 core 动态查找；Go 版等价物是启动时从 config 注入、字段可在测试里改。
	OrKey string

	// AuthTOML 凭据文件路径（默认 ~/.atomcode/auth.toml，测试指向临时目录）。
	AuthTOML string
	// AuthJSON 网关独立凭据文件（StateDir/auth.json）：刷新/登录产物落这里，
	// 加载时优先于 auth.toml（独立 RT 链，不再回写 IDE 共享文件）。
	AuthJSON string
}

// New 构造服务。cred 可为 nil（未登录）；非 nil 时注册为池账号（兼容旧调用方）。
func New(cfg *config.Config, cred *lanes.Credential, logger *slog.Logger) *Server {
	s := &Server{
		Cfg:   cfg,
		Con:   control.New(),
		Up:    upstream.New(),
		OAuth: lanes.NewOAuthLogin(),
		Log:   logger,
		OrKey: cfg.OpenRouterAPIKey,
	}
	s.Up.OpenRouterKey = cfg.OpenRouterAPIKey
	s.Pool = pool.New(cfg.StateDir, s.Con, logger)
	s.settings = loadSettings(cfg.StateDir, func(msg string) {
		logger.Warn("settings 加载", slog.String("warn", msg))
	})
	s.loginRate = newLoginRateLimiter()
	s.recomputeAuth()
	if cred != nil {
		s.SetCred(cred)
	}
	return s
}

// recomputeAuth 重算当前生效密钥与来源（改设置/启动时调用）。
// 优先级：面板显式设置 > 环境变量 API_KEY > 未启用；面板禁用压过 env。
func (s *Server) recomputeAuth() {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	switch {
	case s.settings.APIKey != "":
		s.authKey, s.authSource = s.settings.APIKey, "panel"
	case s.settings.AuthDisabled:
		s.authKey, s.authSource = "", "off"
	case s.Cfg.APIKey != "":
		s.authKey, s.authSource = s.Cfg.APIKey, "env"
	default:
		s.authKey, s.authSource = "", "none"
	}
}

// currentAPIKey 当前生效密钥（鉴权中间件每次现读——保存后立即对后续请求
// 生效，进行中的请求不受影响）。
func (s *Server) currentAPIKey() string {
	s.authMu.RLock()
	defer s.authMu.RUnlock()
	return s.authKey
}

// authSourceLabel 生效来源的面板文案。
func (s *Server) authSourceLabel() string {
	s.authMu.RLock()
	defer s.authMu.RUnlock()
	switch s.authSource {
	case "panel":
		return "面板"
	case "env":
		return "环境变量"
	case "off":
		return "已禁用（面板关闭）"
	}
	return "未启用"
}

// SetCred 换入凭据并启用 CodingPlan 路由（启动装载与 /login/poll 完成后调用）。
// 池化后同时注册进账号池（幂等：同 user.id 视为替换）。
func (s *Server) SetCred(c *lanes.Credential) {
	s.cred.Store(c)
	s.hasCred.Store(true)
	if s.Pool != nil {
		if _, err := s.Pool.AddCredential(c); err != nil {
			s.Log.Warn("凭据注册入池失败", slog.String("err", err.Error()))
		}
	}
}

// ClearCred 置为未登录（auth.toml 运行期被删时的兜底；Python 版无此路径）。
// 池化后同步清空池内账号（仅内存），否则 credGuard 仍会被池放行。
func (s *Server) ClearCred() {
	s.cred.Store(nil)
	s.hasCred.Store(false)
	if s.Pool != nil {
		s.Pool.Clear()
	}
}

// credOrNil 取「代表凭据」：优先池内最优账号（池化后 /status、overview、
// adminRefresh 等单账号语义端点共用），空池回落 legacy 指针。
func (s *Server) credOrNil() *lanes.Credential {
	return s.poolCredOrLegacy()
}

// PoolDefaultCred 池代表凭据（main 启动流程用），无则 nil。
func (s *Server) PoolDefaultCred() *lanes.Credential {
	return s.credOrNil()
}

func (s *Server) poolCredOrLegacy() *lanes.Credential {
	if s.Pool != nil {
		if a := s.Pool.Default(); a != nil {
			return a.Cred
		}
	}
	if !s.hasCred.Load() {
		return nil
	}
	return s.cred.Load()
}

// Headers / Refresh 实现 upstream.Cred：转发给当前凭据。
// 未登录时只给中性 UA 头（此时请求已被 credGuard 401 拦掉，走到这里属于旁路）。
func (s *Server) Headers() http.Header {
	if c := s.credOrNil(); c != nil {
		return c.Headers()
	}
	h := http.Header{}
	h.Set("User-Agent", config.UpstreamUA)
	return h
}

// Refresh 未登录时直接报错（对应 Python cred is None 时的 AttributeError 冒泡）。
func (s *Server) Refresh() error {
	c := s.credOrNil()
	if c == nil {
		return lanes.ErrNotLoggedIn
	}
	return c.Refresh()
}

// nextRID 单调递增请求号 "r%04d"（对应 _next_req_id）。
func (s *Server) nextRID() string { return fmt.Sprintf("r%04d", s.reqSeq.Add(1)) }

// ── 本地鉴权闸门（对应 _guard / _cred_guard，逐端点显式调用，与 Python 一致）──

// guard 数据/管理接口闸门。
//
// /admin/api/*：面板会话 或 API_KEY 任一有效即放行（P6：登录面板后不再二次
// 要密钥；API_KEY 仍是管理接口的程序化凭证）。会话优先判定——带过期/错误的
// localStorage 密钥但有会话时不因此被拒。「免凭证」仅在两种凭证都未配置时
// 成立（纯本地裸奔）；只要设了任一种，就必须出示一种。
// 其余路径（/v1/*、/status、/pool/status）只认 API_KEY：面板密码不越权数据面。
func (s *Server) guard(w http.ResponseWriter, r *http.Request) bool {
	key := s.currentAPIKey()
	if strings.HasPrefix(r.URL.Path, "/admin/") {
		if s.validSession(r) {
			return true
		}
		if key != "" && r.Header.Get("Authorization") == "Bearer "+key {
			return true
		}
		if key == "" && s.settings.PanelPasswordHash == "" {
			return true // 双凭证皆无 = 纯本地开放（P4 原语义）
		}
		writeJSON(w, http.StatusUnauthorized, openAIErrorBody("invalid api key", "auth_error"))
		return false
	}
	if key == "" || r.Header.Get("Authorization") == "Bearer "+key {
		return true
	}
	writeJSON(w, http.StatusUnauthorized, openAIErrorBody("invalid api key", "auth_error"))
	return false
}

// credGuard 未登录（空池且无 legacy 凭据）时 401 提示；有账号即放行——
// 账号全冷却/失效由调度层 Acquire 失败回 429 pool_exhausted（P1 语义）。
func (s *Server) credGuard(w http.ResponseWriter) bool {
	if s.Pool != nil && s.Pool.Count() > 0 {
		return true
	}
	if s.credOrNil() != nil {
		return true
	}
	writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{
		"message":   "尚未登录：先跑官方 `atomcode login`，或 GET /login 走网关 OAuth 登录",
		"type":      "auth_error",
		"login_url": "/login",
	}})
	return false
}

// ── 路由挂载 ────────────────────────────────────────────────────────────────

// Handler 组装路由。Python 版把 /health 放在无鉴权位置，其余端点各自显式过闸。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", s.listModels)
	mux.HandleFunc("/v1/chat/completions", s.chatCompletions)
	mux.HandleFunc("/v1/responses", s.responsesAPI)
	mux.HandleFunc("/v1/messages", s.messagesAPI)
	mux.HandleFunc("/login", s.loginStart)
	mux.HandleFunc("/login/poll", s.loginPoll)
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/status", s.status)
	mux.HandleFunc("GET /pool/status", s.poolStatus)
	mux.HandleFunc("/admin", s.servePanel)
	mux.HandleFunc("/admin/api/overview", s.overview)
	mux.HandleFunc("/admin/api/refresh-token", s.adminRefresh)
	mux.HandleFunc("/admin/api/claim", s.adminClaim)
	mux.HandleFunc("GET /admin/api/accounts", s.accountsList)
	mux.HandleFunc("POST /admin/api/accounts", s.accountsAdd)
	mux.HandleFunc("POST /admin/api/accounts/batch", s.accountsBatch)
	mux.HandleFunc("DELETE /admin/api/accounts/{id}", s.accountsDelete)
	mux.HandleFunc("POST /admin/api/accounts/{id}/disable", s.accountsDisable)
	mux.HandleFunc("POST /admin/api/accounts/{id}/enable", s.accountsEnable)
	mux.HandleFunc("POST /admin/api/accounts/{id}/reset", s.accountsReset)
	mux.HandleFunc("GET /admin/api/auth", s.authGet)
	mux.HandleFunc("POST /admin/api/auth", s.authSetKey)
	mux.HandleFunc("POST /admin/api/auth/disable", s.authDisable)
	mux.HandleFunc("POST /admin/api/login", s.panelLogin)
	mux.HandleFunc("POST /admin/api/logout", s.panelLogout)
	mux.HandleFunc("POST /admin/api/password", s.panelPassword)
	mux.HandleFunc("POST /admin/api/password/reset", s.panelPasswordReset)
	return s.panelGate(mux)
}

// ── /v1/models：控制面目录 + OpenRouter 免费模型 ────────────────────────────

func (s *Server) listModels(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) || !s.credGuard(w) {
		return
	}
	up, err := s.Con.Models(s)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, openAIErrorBody(err.Error(), "upstream_error"))
		return
	}
	data := []any{}
	for _, m := range up {
		// plan_available 缺省 true（Python: m.get("plan_available", True)）
		if v, ok := m["plan_available"].(bool); ok && !v {
			continue
		}
		data = append(data, map[string]any{
			"id":       asString(m["display_model_name"]),
			"object":   "model",
			"owned_by": "atomcode",
		})
	}
	if s.OrKey != "" {
		for _, m := range config.OpenRouterModels {
			data = append(data, map[string]any{"id": m.ID, "object": "model", "owned_by": "openrouter"})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

// ── /health ─────────────────────────────────────────────────────────────────

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "atomcode2api"})
}

// ── /status：额度状态（5h 窗口水位 + 套餐到期）──────────────────────────────

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) || !s.credGuard(w) {
		return
	}
	st := s.quotaStatus()
	if st == nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "无法获取状态"})
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// quotaStatus 拉 status-v2 并整形成 /status 的输出形状；拉不到（网络失败 /
// 上游空响应）返回 nil。/status 与 /admin/api/overview 共用。
func (s *Server) quotaStatus() map[string]any {
	st := s.Con.Status(s)
	// Python: if not s → 空 dict / None 都算失败
	if len(st) == 0 {
		return nil
	}
	free := asMap(st["codingplan_free"])
	usage := asMap(st["current_usage"])
	if free == nil {
		free = map[string]any{}
	}
	if usage == nil {
		usage = map[string]any{}
	}
	return map[string]any{
		"plan":                free["plan_name"],
		"status":              free["status"],
		"claimed_at":          free["claimed_at"],
		"expires_at":          free["expires_at"],
		"remaining_days":      free["remaining_days"],
		"window_used":         usage["window_tokens_used"],
		"window_limit":        usage["window_token_limit"],
		"window_reset":        usage["reset_at"],
		"seconds_until_reset": usage["seconds_until_reset"],
	}
}

// ── /pool/status：池级全量视图（P3）──────────────────────────────────────────

// poolStatus GET /pool/status：全量账号视图（状态/窗口/冷却/成功率/最近使用/
// 最近错误）+ 池级汇总。/status 的单账号语义不变。
func (s *Server) poolStatus(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	now := time.Now()
	list := []any{}
	healthy := 0
	for _, a := range s.Pool.List() {
		v := accountView(a, now)
		if tot := a.TotalOK + a.TotalFail; tot > 0 {
			v["success_rate"] = float64(a.TotalOK) / float64(tot)
		} else {
			v["success_rate"] = nil
		}
		list = append(list, v)
		if a.Status(now) == "ok" {
			healthy++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accounts":         list,
		"count":            s.Pool.Count(),
		"healthy":          healthy,
		"cap":              pool.MaxAccounts,
		"retry_after_hint": s.Pool.MinCooldownSeconds(),
	})
}

// ── /login、/login/poll：网关自建 OAuth（平台代持流）────────────────────────

func (s *Server) loginStart(w http.ResponseWriter, r *http.Request) {
	if err := s.OAuth.Start(); err != nil {
		s.Log.Error("OAuth 发起失败", slog.String("err", err.Error()))
		writeJSON(w, http.StatusBadGateway, openAIErrorBody(err.Error(), "auth_error"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":    "在浏览器打开以下 URL 完成授权，然后 GET /login/poll 轮询",
		"login_url":  s.OAuth.LoginURL(),
		"expires_in": 600,
	})
}

func (s *Server) loginPoll(w http.ResponseWriter, r *http.Request) {
	// Python: oauth_session.poll() 抛异常（网络失败 / _exchange raise_for_status /
	// JSON 解析错）→ 冒泡到路由 except → 502 {"status":"error","message":...}
	creds, state, perr := s.OAuth.Poll()
	if perr != nil {
		s.Log.Error("OAuth 轮询失败", slog.String("err", perr.Error()))
		writeJSON(w, http.StatusBadGateway, map[string]any{"status": "error", "message": perr.Error()})
		return
	}
	if creds == nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": state})
		return
	}
	sc := creds.ToSaveCreds()
	// P2：OAuth 登录直接入池（accounts/<id>.json），不再写单 auth.json；
	// 同账号重复登录走替换（保留调度统计并清失效标记）。
	acct, err := s.Pool.AddOrReplace(sc)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "message": err.Error()})
		return
	}
	s.cred.Store(acct.Cred)
	s.hasCred.Store(true)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "done",
		"username": creds.User.Username,
		"uid":      creds.User.IDStr(),
		"message":  "登录成功，凭据已入池（accounts/" + acct.ID + ".json），网关已切换到新凭据",
	})
}

// logIn 出 in: 行（对应 routes/chat.py 的 logger.info("[%s] in: ...")；
// 只有 chat 路由打这行，responses/messages 路由没有）。
// ua 是日志里唯一的客户端归因维度（API key 全客户端共用、ip 恒为 127.0.0.1）；
// 折掉换行防伪造多行日志。
func (s *Server) logIn(rid string, r *http.Request, payload map[string]any, bodyLen int) {
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		ua = "-"
	}
	ua = strings.ReplaceAll(strings.ReplaceAll(ua, "\r", " "), "\n", " ")
	msgs := len(asList(payload["messages"]))
	s.Log.Info("in:", slog.String("rid", rid),
		slog.String("line", fmt.Sprintf("model=%s stream=%s msgs=%d | ua=%s | body=%dB",
			asString(payload["model"]), pyVal(truthy(payload["stream"])), msgs, ua, bodyLen)))
}

// doneLog 出 done: 行（"%s %dB %.1fs"）。
func (s *Server) doneLog(rid, kind string, n int, t0 time.Time) {
	s.Log.Info("done:", slog.String("rid", rid),
		slog.String("line", fmt.Sprintf("%s %dB %.1fs", kind, n, time.Since(t0).Seconds())))
}

// ── 响应辅助 ─────────────────────────────────────────────────────────────────

func openAIErrorBody(message, typ string) map[string]any {
	return map[string]any{"error": map[string]any{"message": message, "type": typ}}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(marshalCompact(v))
}

// marshalCompact JSON 紧凑序列化，不转义 HTML 字符（对齐 Python
// json.dumps(..., ensure_ascii=False, separators=(",",":"))）。
func marshalCompact(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return []byte("null")
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// writeRaw 原样回吐上游字节（chat 路由非流式透传用）。
func writeRaw(w http.ResponseWriter, status int, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// sseHeaders 流式响应头。Python 版只设 mimetype="text/event-stream"
// （Flask 会附带 charset=utf-8），未设 Cache-Control/X-Accel-Buffering。
func sseHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
}

// readJSONBody 读请求体（上限 64MB）并解析 JSON object。
// ok=false 对应 Python `not isinstance(body, dict)`（含空 body、非 object、解析失败）。
func readJSONBody(r *http.Request) (map[string]any, int, bool) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if len(raw) == 0 {
		return nil, 0, false
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, len(raw), false
	}
	return m, len(raw), true
}

// sseLineFeed 把上游 SSE body 转成行流（iter.Seq[string]，含 "data:" 前缀的原始行）。
// SSE 的 data 行可能极长（整块 JSON），Scanner 上限放到 8MB。
// 对应 Python resp.iter_lines(decode_unicode=False)（按 \n 切行，去掉行尾）。
func sseLineFeed(r io.Reader) (seq iter.Seq[string], errFn func() error) {
	var readErr error
	errFn = func() error { return readErr }
	seq = func(yield func(string) bool) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for sc.Scan() {
			if !yield(sc.Text()) {
				return
			}
		}
		readErr = sc.Err()
	}
	return seq, errFn
}

// lineTap 在裸字节流转发的同时切出完整 SSE 行（不改变转发字节）。
// chat 路由的伪回复检测需要看到行内容，但仍要原样透传 chunk，故不能走 sseLineFeed。
type lineTap struct {
	carry []byte
}

// feed 喂入一个 chunk，返回其中已完整的行（不含行尾）。
func (t *lineTap) feed(chunk []byte) []string {
	buf := append(t.carry, chunk...)
	var lines []string
	for {
		i := bytes.IndexByte(buf, '\n')
		if i < 0 {
			break
		}
		line := bytes.TrimRight(buf[:i], "\r")
		lines = append(lines, string(line))
		buf = buf[i+1:]
	}
	t.carry = append([]byte(nil), buf...)
	return lines
}

// decodeChatJSON 解析上游 Chat JSON 并取 choices[0].message.content。
// 返回 (解析结果|nil, content)；nil 对应 Python 的 _j = None（解析失败或
// choices[0] 不是 object）。content 非字符串时按空串处理（Python 会 TypeError
// 冒泡成 500，见行为差异清单）。
func decodeChatJSON(body []byte) (map[string]any, string) {
	var j map[string]any
	if json.Unmarshal(body, &j) != nil || j == nil {
		return nil, ""
	}
	list := asList(j["choices"])
	if len(list) == 0 {
		return j, ""
	}
	ch := asMap(list[0])
	if ch == nil {
		return nil, ""
	}
	msg := asMap(ch["message"])
	if msg == nil {
		msg = map[string]any{}
	}
	txt, _ := msg["content"].(string)
	return j, txt
}

// truthy Python 真值语义（日志里 stream=%s 打 bool）。
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// pyVal 以 Python str() 形态渲染 usage 里的数值字段（None / 整数 / 浮点）。
func pyVal(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	}
	return fmt.Sprintf("%v", v)
}

// ── 日志：server.log 2MB×3 轮转 + stdout（与 Python RotatingFileHandler 对齐）──

// NewLogger 建 slog logger：同时写 stdout 与 server.log（2MB 轮转，保 3 份）。
// werkzeug 访问行被禁掉的语义 = Go 侧本来就不打 access log，统一由 done: 汇报。
func NewLogger(dir string) *slog.Logger {
	path := filepath.Join(dir, "server.log")
	rw := &rotateWriter{path: path, maxBytes: 2 << 20, backupCount: 3}
	return slog.New(slog.NewTextHandler(io.MultiWriter(os.Stdout, rw), &slog.HandlerOptions{}))
}

type rotateWriter struct {
	mu          sync.Mutex
	path        string
	maxBytes    int64
	backupCount int
	f           *os.File
	written     int64
}

func (rw *rotateWriter) Write(p []byte) (int, error) {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.f == nil {
		if err := rw.open(); err != nil {
			return 0, err
		}
	}
	if rw.written+int64(len(p)) > rw.maxBytes {
		rw.rotate()
	}
	n, err := rw.f.Write(p)
	rw.written += int64(n)
	return n, err
}

func (rw *rotateWriter) open() error {
	f, err := os.OpenFile(rw.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	rw.f = f
	if info, err := f.Stat(); err == nil {
		rw.written = info.Size()
	}
	return nil
}

// rotate 关闭当前文件，.log.(n-1) → .log.n 链式改名，重开新文件。
func (rw *rotateWriter) rotate() {
	if rw.f != nil {
		rw.f.Close()
		rw.f = nil
	}
	for i := rw.backupCount - 1; i > 0; i-- {
		os.Rename(fmt.Sprintf("%s.%d", rw.path, i), fmt.Sprintf("%s.%d", rw.path, i+1))
	}
	os.Rename(rw.path, rw.path+".1")
	rw.written = 0
	_ = rw.open()
}
