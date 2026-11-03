// /admin 控制面：内置面板页 + overview / refresh-token 两个面板后端。
// panel.html 内嵌一份（//go:embed），状态目录里有同名文件时优先用用户的——
// 内置版只是让 /admin 开箱即用，不依赖手动安装步骤。
package handler

import (
	_ "embed"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"atomcode2api/internal/config"
	"atomcode2api/internal/lanes"
	"atomcode2api/internal/pool"
)

//go:embed panel.html
var panelBuiltin []byte

// servePanel 输出面板 HTML：状态目录 panel.html > 内置版。
func (s *Server) servePanel(w http.ResponseWriter, _ *http.Request) {
	raw, err := os.ReadFile(s.Cfg.StateFilePath("panel.html"))
	if err != nil || len(raw) == 0 {
		raw = panelBuiltin
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(raw)
}

// overview GET /admin/api/overview：面板概览数据。
// 形状 {credential:{valid,.../status 同形的套餐字段}, models, local_auth}；
// 凭据无效时仍返回（valid=false），模型拉取失败时置空——面板要能展示"未登录"，
// 所以这里不走 credGuard。
func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	credential := map[string]any{"valid": false}
	if c := s.credOrNil(); c != nil {
		credential["valid"] = true
		credential["username"] = c.Username()
		credential["uid"] = c.UserID()
		// token 本体到期时间（凭据自动续期后跟着变），与套餐到期区分
		if e := c.ExpiresAt(); e > 0 {
			credential["token_expires_at"] = e
		}
		// /status 同形的套餐与 5h 窗口字段；拉不到不影响其余展示
		if st := s.quotaStatus(); st != nil {
			for k, v := range st {
				credential[k] = v
			}
		}
	}
	models := []any{}
	if up, err := s.Con.Models(s); err == nil {
		for _, m := range up {
			// plan_available 缺省 true（与 /v1/models 一致）
			if v, ok := m["plan_available"].(bool); ok && !v {
				continue
			}
			models = append(models, map[string]any{
				"id":       asString(m["display_model_name"]),
				"owned_by": "atomcode",
			})
		}
	}
	if s.OrKey != "" {
		for _, m := range config.OpenRouterModels {
			models = append(models, map[string]any{"id": m.ID, "owned_by": "openrouter"})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"credential": credential,
		"models":     models,
		"local_auth": s.currentAPIKey() != "",
	})
}

// adminClaim POST /admin/api/claim：按 Max → Pro → Lite 级联领取免费 CodingPlan。
// ?preview=1 只查状态不领取。幂等——已持有（duplicate）不会重复领。
func (s *Server) adminClaim(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Get("preview") == "1" {
		st := s.Con.Status(s)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "preview": true, "status": st})
		return
	}
	res := s.Con.ClaimBest(s)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     res.OK,
		"tier":   res.Tier,
		"plan":   res.Plan,
		"held":   res.Held,
		"message": res.Message,
	})
}

// ── /admin/api/accounts：账号池管理（P1）─────────────────────────────────────

// accountView 账号的面板展示 JSON。
func accountView(a *pool.Account, now time.Time) map[string]any {
	cooldownSec := 0
	if d := a.CooldownUntil.Sub(now); d > 0 {
		cooldownSec = int(d.Seconds())
	}
	return map[string]any{
		"id":                 a.ID,
		"username":           a.Username,
		"status":             a.Status(now),
		"plan":               a.Plan,
		"plan_expires_at":    a.PlanExpiresAt,
		"window_used":        a.WindowUsed,
		"window_limit":       a.WindowLimit,
		"window_reset":       a.WindowReset,
		"cooldown_until":     a.CooldownUntil,
		"cooldown_remaining": cooldownSec,
		"consec_fail":        a.ConsecFail,
		"total_ok":           a.TotalOK,
		"total_fail":         a.TotalFail,
		"last_used":          a.LastUsed,
		"last_error":         a.LastError,
		"added_at":           a.AddedAt,
		"disabled":           a.Disabled,
		"next_claim_at":      a.NextClaimAt,
	}
}

// accountsList GET /admin/api/accounts：池内全部账号 + 上限。
func (s *Server) accountsList(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	now := time.Now()
	list := []any{}
	for _, a := range s.Pool.List() {
		list = append(list, accountView(a, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accounts": list, "count": s.Pool.Count(), "cap": pool.MaxAccounts,
	})
}

// accountsAdd POST /admin/api/accounts {"toml": "<auth.toml 内容>"}：
// 解析 → 查重 → 落盘 → 校验（RT 活性 + status-v2 校准）。校验失败账号仍入库，
// 状态 auth_invalid（绝不静默——响应里带上具体 last_error）。
func (s *Server) accountsAdd(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	body, _, ok := readJSONBody(r)
	if !ok || asString(body["toml"]) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "error": "请求体需为 {\"toml\": \"<auth.toml 内容>\"}"})
		return
	}
	sc, err := lanes.ParseAuthTOML([]byte(asString(body["toml"])))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "error": "auth.toml 解析失败: " + err.Error()})
		return
	}
	if sc.AccessToken == "" || sc.RefreshToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "error": "凭据缺少 access_token / refresh_token"})
		return
	}
	a, err := s.Pool.Add(sc, true)
	if errors.Is(err, pool.ErrDuplicate) {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.Log.Info("账号池新增账号", "account", a.Username, "id", a.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "account": accountView(a, time.Now())})
}

// accountsBatch POST /admin/api/accounts/batch {"text": "..."}：批量导入（P3）。
// 条目间用单独一行 --- 分隔；每条自动识别 JSON（auth.json 形状）或 TOML，
// 逐条校验（同单条录入管线），单条失败不中断整批。
func (s *Server) accountsBatch(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	body, _, ok := readJSONBody(r)
	if !ok || asString(body["text"]) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "error": `请求体需为 {"text": "条目1\n---\n条目2\n..."}`})
		return
	}
	items := splitBatchText(asString(body["text"]))
	if len(items) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "未解析到任何条目"})
		return
	}
	results := []any{}
	imported, skipped, failed := 0, 0, 0
	for i, item := range items {
		res := map[string]any{"index": i + 1}
		sc, perr := parseCredAuto(item)
		switch {
		case perr != nil:
			res["ok"], res["error"] = false, "解析失败: "+perr.Error()
			failed++
		case sc.AccessToken == "" || sc.RefreshToken == "":
			res["ok"], res["error"] = false, "缺少 access_token / refresh_token"
			failed++
		default:
			a, aerr := s.Pool.Add(sc, true)
			switch {
			case errors.Is(aerr, pool.ErrDuplicate):
				res["ok"], res["skipped"] = true, "duplicate"
				res["error"] = "账号已存在（refresh token 或 user.id 重复）"
				skipped++
			case aerr != nil:
				res["ok"], res["error"] = false, aerr.Error()
				failed++
			default:
				res["ok"] = true
				res["id"], res["username"] = a.ID, a.Username
				res["status"] = a.Status(time.Now())
				if a.LastError != "" {
					res["last_error"] = a.LastError
				}
				imported++
			}
		}
		results = append(results, res)
	}
	s.Log.Info("账号池批量导入", "imported", imported, "skipped", skipped, "failed", failed)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "imported": imported, "skipped": skipped, "failed": failed,
		"results": results,
	})
}

// splitBatchText 按单独一行的 --- 切分批量导入文本，空条目跳过。
func splitBatchText(text string) []string {
	var items []string
	var cur []string
	flush := func() {
		joined := strings.TrimSpace(strings.Join(cur, "\n"))
		if joined != "" {
			items = append(items, joined)
		}
		cur = nil
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "---" {
			flush()
			continue
		}
		cur = append(cur, line)
	}
	flush()
	return items
}

// parseCredAuto 自动识别凭据格式：{ 开头按 auth.json（JSON），否则按 auth.toml。
func parseCredAuto(text string) (lanes.SaveCreds, error) {
	if strings.HasPrefix(strings.TrimSpace(text), "{") {
		return lanes.ParseAuthJSON([]byte(text))
	}
	return lanes.ParseAuthTOML([]byte(text))
}

// ── /admin/api/auth：API 鉴权密钥管理（P4）────────────────────────────────────
//
// 安全取舍：写入类端点（设置/清除/禁用）仅允许回环地址调用。
// /admin 面板本身无鉴权是既定事实（本地工具定位）；但密钥写入是提权操作，
// 回环限制能在「0.0.0.0 监听」误暴露时挡住局域网改钥，同时不把合法的
// 本机用户锁在门外。反代暴露场景的运维应在反代层加保护（README 已注明）。

// writeGate 写操作闸门：回环 或 有效面板会话 二选一。
// 面板密码已是真实闸门时，登录会话的远程运维与回环等权；
// 无密码裸奔部署时远程写继续拒绝（loopbackOnly 原语义保住）。
func (s *Server) writeGate(w http.ResponseWriter, r *http.Request) bool {
	if isLoopbackAddr(r.RemoteAddr) || s.validSession(r) {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]any{
		"ok": false, "error": "写操作仅允许本机（回环）或已登录面板会话"})
	return false
}

// isLoopbackAddr 判定 RemoteAddr 是否回环。
func isLoopbackAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// loopbackOnly 写操作回环闸门：非回环 RemoteAddr → 403。
func (s *Server) loopbackOnly(w http.ResponseWriter, r *http.Request) bool {
	if isLoopbackAddr(r.RemoteAddr) {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]any{
		"ok": false, "error": "仅允许本机（回环）操作"})
	return false
}

// authView 当前鉴权状态视图。
func (s *Server) authView() map[string]any {
	key := s.currentAPIKey()
	return map[string]any{
		"enabled":       key != "",
		"masked_key":    maskKey(key),
		"source":        s.authSourceLabel(),
		"panel_set":     s.settings.APIKey != "",
		"env_present":   s.Cfg.APIKey != "",
		"auth_disabled": s.settings.AuthDisabled,
		// 面板密码状态（P5）：诊断页密码卡片与登出按钮的显示依据
		"panel_password_set": s.settings.PanelPasswordHash != "",
	}
}

// ── /admin/api/auth：API 鉴权密钥管理（P4）────────────────────────────────────
//
// 安全取舍：写入类端点（设置/清除/禁用）仅允许回环地址调用。
// /admin 面板本身无鉴权是既定事实（本地工具定位）；但密钥写入是提权操作，
// 回环限制能在「0.0.0.0 监听」误暴露时挡住局域网改钥，同时不把合法的
// 本机用户锁在门外。反代暴露场景的运维应在反代层加保护（README 已注明）。
//
// 防锁死（2026-11-03 事故修复）：这三个端点**刻意不挂 API_KEY 闸门**——
// 密钥一旦生效，面板必须仍能打开、读状态、清除密钥，否则没有任何入口能
// 解除（用户实测被锁）。回环闸门保留为唯一写保护。回环上的本机进程本来
// 就能直接改 settings.json，闸门不制造虚假安全。

// authGet GET /admin/api/auth：查看当前状态（掩码，不回传明文）。不挂
// API_KEY 闸门——它是锁定状态下唯一的状态读取与自救入口。
func (s *Server) authGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.authView())
}

// authSetKey POST /admin/api/auth {"api_key":"..."}：设置面板密钥（热生效）。
// {"api_key":""} 表示清除面板值 → 回落环境变量。
// {"generate":true} 只生成不落盘（生成与保存分离——直接保存+启用曾把用户
// 锁在门外：toast 3.5s 后密钥永不可见）。仅回环可写。
func (s *Server) authSetKey(w http.ResponseWriter, r *http.Request) {
	if !s.writeGate(w, r) {
		return
	}
	body, _, ok := readJSONBody(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "需要 JSON 请求体"})
		return
	}
	if truthy(body["generate"]) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "generated_key": genAPIKey()})
		return
	}
	key := asString(body["api_key"])
	if key == "" {
		// 清除面板值（回落 env；要彻底关用 /disable）
		s.settings.APIKey = ""
	} else {
		if err := validateAPIKey(key); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		s.settings.APIKey = key
	}
	if err := s.settings.save(s.Cfg.StateDir); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.recomputeAuth()
	s.Log.Info("API 鉴权密钥已更新", "source", s.authSourceLabel())
	out := s.authView()
	out["ok"] = true
	writeJSON(w, http.StatusOK, out)
}

// authDisable POST /admin/api/auth/disable {"disable":true|false}：
// 显式关闭/恢复鉴权（压过环境变量；UI 侧已二次确认+风险提示）。仅回环可写。
func (s *Server) authDisable(w http.ResponseWriter, r *http.Request) {
	if !s.writeGate(w, r) {
		return
	}
	body, _, ok := readJSONBody(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "需要 JSON 请求体"})
		return
	}
	s.settings.AuthDisabled = truthy(body["disable"])
	if err := s.settings.save(s.Cfg.StateDir); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.recomputeAuth()
	s.Log.Warn("鉴权开关已切换", "auth_disabled", s.settings.AuthDisabled)
	out := s.authView()
	out["ok"] = true
	writeJSON(w, http.StatusOK, out)
}

// accountsDelete DELETE /admin/api/accounts/{id}。
func (s *Server) accountsDelete(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.Pool.Remove(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.Log.Info("账号池删除账号", "id", id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// accountsDisable POST /admin/api/accounts/{id}/disable。
func (s *Server) accountsDisable(w http.ResponseWriter, r *http.Request) {
	s.accountsFlag(w, r, true)
}

// accountsEnable POST /admin/api/accounts/{id}/enable。
func (s *Server) accountsEnable(w http.ResponseWriter, r *http.Request) {
	s.accountsFlag(w, r, false)
}

func (s *Server) accountsFlag(w http.ResponseWriter, r *http.Request, disabled bool) {
	if !s.guard(w, r) {
		return
	}
	if err := s.Pool.SetDisabled(r.PathValue("id"), disabled); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// accountsReset POST /admin/api/accounts/{id}/reset：清冷却/失败计数/auth_invalid。
func (s *Server) accountsReset(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	if err := s.Pool.ResetState(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// adminRefresh POST /admin/api/refresh-token：强制刷新当前凭据（诊断页用）。
// Refresh 产出的新凭据落网关独立凭据文件 auth.json（不再回写 auth.toml）。
func (s *Server) adminRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	if err := s.Refresh(); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "已刷新（auth.json）"})
}
