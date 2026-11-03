// 面板 OAuth 登录向导（P7）：把 /login 单例轮询流包装成多会话的面板 API。
//
// 复用链路：lanes.OAuthLogin（acs.atomgit.com 平台代持流：/auth/login 拿
// login_url+state → 用户浏览器授权 → /auth/check 轮询 → /auth/token 一次性
// 换凭据），入池走 Pool.AddOrReplace（与 server.go loginPoll 同一条）。
// 差异：旧 /login 是进程级单例（两会话互相覆盖）；这里每个向导会话一个独立
// OAuthLogin 实例 + 随机 session id，并发互不干扰，TTL 10 分钟。
// 安全：state 日志只留前 8 位；凭据/token 永不进日志与响应体（只回账号名与套餐）。
package handler

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"atomcode2api/internal/lanes"
)

const panelOAuthTTL = 10 * time.Minute // 与 lanes.oauthTTL 一致

// panelOAuthSess 一次向导登录会话。
type panelOAuthSess struct {
	o       *lanes.OAuthLogin
	created time.Time
}

// oauthStart POST /admin/api/oauth/start：发起一次登录会话。
// 返回 {session_id, login_url, expires_in}；guard（会话/API_KEY）已在路由层。
func (s *Server) oauthStart(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	o := lanes.NewOAuthLogin()
	if s.OAuthBase != "" { // 测试注入
		o.Base = s.OAuthBase
	}
	if err := o.Start(); err != nil {
		s.Log.Error("面板 OAuth 发起失败", slog.String("err", err.Error()))
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok": false, "error": "发起授权会话失败：" + err.Error()})
		return
	}
	sid := newSessionID()
	s.oauthSessMu.Lock()
	if s.oauthSess == nil {
		s.oauthSess = make(map[string]*panelOAuthSess)
	}
	s.oauthSess[sid] = &panelOAuthSess{o: o, created: time.Now()}
	// 顺手清扫过期会话（避免只增不减）
	for id, sess := range s.oauthSess {
		if time.Since(sess.created) > panelOAuthTTL {
			delete(s.oauthSess, id)
		}
	}
	s.oauthSessMu.Unlock()
	s.Log.Info("面板 OAuth 会话已发起", slog.String("session", sid[:8]))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "session_id": sid, "login_url": o.LoginURL(), "expires_in": int(panelOAuthTTL.Seconds()),
	})
}

// oauthPoll POST /admin/api/oauth/poll {"session_id"}：查一次进度。
// waiting → 前端继续轮；done → 已入池（返回账号名/套餐）；其余给具体中文原因。
// 完成后会话即销毁——重复提交同一 session_id 明确报"会话不存在或已完成"。
func (s *Server) oauthPoll(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	body, _, ok := readJSONBody(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "需要 JSON 请求体"})
		return
	}
	sid := asString(body["session_id"])
	s.oauthSessMu.Lock()
	sess := s.oauthSess[sid]
	s.oauthSessMu.Unlock()
	if sess == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"ok": false, "status": "gone", "error": "会话不存在、已完成或已过期，请重新发起"})
		return
	}
	if time.Since(sess.created) > panelOAuthTTL {
		s.dropOAuthSess(sid)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": false, "status": "expired", "error": "授权会话已超时（10 分钟），请重新发起"})
		return
	}
	creds, state, perr := sess.o.Poll()
	if perr != nil {
		s.Log.Error("面板 OAuth 轮询失败", slog.String("session", sid[:8]), slog.String("err", perr.Error()))
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok": false, "status": "error", "error": "与授权平台通信失败：" + perr.Error()})
		return
	}
	if creds == nil {
		// state 可能是 "waiting" 或 lanes 侧的超时/未发起说明
		if strings.Contains(state, "超时") {
			s.dropOAuthSess(sid)
			writeJSON(w, http.StatusOK, map[string]any{
				"ok": false, "status": "expired", "error": "授权会话已超时（10 分钟），请重新发起"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "waiting"})
		return
	}
	// 完成：入池（同账号重登走替换，保留统计并清失效——与 /login/poll 同语义）
	acct, err := s.Pool.AddOrReplace(creds.ToSaveCreds())
	s.dropOAuthSess(sid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok": false, "status": "error", "error": "入池失败：" + err.Error()})
		return
	}
	s.Log.Info("面板 OAuth 登录完成", slog.String("username", acct.Username))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "status": "done",
		"account": map[string]any{"id": acct.ID, "username": acct.Username, "plan": acct.Plan},
	})
}

// dropOAuthSess 删除会话（完成/过期后一次性销毁，防重放）。
func (s *Server) dropOAuthSess(sid string) {
	s.oauthSessMu.Lock()
	delete(s.oauthSess, sid)
	s.oauthSessMu.Unlock()
}

// newSessionID 128 位随机会话 id（hex）。
func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
