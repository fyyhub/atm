// P7 面板 OAuth 向导测试：httptest mock acs 三端点，覆盖成功入池、过期、
// 无会话、上游拒绝、重复提交、并发会话隔离、guard 不放宽。
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// acsMock 模拟 acs.atomgit.com 的 /auth/login|check|token。
// checkValid 控制 check 是否判已授权；tokenStatus/tokenBody 控制交换结果。
type acsMock struct {
	*httptest.Server
	checkValid  *bool
	tokenStatus int
	tokenBody   string
}

func newACSMock() *acsMock {
	m := &acsMock{tokenStatus: 200, tokenBody: `{
		"access_token":"at-mock","token_type":"Bearer","refresh_token":"rt-mock",
		"expires_in":604800,"user":{"id":"u-mock-1","username":"mockuser","name":"Mock","email":"m@example.com"}}`}
	valid := false
	m.checkValid = &valid
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/login":
			state := r.URL.Query().Get("provider") + "-state-12345"
			fmt.Fprintf(w, `{"state":%q,"login_url":"https://atomgit.com/login/oauth/authorize?state=%s"}`, state, state)
		case "/auth/check":
			fmt.Fprintf(w, `{"valid":%v}`, *m.checkValid)
		case "/auth/token":
			w.WriteHeader(m.tokenStatus)
			fmt.Fprint(w, m.tokenBody)
		default:
			w.WriteHeader(404)
		}
	}))
	return m
}

func oauthPost(s *Server, path string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func oauthFixture(t *testing.T) (*Server, *acsMock) {
	t.Helper()
	up := &authSwitch{decide: func(string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)
	m := newACSMock()
	t.Cleanup(m.Close)
	s.OAuthBase = m.URL
	return s, m
}

// 正常三步：start → waiting → check 翻真 → done 入池。
func TestOAuthWizardSuccess(t *testing.T) {
	s, m := oauthFixture(t)

	r := oauthPost(s, "/admin/api/oauth/start", map[string]any{})
	var st struct {
		OK        bool   `json:"ok"`
		SessionID string `json:"session_id"`
		LoginURL  string `json:"login_url"`
		ExpiresIn int    `json:"expires_in"`
	}
	if json.Unmarshal(r.Body.Bytes(), &st); !st.OK || st.SessionID == "" || st.LoginURL == "" || st.ExpiresIn != 600 {
		t.Fatalf("start 响应异常: %s", r.Body.String())
	}
	// 未授权 → waiting
	r = oauthPost(s, "/admin/api/oauth/poll", map[string]any{"session_id": st.SessionID})
	var w1 map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &w1)
	if w1["status"] != "waiting" {
		t.Fatalf("未授权应 waiting: %s", r.Body.String())
	}
	// 授权完成 → done + 入池
	*m.checkValid = true
	r = oauthPost(s, "/admin/api/oauth/poll", map[string]any{"session_id": st.SessionID})
	var d struct {
		OK      bool   `json:"ok"`
		Status  string `json:"status"`
		Account struct {
			Username string `json:"username"`
			Plan     string `json:"plan"`
		} `json:"account"`
	}
	if json.Unmarshal(r.Body.Bytes(), &d); !d.OK || d.Status != "done" {
		t.Fatalf("应 done: %s", r.Body.String())
	}
	if d.Account.Username != "mockuser" {
		t.Fatalf("账号名: %+v", d.Account)
	}
	if s.Pool.Count() != 2 { // fixture 1 + 新入池 1
		t.Fatalf("池应有 2 账号，得 %d", s.Pool.Count())
	}
	// 重复提交同一会话 → 明确 404 gone（幂等：不重复入池）
	r = oauthPost(s, "/admin/api/oauth/poll", map[string]any{"session_id": st.SessionID})
	if r.Code != 404 {
		t.Fatalf("重复提交应 404，得 %d", r.Code)
	}
	if s.Pool.Count() != 2 {
		t.Fatal("重复提交不应重复入池")
	}
}

// 会话过期 → expired 明确提示。
func TestOAuthWizardExpired(t *testing.T) {
	s, _ := oauthFixture(t)
	r := oauthPost(s, "/admin/api/oauth/start", map[string]any{})
	var st map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &st)
	sid := st["session_id"].(string)
	// 手动把会话时间拨到 11 分钟前
	s.oauthSessMu.Lock()
	s.oauthSess[sid].created = time.Now().Add(-11 * time.Minute)
	s.oauthSessMu.Unlock()
	r = oauthPost(s, "/admin/api/oauth/poll", map[string]any{"session_id": sid})
	var res map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &res)
	if res["status"] != "expired" || !strings.Contains(res["error"].(string), "超时") {
		t.Fatalf("应 expired 明确提示: %s", r.Body.String())
	}
	// 过期后会话被清
	if r := oauthPost(s, "/admin/api/oauth/poll", map[string]any{"session_id": sid}); r.Code != 404 {
		t.Fatalf("过期清理后应 404，得 %d", r.Code)
	}
}

// 上游拒绝（token 交换 4xx）→ 可读错误，不入池。
func TestOAuthWizardUpstreamReject(t *testing.T) {
	s, m := oauthFixture(t)
	m.tokenStatus = 400
	m.tokenBody = `{"error":"invalid_grant","error_description":"refresh_token不存在或已过期"}`
	r := oauthPost(s, "/admin/api/oauth/start", map[string]any{})
	var st map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &st)
	*m.checkValid = true
	r = oauthPost(s, "/admin/api/oauth/poll", map[string]any{"session_id": st["session_id"]})
	if r.Code != 502 {
		t.Fatalf("上游拒绝应 502，得 %d", r.Code)
	}
	var res map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &res)
	if !strings.Contains(res["error"].(string), "授权平台") {
		t.Fatalf("错误应可读: %s", r.Body.String())
	}
	if s.Pool.Count() != 1 {
		t.Fatal("失败不应入池")
	}
}

// 并发两会话互不干扰：各自独立 state，先后完成不串号。
func TestOAuthWizardConcurrent(t *testing.T) {
	s, m := oauthFixture(t)
	start := func() string {
		r := oauthPost(s, "/admin/api/oauth/start", map[string]any{})
		var st map[string]any
		_ = json.Unmarshal(r.Body.Bytes(), &st)
		return st["session_id"].(string)
	}
	s1, s2 := start(), start()
	if s1 == s2 {
		t.Fatal("两会话 id 应不同")
	}
	// 只完成 s1
	*m.checkValid = true
	r := oauthPost(s, "/admin/api/oauth/poll", map[string]any{"session_id": s1})
	var res map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &res)
	if res["status"] != "done" {
		t.Fatalf("s1 应完成: %s", r.Body.String())
	}
	// s2 不受影响：会话还在且能独立完成；mock 返回同一用户 → 同账号重登走替换，
	// 池不重复计数（AddOrReplace 语义），关键是 s1 的销毁不影响 s2。
	r = oauthPost(s, "/admin/api/oauth/poll", map[string]any{"session_id": s2})
	res = map[string]any{}
	_ = json.Unmarshal(r.Body.Bytes(), &res)
	if res["status"] != "done" {
		t.Fatalf("s2 应独立完成: %s", r.Body.String())
	}
	if s.Pool.Count() != 2 { // fixture 1 + 同一用户替换 1
		t.Fatalf("同用户重登应替换不新增，池应有 2，得 %d", s.Pool.Count())
	}
}

// guard 不放宽：设了 API_KEY 时无凭证访问 start/poll → 401；/v1 仍只认 API_KEY。
func TestOAuthWizardGuard(t *testing.T) {
	s, _ := oauthFixture(t)
	s.settings.APIKey = "sk-p7-test"
	s.recomputeAuth()
	req := httptest.NewRequest(http.MethodPost, "/admin/api/oauth/start", strings.NewReader("{}"))
	req.RemoteAddr = "203.0.113.9:1111"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("无凭证远程 start 应 401，得 %d", w.Code)
	}
	// 带 API_KEY → 200
	req = httptest.NewRequest(http.MethodPost, "/admin/api/oauth/start", strings.NewReader("{}"))
	req.RemoteAddr = "203.0.113.9:1111"
	req.Header.Set("Authorization", "Bearer sk-p7-test")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("带 API_KEY 应 200，得 %d", w.Code)
	}
}
