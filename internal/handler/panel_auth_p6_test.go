// P6 面板会话与 API_KEY 协作测试：会话可替代 API_KEY 访问 /admin/api/*，
// 写闸门 = 回环或会话；两套鉴权互不越权。
package handler

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// p6Fixture：API_KEY + 面板密码同时生效的服务器，返回已登录会话 cookie。
func p6Fixture(t *testing.T) (*Server, string) {
	t.Helper()
	up := &authSwitch{decide: func(string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)
	s.settings.APIKey = "sk-p6-test"
	s.settings.PanelPasswordHash, _ = hashPassword("pw-p6-1234")
	s.recomputeAuth()
	w := httptest.NewRecorder()
	s.issueSession(w)
	return s, w.Header().Get("Set-Cookie")
}

func p6Req(s *Server, method, path, body, cookie, auth, remote string) *httptest.ResponseRecorder {
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = remote
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

// 会话替代 API_KEY 访问 /admin/api/*；失效会话回落 API_KEY 校验；
// 会话优先于错误的 localStorage 密钥；/v1/* 不被面板会话越权。
func TestSessionSubstitutesAPIKey(t *testing.T) {
	s, cookie := p6Fixture(t)

	// 远程 + 会话 + 无 API_KEY → /admin/api/overview 200（不再二次要密钥）
	if r := p6Req(s, "GET", "/admin/api/overview", "", cookie, "", "203.0.113.9:1111"); r.Code != 200 {
		t.Fatalf("会话访问 overview 应 200，得 %d", r.Code)
	}
	// 远程 + 会话 + 错误的 Authorization 头 → 仍 200（会话优先，不被旧密钥干扰）
	if r := p6Req(s, "GET", "/admin/api/overview", "", cookie, "stale-wrong-key", "203.0.113.9:1111"); r.Code != 200 {
		t.Fatalf("会话+错误密钥头应 200，得 %d", r.Code)
	}
	// 远程 + 无会话 + 无密钥 → 401
	if r := p6Req(s, "GET", "/admin/api/overview", "", "", "", "203.0.113.9:1111"); r.Code != 401 {
		t.Fatalf("无会话无密钥应 401，得 %d", r.Code)
	}
	// 远程 + 无会话 + 正确 API_KEY → 200（API_KEY 语义不变）
	if r := p6Req(s, "GET", "/admin/api/overview", "", "", "sk-p6-test", "203.0.113.9:1111"); r.Code != 200 {
		t.Fatalf("API_KEY 访问应 200，得 %d", r.Code)
	}
	// 过期/篡改会话 → 回落 API_KEY → 401
	bad := sessionCookieName + "=9999999999|deadbeef|00"
	if r := p6Req(s, "GET", "/admin/api/overview", "", bad, "", "203.0.113.9:1111"); r.Code != 401 {
		t.Fatalf("坏会话应回落 401，得 %d", r.Code)
	}
	// 面板会话不越权数据面：/v1 仍按 API_KEY
	chat := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`
	if r := p6Req(s, "POST", "/v1/chat/completions", chat, cookie, "", "203.0.113.9:1111"); r.Code != 401 {
		t.Fatalf("面板会话不应开 /v1，得 %d", r.Code)
	}
	if r := p6Req(s, "POST", "/v1/chat/completions", chat, "", "sk-p6-test", "203.0.113.9:1111"); r.Code != 200 {
		t.Fatalf("API_KEY 开 /v1 应 200，得 %d", r.Code)
	}
	// /pool/status 对外语义不变：会话不顶用
	if r := p6Req(s, "GET", "/pool/status", "", cookie, "", "203.0.113.9:1111"); r.Code != 401 {
		t.Fatalf("/pool/status 不认会话，得 %d", r.Code)
	}
}

// 写闸门 = 回环 或 会话。
func TestWriteGate(t *testing.T) {
	s, cookie := p6Fixture(t)

	// 远程 + 会话 → generate 200（且不落盘）
	r := p6Req(s, "POST", "/admin/api/auth", `{"generate":true}`, cookie, "", "203.0.113.9:1111")
	if r.Code != 200 {
		t.Fatalf("远程+会话 generate 应 200，得 %d", r.Code)
	}
	var g map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &g)
	if g["generated_key"] == nil {
		t.Fatal("应返回 generated_key")
	}
	if s.settings.APIKey != "sk-p6-test" {
		t.Fatal("generate 不应改密钥")
	}
	// 远程 + 会话 → 保存密钥 200
	if r := p6Req(s, "POST", "/admin/api/auth", `{"api_key":"sk-remote-set-1"}`, cookie, "", "203.0.113.9:1111"); r.Code != 200 {
		t.Fatalf("远程+会话保存应 200，得 %d", r.Code)
	}
	// 本机回环无会话 → 写仍 200（原语义）
	if r := p6Req(s, "POST", "/admin/api/auth", `{"generate":true}`, "", "", "127.0.0.1:2222"); r.Code != 200 {
		t.Fatalf("回环写应 200，得 %d", r.Code)
	}
	// 远程 + 无会话 → 403（无密码裸奔保护）
	if r := p6Req(s, "POST", "/admin/api/auth", `{"api_key":"sk-hack-hack"}`, "", "", "203.0.113.9:1111"); r.Code != 403 {
		t.Fatalf("远程无会话写应 403，得 %d", r.Code)
	}
	if s.settings.APIKey != "sk-remote-set-1" {
		t.Fatal("403 不应改密钥")
	}
}

// 无面板密码时：远程写仍 403；读与自救通道不破。
func TestWriteGateNoPassword(t *testing.T) {
	up := &authSwitch{decide: func(string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)
	s.settings.APIKey = "sk-p6-nopw"
	s.recomputeAuth() // 无面板密码

	// 远程无会话写 → 403
	if r := p6Req(s, "POST", "/admin/api/auth", `{"api_key":""}`, "", "", "203.0.113.9:1111"); r.Code != 403 {
		t.Fatalf("无密码远程写应 403，得 %d", r.Code)
	}
	// 远程读 /admin → 200（面板可读）
	if r := p6Req(s, "GET", "/admin", "", "", "", "203.0.113.9:1111"); r.Code != 200 {
		t.Fatalf("/admin 读应 200，得 %d", r.Code)
	}
	// 自救：回环清除密钥 → 200（P4 通道不破）
	if r := p6Req(s, "POST", "/admin/api/auth", `{"api_key":""}`, "", "", "127.0.0.1:2222"); r.Code != 200 {
		t.Fatalf("回环自救清除应 200，得 %d", r.Code)
	}
	if s.currentAPIKey() != "" {
		t.Fatal("清除后应无密钥")
	}
}

// 会话吊销语义保持：改密后旧会话访问 /admin/api/* → 回落 API_KEY → 401。
func TestSessionRevocationStillHolds(t *testing.T) {
	s, cookie := p6Fixture(t)
	// 改密（带当前密码 + 旧会话，回环）
	r := p6Req(s, "POST", "/admin/api/password", `{"current_password":"pw-p6-1234","new_password":"pw-p6-5678"}`, cookie, "", "127.0.0.1:2222")
	if r.Code != 200 {
		t.Fatalf("改密应 200，得 %d", r.Code)
	}
	// 旧会话访问数据接口 → 401（会话已吊销，且无 API_KEY）
	if r := p6Req(s, "GET", "/admin/api/overview", "", cookie, "", "203.0.113.9:1111"); r.Code != 401 {
		t.Fatalf("改密后旧会话应 401，得 %d", r.Code)
	}
	// 新密码登录 → 新会话可用
	r = p6Req(s, "POST", "/admin/api/login", `{"password":"pw-p6-5678"}`, "", "", "127.0.0.1:2222")
	if r.Code != 200 {
		t.Fatalf("新密码登录应 200，得 %d", r.Code)
	}
	ck2 := r.Header().Get("Set-Cookie")
	if r := p6Req(s, "GET", "/admin/api/overview", "", ck2, "", "203.0.113.9:1111"); r.Code != 200 {
		t.Fatalf("新会话应 200，得 %d", r.Code)
	}
}

// 登录页面板密码时 /admin 给登录页而非数据（回归）。
func TestLoginPageRegression(t *testing.T) {
	s, _ := p6Fixture(t)
	r := p6Req(s, "GET", "/admin", "", "", "", "203.0.113.9:1111")
	if r.Code != 200 || !strings.Contains(r.Body.String(), `id="pw"`) {
		t.Fatalf("未登录应见登录页，得 %d", r.Code)
	}
}

// 防空洞回归：设了面板密码但没设 API_KEY 时，/admin/api/* 对无会话远程
// 也必须 401（不能因「密钥未配置」整段放行）。
func TestNoHolePasswordOnly(t *testing.T) {
	up := &authSwitch{decide: func(string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)
	s.settings.PanelPasswordHash, _ = hashPassword("pw-only-123")
	s.recomputeAuth() // 无 API_KEY

	if r := p6Req(s, "GET", "/admin/api/overview", "", "", "", "203.0.113.9:1111"); r.Code != 401 {
		t.Fatalf("只设密码时无会话应 401，得 %d", r.Code)
	}
	// 登录后的会话可进
	w := httptest.NewRecorder()
	s.issueSession(w)
	if r := p6Req(s, "GET", "/admin/api/overview", "", w.Header().Get("Set-Cookie"), "", "203.0.113.9:1111"); r.Code != 200 {
		t.Fatalf("只设密码时会话应 200，得 %d", r.Code)
	}
	// /v1 无密钥配置 → 开放（数据面语义不变）
	chat := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`
	if r := p6Req(s, "POST", "/v1/chat/completions", chat, "", "", "203.0.113.9:1111"); r.Code != 200 {
		t.Fatalf("无 API_KEY 时 /v1 应开放，得 %d", r.Code)
	}
}
