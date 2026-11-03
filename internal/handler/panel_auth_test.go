// P5 面板登录保护测试：哈希/会话/闸门/限速/恢复路径。
package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// signForTest 用服务器当前会话密钥给消息签名（构造过期 cookie 用）。
func signForTest(s *Server, msg string) string {
	mac := hmac.New(sha256.New, s.sessionSecret())
	_, _ = mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func itoaI(v int64) string { return strconv.FormatInt(v, 10) }

// PBKDF2 哈希与校验：回环、错密码拒绝、坏格式拒绝、常量时间比较路径。
func TestPasswordHash(t *testing.T) {
	h1, err := hashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h1, "pbkdf2$210000$") {
		t.Fatalf("格式: %q", h1)
	}
	if !verifyPassword("correct horse battery", h1) {
		t.Fatal("正确密码应通过")
	}
	if verifyPassword("wrong", h1) {
		t.Fatal("错密码应拒绝")
	}
	for _, bad := range []string{"", "plain", "pbkdf2$x$zz$yy", "argon2$1$aa$bb"} {
		if verifyPassword("correct horse battery", bad) {
			t.Fatalf("坏格式 %q 应拒绝", bad)
		}
	}
	// 同密码两次哈希不同（随机盐）
	h2, _ := hashPassword("correct horse battery")
	if h1 == h2 {
		t.Fatal("同密码两次哈希应不同（随机盐）")
	}
	// 强度校验
	if validatePassword("short") == nil || validatePassword("   ") == nil || validatePassword("") == nil {
		t.Fatal("弱密码应被拒")
	}
	if validatePassword("long-enough-1") != nil {
		t.Fatal("合格密码被拒")
	}
}

// 会话：签发/校验/过期/篡改失效。
func TestSession(t *testing.T) {
	up := &authSwitch{decide: func(string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)

	w := httptest.NewRecorder()
	s.issueSession(w)
	cookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "SameSite=Lax") {
		t.Fatalf("cookie 属性缺失: %s", cookie)
	}
	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Cookie", cookie)
	if !s.validSession(req) {
		t.Fatal("签发的会话应有效")
	}
	// 篡改签名：取 cookie 值，翻最后一位 hex
	val := strings.Split(strings.Split(cookie, ";")[0], "=")[1]
	last := val[len(val)-1]
	flip := "0"
	if last != 'f' {
		flip = "f"
	}
	tampered := val[:len(val)-1] + flip
	bad := httptest.NewRequest("GET", "/admin", nil)
	bad.Header.Set("Cookie", sessionCookieName+"="+tampered)
	if s.validSession(bad) {
		t.Fatal("篡改签名应失效")
	}
	// 过期：造一个过去时间的 cookie（用真实密钥签，但 exp 已过）
	exp := time.Now().Add(-time.Hour).Unix()
	mac := func(msg string) string { return signForTest(s, msg) }
	past := itoaI(exp) + "|aabb|" + mac(itoaI(exp)+"|aabb")
	old := httptest.NewRequest("GET", "/admin", nil)
	old.Header.Set("Cookie", sessionCookieName+"="+past)
	if s.validSession(old) {
		t.Fatal("过期会话应失效")
	}
	// 无 cookie
	if s.validSession(httptest.NewRequest("GET", "/admin", nil)) {
		t.Fatal("无 cookie 应无效")
	}
}

// 登录全流程：设密码 → /admin 给登录页 → 错误登录 401 → 正确登录带 cookie →
// /admin 200 → /v1 不受面板密码影响 → 登出 → 再次被拦 → 清除密码恢复开放。
func TestPanelAuthFlow(t *testing.T) {
	up := &authSwitch{decide: func(string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)

	get := func(path, cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:9999"
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}
	post := func(path string, body any, cookie, remote string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
		req.RemoteAddr = remote
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}

	// 未设密码：面板全开（登录页标志 = 密码输入框 id="pw"）
	if r := get("/admin", ""); r.Code != 200 || strings.Contains(r.Body.String(), `id="pw"`) {
		t.Fatal("未设密码应直接见面板")
	}
	// 首次设置无需登录
	r := post("/admin/api/password", map[string]any{"new_password": "pw-test-1234"}, "", "127.0.0.1:9999")
	if r.Code != 200 {
		t.Fatalf("首次设置应 200，得 %d %s", r.Code, r.Body.String())
	}
	cookie := r.Header().Get("Set-Cookie") // 设置后已带会话
	// 未登录访问 /admin → 登录页（200，非 401 空白）
	r = get("/admin", "")
	if r.Code != 200 || !strings.Contains(r.Body.String(), `id="pw"`) {
		t.Fatalf("未登录应给登录页，得 %d", r.Code)
	}
	// 未登录访问 /admin/api/* → 401 JSON
	if r := get("/admin/api/accounts", ""); r.Code != 401 {
		t.Fatalf("未登录 api 应 401，得 %d", r.Code)
	}
	// 错误密码 → 401
	if r := post("/admin/api/login", map[string]any{"password": "nope-nope"}, "", "127.0.0.1:9999"); r.Code != 401 {
		t.Fatalf("错密码应 401，得 %d", r.Code)
	}
	// 正确密码 → cookie
	r = post("/admin/api/login", map[string]any{"password": "pw-test-1234"}, "", "127.0.0.1:9999")
	if r.Code != 200 {
		t.Fatalf("登录应 200，得 %d", r.Code)
	}
	cookie = r.Header().Get("Set-Cookie")
	// 登录后 /admin 正常
	if r := get("/admin", cookie); r.Code != 200 || !strings.Contains(r.Body.String(), "控制台") {
		t.Fatalf("登录后应见面板，得 %d", r.Code)
	}
	// /v1/* 不受面板密码影响（走 API_KEY 语义，当前未启用 → 放行）
	chatBody := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`
	creq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(chatBody))
	creq.RemoteAddr = "127.0.0.1:9999"
	cw := httptest.NewRecorder()
	s.Handler().ServeHTTP(cw, creq)
	if cw.Code != 200 {
		t.Fatalf("/v1 不应受面板密码影响，得 %d", cw.Code)
	}
	// 登出 → 浏览器丢弃 cookie（无状态会话的登出即客户端语义）→ 再访问被拦
	post("/admin/api/logout", map[string]any{}, cookie, "127.0.0.1:9999")
	if r := get("/admin", ""); !strings.Contains(r.Body.String(), `id="pw"`) {
		t.Fatal("登出后（不带 cookie）应回登录页")
	}
	// 改密码要当前密码
	if r := post("/admin/api/password", map[string]any{"new_password": "pw-new-1234"}, "", "127.0.0.1:9999"); r.Code != 401 {
		t.Fatalf("无会话改密应 401，得 %d", r.Code)
	}
	r = post("/admin/api/login", map[string]any{"password": "pw-test-1234"}, "", "127.0.0.1:9999")
	cookie = r.Header().Get("Set-Cookie")
	if r := post("/admin/api/password", map[string]any{"current_password": "wrong", "new_password": "pw-new-1234"}, cookie, "127.0.0.1:9999"); r.Code != 403 {
		t.Fatalf("当前密码错应 403，得 %d", r.Code)
	}
	r = post("/admin/api/password", map[string]any{"current_password": "pw-test-1234", "new_password": "pw-new-1234"}, cookie, "127.0.0.1:9999")
	if r.Code != 200 {
		t.Fatalf("改密应 200，得 %d", r.Code)
	}
	newCookie := r.Header().Get("Set-Cookie") // 改密响应带的新会话
	// 改密后旧会话失效（会话绑定密码域）
	if r := get("/admin", cookie); !strings.Contains(r.Body.String(), `id="pw"`) {
		t.Fatal("改密后旧会话应失效")
	}
	// 清除密码（需会话）→ 恢复开放
	if r := post("/admin/api/password", map[string]any{"clear": true}, newCookie, "127.0.0.1:9999"); r.Code != 200 {
		t.Fatalf("清除应 200，得 %d", r.Code)
	}
	if r := get("/admin", ""); !strings.Contains(r.Body.String(), "控制台") {
		t.Fatal("清除后应恢复无密码面板")
	}
}

// 登录限速：连败 5 次锁 60s（429 + Retry-After），锁定过期自动恢复。
func TestLoginRateLimit(t *testing.T) {
	up := &authSwitch{decide: func(string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)
	s.loginRate.max = 5
	s.loginRate.lock = 60 * time.Second
	// 缩短 PBKDF2 迭代以外的耗时——测试直接用错密码（verify 很快返回 false）
	post := func(pw string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"password": pw})
		req := httptest.NewRequest(http.MethodPost, "/admin/api/login", strings.NewReader(string(raw)))
		req.RemoteAddr = "10.1.1.1:5555"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}
	s.settings.PanelPasswordHash, _ = hashPassword("real-password")
	s.loginRate.now = func() time.Time { return time.Now() } // 真实时钟

	// 连败 5 次 → 第 6 次 429
	for i := 0; i < 5; i++ {
		if r := post("bad-password"); r.Code != 401 {
			t.Fatalf("第 %d 次应 401，得 %d", i+1, r.Code)
		}
	}
	r := post("bad-password")
	if r.Code != 429 || r.Header().Get("Retry-After") == "" {
		t.Fatalf("锁定应 429+Retry-After，得 %d", r.Code)
	}
	// 锁定期间连正确密码也拦（暴力无法靠运气穿锁）
	if r := post("real-password"); r.Code != 429 {
		t.Fatalf("锁定期应 429，得 %d", r.Code)
	}
	// 锁定期过 → 自动恢复（注入时钟快进）
	base := time.Now()
	s.loginRate.now = func() time.Time { return base.Add(61 * time.Second) }
	if r := post("real-password"); r.Code != 200 {
		t.Fatalf("锁过期应恢复，得 %d", r.Code)
	}
}

// 忘记密码恢复：回环 reset 清除；非回环 403。
func TestPasswordReset(t *testing.T) {
	up := &authSwitch{decide: func(string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)
	s.settings.PanelPasswordHash, _ = hashPassword("forgotten-pw")

	post := func(remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/api/password/reset", strings.NewReader("{}"))
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}
	if r := post("10.2.2.2:80"); r.Code != 403 {
		t.Fatalf("非回环 reset 应 403，得 %d", r.Code)
	}
	if s.settings.PanelPasswordHash == "" {
		t.Fatal("非回环 reset 不应生效")
	}
	if r := post("127.0.0.1:80"); r.Code != 200 {
		t.Fatalf("回环 reset 应 200，得 %d", r.Code)
	}
	if s.settings.PanelPasswordHash != "" {
		t.Fatal("reset 后密码应清除")
	}
}

// 重启后会话有效（密钥持久化在 settings.json）。
func TestSessionSurvivesRestart(t *testing.T) {
	up := &authSwitch{decide: func(string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)
	s.settings.PanelPasswordHash, _ = hashPassword("pw-123456")
	_ = s.settings.save(s.Cfg.StateDir)

	w := httptest.NewRecorder()
	s.issueSession(w)
	cookie := w.Header().Get("Set-Cookie")

	// 同 StateDir 重建（模拟重启）
	s2 := New(s.Cfg, nil, s.Log)
	req := httptest.NewRequest("GET", "/admin", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("Cookie", cookie)
	w2 := httptest.NewRecorder()
	s2.Handler().ServeHTTP(w2, req)
	if w2.Code != 200 || !strings.Contains(w2.Body.String(), "控制台") {
		t.Fatalf("重启后会话应仍有效，得 %d", w2.Code)
	}
}

// 面板密码不影响 API_KEY 优先级（两套鉴权独立）。
func TestPanelPasswordVsAPIKey(t *testing.T) {
	up := &authSwitch{decide: func(string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)
	s.settings.PanelPasswordHash, _ = hashPassword("pw-123456")
	s.settings.APIKey = "sk-combo-test"
	s.recomputeAuth()

	// /v1 走 API_KEY：无钥 401、带钥 200（与面板密码无关）
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`
	mk := func(key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:9999"
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}
	if r := mk(""); r.Code != 401 {
		t.Fatalf("无 API key 应 401，得 %d", r.Code)
	}
	if r := mk("sk-combo-test"); r.Code != 200 {
		t.Fatalf("带 API key 应 200，得 %d", r.Code)
	}
	// /admin 要面板密码（API key 不能开面板）
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("Authorization", "Bearer sk-combo-test")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), `id="pw"`) {
		t.Fatal("面板应仍要密码（API key 不开面板）")
	}
}
