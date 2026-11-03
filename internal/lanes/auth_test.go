// lanes 包关键路径的 httptest 覆盖（Python 版测试未覆盖的部分）：
//   - RT 轮换刷新：POST /oauth/refresh 成功 → 新 token 生效并原子写回 auth.toml
//   - 并发/外部抢先刷新：锁内重读文件后跳过重复刷新（旧 RT 已作废，双刷必互杀）
//   - auth.toml mtime 热加载：外部改写后 Headers() 自动跟随
//   - auth.toml 字节格式：Go 写 → 极简解析读回，未识别的行与 [user] 表原样保留
package lanes

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func writeCredsFile(t *testing.T, path, at, rt string, created int64, extra string) {
	t.Helper()
	text := "access_token = \"" + at + "\"\n" +
		"token_type = \"Bearer\"\n" +
		"refresh_token = \"" + rt + "\"\n" +
		"expires_in = 604800\n" +
		"created_at = " + itoa(created) + "\n"
	if extra != "" {
		text += "\n" + extra
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

func tempAuthTOML(t *testing.T, at, rt string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.toml")
	writeCredsFile(t, path, at, rt, time.Now().Unix(), "[user]\nid = \"42\"\nusername = \"tester\"\n")
	return path
}

// 刷新成功：新 AT/RT 生效，且写回文件（RT 轮换必须持久化）
func TestRefreshRotatesAndPersists(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		raw, _ := io.ReadAll(r.Body)
		var got map[string]string
		_ = json.Unmarshal(raw, &got)
		if got["refresh_token"] != "old-rt" {
			t.Errorf("刷新请求体带的是旧 RT: %v", got)
		}
		if ua := r.Header.Get("User-Agent"); !strings.HasPrefix(ua, "ac2api/") {
			t.Errorf("刷新请求 UA=%q，必须中性", ua)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"new-at","refresh_token":"new-rt","expires_in":7200}`)
	}))
	defer srv.Close()

	path := tempAuthTOML(t, "old-at", "old-rt")
	c, err := NewCredential(path, path+".json", quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	c.RefreshURL = srv.URL
	if err := c.Refresh(); err != nil {
		t.Fatalf("刷新失败: %v", err)
	}
	if c.AccessToken() != "new-at" || c.RefreshToken() != "new-rt" {
		t.Errorf("内存态未更新: at=%q rt=%q", c.AccessToken(), c.RefreshToken())
	}
	// expires_in 用响应值（7200），不是默认 604800
	if delta := c.ExpiresAt() - time.Now().Unix(); delta < 7100 || delta > 7200 {
		t.Errorf("expiresAt 偏移=%d，期望 ~7200", delta)
	}
	// 新语义：刷新产物落 auth.json（网关独立凭据文件），auth.toml 保持原样不写回
	jraw, _ := os.ReadFile(path + ".json")
	var saved map[string]any
	if err := json.Unmarshal(jraw, &saved); err != nil {
		t.Fatalf("auth.json 解析失败: %v\nraw=%s", err, jraw)
	}
	if saved["access_token"] != "new-at" || saved["refresh_token"] != "new-rt" {
		t.Fatalf("auth.json 未写回新凭据: %v", saved)
	}
	tomlRaw, _ := os.ReadFile(path)
	if !strings.Contains(string(tomlRaw), `access_token = "old-at"`) {
		t.Errorf("auth.toml 不应被写回:\n%s", tomlRaw)
	}
	// expires_in 用响应值（7200），落在 auth.json
	if saved["expires_in"] != float64(7200) {
		t.Errorf("expires_in 应为 7200, got %v", saved["expires_in"])
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("刷新端点被打 %d 次，期望 1", n)
	}
}

// 抢先刷新：文件已被外部（官方 CLI）换掉时，锁内重读后跳过本次刷新——
// 否则两条链路各拿一个旧 RT 去换，第二次必失败并把凭据写坏。
func TestRefreshSkipsWhenFileAlreadyRotated(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, `{"access_token":"server-at","refresh_token":"server-rt"}`)
	}))
	defer srv.Close()

	path := tempAuthTOML(t, "old-at", "old-rt")
	c, err := NewCredential(path, path+".json", quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	c.RefreshURL = srv.URL

	// 模拟外部抢先刷新（mtime 必须变）
	time.Sleep(10 * time.Millisecond)
	writeCredsFile(t, path, "cli-at", "cli-rt", time.Now().Unix(), "[user]\nid = \"42\"\nusername = \"tester\"\n")

	if err := c.Refresh(); err != nil {
		t.Fatalf("应跳过刷新而不是报错: %v", err)
	}
	if c.AccessToken() != "cli-at" {
		t.Errorf("at=%q，期望热加载到文件里的 cli-at", c.AccessToken())
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("端点被打 %d 次，期望 0（跳过重复刷新）", n)
	}
}

// 并发请求同时撞上 401：只有一个真去刷，另一个复用文件里的新凭据。
func TestConcurrentRefreshSingleFlight(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(20 * time.Millisecond) // 放大竞争窗口
		_, _ = io.WriteString(w, `{"access_token":"new-at","refresh_token":"new-rt"}`)
	}))
	defer srv.Close()

	path := tempAuthTOML(t, "old-at", "old-rt")
	c, err := NewCredential(path, path+".json", quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	c.RefreshURL = srv.URL

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Refresh(); err != nil {
				t.Errorf("并发刷新报错: %v", err)
			}
		}()
	}
	wg.Wait()
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("刷新端点被打 %d 次，期望 1（RT 轮换只能成功一次）", n)
	}
	if c.AccessToken() != "new-at" {
		t.Errorf("最终 at=%q", c.AccessToken())
	}
}

// mtime 热加载：官方 CLI 改写 auth.toml 后，下一次 Headers() 即跟随新 token。
func TestMtimeHotReload(t *testing.T) {
	path := tempAuthTOML(t, "at-1", "rt-1")
	c, err := NewCredential(path, path+".json", quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if h := c.Headers(); h.Get("Authorization") != "Bearer at-1" {
		t.Fatalf("初始头=%q", h.Get("Authorization"))
	}
	time.Sleep(10 * time.Millisecond)
	writeCredsFile(t, path, "at-2", "rt-2", time.Now().Unix(), "")
	// 新文件里没有 [user]：Python 的 data.get("user", {}) 语义是清空账号信息，
	// 但 token 必须已跟随文件（Headers() 现取）
	h := c.Headers()
	if h.Get("Authorization") != "Bearer at-2" {
		t.Errorf("热加载未生效: %q", h.Get("Authorization"))
	}
	if c.UserID() != "" || c.Username() != "" {
		t.Errorf("文件无 [user] 时账号信息应清空，得 %q/%q", c.UserID(), c.Username())
	}
	if h.Get("User-Agent") != UpstreamUA || strings.HasPrefix(h.Get("User-Agent"), "atomcode") {
		t.Errorf("UA=%q，UA 门要求中性", h.Get("User-Agent"))
	}
	if h.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type=%q", h.Get("Content-Type"))
	}
}

// 读坏（非法 UTF-8 / 解析不出键）时保留内存凭据，不清空。
func TestCorruptFileKeepsMemoryCreds(t *testing.T) {
	path := tempAuthTOML(t, "good-at", "good-rt")
	c, err := NewCredential(path, path+".json", quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("access_token = unterminated\n[[[\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if h := c.Headers(); h.Get("Authorization") != "Bearer good-at" {
		t.Errorf("读坏后凭据被清空: %q", h.Get("Authorization"))
	}
}

// 文件缺失 → ErrNotLoggedIn（Python 的 NotLoggedInError）
func TestMissingFileNotLoggedIn(t *testing.T) {
	if _, err := NewCredential(filepath.Join(t.TempDir(), "nope.toml"), filepath.Join(t.TempDir(), "nope.json"), quietLogger()); err != ErrNotLoggedIn {
		t.Errorf("err=%v，期望 ErrNotLoggedIn", err)
	}
}

// 临期判定：提前 1 小时算过期（Python: time.time() > expires_at - 3600）
func TestIsExpiredMargin(t *testing.T) {
	cases := []struct {
		createdAgo int64
		want       bool
	}{
		{0, false},             // 刚签发，7 天有效
		{604800 - 1800, true},  // 只剩 30 分钟 < 1 小时余量
		{604800 - 7200, false}, // 剩 2 小时
	}
	for _, tc := range cases {
		path := filepath.Join(t.TempDir(), "auth.toml")
		writeCredsFile(t, path, "at", "rt", time.Now().Unix()-tc.createdAgo, "")
		c, err := NewCredential(path, path+".json", quietLogger())
		if err != nil {
			t.Fatal(err)
		}
		if got := c.IsExpired(); got != tc.want {
			t.Errorf("createdAgo=%d IsExpired=%v，期望 %v", tc.createdAgo, got, tc.want)
		}
	}
}

// auth.toml 写回：未知行与 [user] 表原样保留、行尾风格保留、原子替换不留 .tmp
func TestSaveAuthTOMLPreservesForeignContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.toml")
	original := "# 官方 CLI 注释\r\naccess_token = \"a\"\r\nsome_future_key = 7\r\n" +
		"token_type = \"Bearer\"\r\nrefresh_token = \"r\"\r\nexpires_in = 100\r\ncreated_at = 1\r\n" +
		"\r\n[user]\r\nid = \"9\"\r\nusername = \"u\"\r\nname = \"N\"\r\nemail = \"e@x\"\r\navatar_url = \"http://a\"\r\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveCredentials(path, SaveCreds{
		AccessToken: "b", TokenType: "Bearer", RefreshToken: "r2",
		ExpiresIn: 604800, CreatedAt: 2,
	}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	got := string(raw)
	if !strings.Contains(got, "some_future_key = 7") {
		t.Errorf("未知键被吃掉:\n%s", got)
	}
	if !strings.Contains(got, "# 官方 CLI 注释") {
		t.Errorf("注释被吃掉:\n%s", got)
	}
	if !strings.Contains(got, "[user]") || !strings.Contains(got, `id = "9"`) {
		t.Errorf("[user] 表被改:\n%s", got)
	}
	if !strings.Contains(got, "access_token = \"b\"") || !strings.Contains(got, "expires_in = 604800") {
		t.Errorf("凭据未替换:\n%s", got)
	}
	if strings.Contains(got, "\n") && strings.Count(got, "\r\n") < 3 {
		t.Errorf("CRLF 行尾没保留:\n%q", got)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("残留 .tmp 文件")
	}
	// 读回验证（Go 自己的解析器 == Python tomllib 在这份形状上的等价子集）
	c, err := parseAuthTOML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessToken != "b" || c.RefreshToken != "r2" || c.ExpiresIn != 604800 || c.CreatedAt != 2 {
		t.Errorf("读回=%+v", c)
	}
	if !c.HasUser || c.User.ID != "9" || c.User.Username != "u" || c.User.Email != "e@x" {
		t.Errorf("[user] 读回=%+v", c.User)
	}
}

// 原文件缺凭据键时按固定顺序追加；给了 user 且原文件无 [user] 时追加表
func TestSaveAuthTOMLAppendsMissingKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.toml")
	if err := os.WriteFile(path, []byte("token_type = \"Bearer\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveCredentials(path, SaveCreds{
		AccessToken: "a", RefreshToken: "r", ExpiresIn: 60, CreatedAt: 5,
		User: User{ID: "1", Username: "u"}, HasUser: true,
	}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	got := string(raw)
	want := "token_type = \"Bearer\"\n" +
		"access_token = \"a\"\nrefresh_token = \"r\"\nexpires_in = 60\ncreated_at = 5\n" +
		"\n[user]\nid = \"1\"\nusername = \"u\"\nname = \"\"\nemail = \"\"\navatar_url = \"\"\n"
	if got != want {
		t.Errorf("落盘形状不符:\n got=%q\nwant=%q", got, want)
	}
}

// HasUser=false（Python: user.id 为空则不写 [user]）
func TestSaveAuthTOMLWithoutUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.toml")
	if err := SaveCredentials(path, SaveCreds{AccessToken: "a", RefreshToken: "r"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "[user]") {
		t.Errorf("不该写 [user]:\n%s", raw)
	}
}

// OAuth 会话 httptest：start → waiting → done，凭据落盘且 state 一次性
func TestOAuthPollFlowAgainstFakeACS(t *testing.T) {
	var mu sync.Mutex
	authorized := false
	var states []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/login":
			if r.URL.Query().Get("provider") != "atomgit" {
				t.Errorf("provider=%q", r.URL.Query().Get("provider"))
			}
			_, _ = io.WriteString(w, `{"state":"st-1","login_url":"https://acs.atomgit.com/authorize?force_login=true&a=1"}`)
		case "/auth/check":
			mu.Lock()
			ok := authorized
			mu.Unlock()
			if ok {
				_, _ = io.WriteString(w, `{"valid":true}`)
			} else {
				_, _ = io.WriteString(w, `{"valid":false}`)
			}
		case "/auth/token":
			states = append(states, r.URL.Query().Get("state"))
			_, _ = io.WriteString(w, `{"access_token":"at-o","refresh_token":"rt-o","expires_in":600,
			  "user":{"id":123,"username":"oauthuser","name":"O","email":"","avatar_url":""}}`)
		default:
			t.Errorf("未预期路径 %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	o := NewOAuthLogin()
	o.Base = srv.URL
	if err := o.Start(); err != nil {
		t.Fatal(err)
	}
	// force_login=true 被剥掉（? 与后续参数拼接正确）
	if got := o.LoginURL(); strings.Contains(got, "force_login") {
		t.Errorf("login_url 没剥 force_login: %s", got)
	}

	// 未授权 → waiting
	if creds, state, err := o.Poll(); creds != nil || err != nil || state != "waiting" {
		t.Errorf("未授权时 (%v, %q, %v)，期望 (nil, waiting, nil)", creds, state, err)
	}

	mu.Lock()
	authorized = true
	mu.Unlock()
	creds, state, err := o.Poll()
	if err != nil || state != "done" || creds == nil {
		t.Fatalf("授权后 (%v, %q, %v)", creds, state, err)
	}
	if creds.AccessToken != "at-o" || creds.User.IDStr() != "123" {
		t.Errorf("凭据=%+v", creds)
	}
	// state 一次性：再轮询应报未发起
	if _, state2, _ := o.Poll(); state2 != "login 未发起，先 GET /login" {
		t.Errorf("二次轮询 state=%q，期望未发起", state2)
	}
	if len(states) != 1 || states[0] != "st-1" {
		t.Errorf("token 端点 state=%v", states)
	}

	// ToSaveCreds → 落盘可读回
	path := filepath.Join(t.TempDir(), "auth.toml")
	if err := SaveCredentials(path, creds.ToSaveCreds()); err != nil {
		t.Fatal(err)
	}
	c, err := NewCredential(path, path+".json", quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessToken() != "at-o" || c.UserID() != "123" || c.Username() != "oauthuser" {
		t.Errorf("落盘读回=%q/%q/%q", c.AccessToken(), c.UserID(), c.Username())
	}
}

// 未 Start 就 Poll
func TestOAuthPollNotStarted(t *testing.T) {
	o := NewOAuthLogin()
	creds, state, err := o.Poll()
	if creds != nil || err != nil || state != "login 未发起，先 GET /login" {
		t.Errorf("(%v, %q, %v)", creds, state, err)
	}
}

// 会话超时（10 分钟）：清空 state，需重新 /login
func TestOAuthSessionTimeout(t *testing.T) {
	o := NewOAuthLogin()
	o.state = "st"
	o.createdAt = time.Now().Add(-11 * time.Minute)
	creds, state, err := o.Poll()
	if creds != nil || err != nil || !strings.Contains(state, "超时") {
		t.Errorf("(%v, %q, %v)", creds, state, err)
	}
	if o.state != "" {
		t.Errorf("超时后 state 未清空: %q", o.state)
	}
}

// ACS 侧报错（非 200）→ start 冒泡成 error（路由层 502）
func TestOAuthStartUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"msg":"acs down"}`)
	}))
	defer srv.Close()
	o := NewOAuthLogin()
	o.Base = srv.URL
	if err := o.Start(); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err=%v，期望带 HTTP 500", err)
	}
}

// SaveAuthJSON 写盘后含 user 表且可读回（种子/池凭据自描述）。
func TestSaveAuthJSON_UserRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.json")
	sc := SaveCreds{
		AccessToken: "at", RefreshToken: "rt", ExpiresIn: 604800, CreatedAt: 1,
		User: User{ID: "u1", Username: "alice", AvatarURL: "http://a/b.png"}, HasUser: true,
	}
	if err := SaveAuthJSON(path, sc); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseAuthJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !back.HasUser || back.User.ID != "u1" || back.User.Username != "alice" || back.User.AvatarURL != "http://a/b.png" {
		t.Fatalf("user 未回读: %+v", back.User)
	}
}
