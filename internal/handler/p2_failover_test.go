// P2 换人重试与调试头的路由级测试（httptest 假上游按 Authorization 分账号）。
package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"atomcode2api/internal/config"
	"atomcode2api/internal/lanes"
)

// authSwitch 假上游：按 Authorization 头区分账号，decide 决定响应。
type authSwitch struct {
	mu     sync.Mutex
	auths  []string
	decide func(auth string) (int, []byte)
}

func (a *authSwitch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	a.mu.Lock()
	a.auths = append(a.auths, auth)
	a.mu.Unlock()
	status, body := a.decide(auth)
	if strings.HasPrefix(string(body), "data: ") {
		w.Header().Set("Content-Type", "text/event-stream")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (a *authSwitch) seen() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.auths...)
}

func (a *authSwitch) seenDistinct() []string {
	m := map[string]bool{}
	out := []string{}
	for _, x := range a.seen() {
		if !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	return out
}

// newPoolFixture 手工装 Server（夹具账号 id=42, AT=fake-at）。
func newPoolFixture(t *testing.T, up http.Handler) *Server {
	t.Helper()
	srv := httptest.NewServer(up)
	t.Cleanup(srv.Close)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{Host: "127.0.0.1", Port: 8788, StateDir: t.TempDir()}
	cred, err := lanes.NewCredential(newAuthTOML(t), filepath.Join(t.TempDir(), "c.json"), logger)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, cred, logger)
	s.Up.CodingPlanBase = srv.URL + "/v1"
	s.Con.Base = srv.URL + "/api/v5/coding-plan"
	s.Up.Backoff = []time.Duration{time.Millisecond}
	return s
}

// addAcct 池里加账号（id/AT/RT 可指）。
func addAcct(t *testing.T, s *Server, id, at, rt string) {
	t.Helper()
	_, err := s.Pool.Add(lanes.SaveCreds{
		AccessToken: at, TokenType: "Bearer", RefreshToken: rt,
		ExpiresIn: 604800, CreatedAt: time.Now().Unix(),
		User: lanes.User{ID: id, Username: "u" + id}, HasUser: true,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
}

func doChat(t *testing.T, s *Server, stream bool, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"model": "m", "stream": stream,
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

var err429 = []byte(`{"error":{"message":"rate limited"}}`)

// 非流式换人：账号 1 上游 429 → 自动切账号 2 并成功；账号 1 被冷却记账。
func TestFailover429_NonStream(t *testing.T) {
	up := &authSwitch{decide: func(auth string) (int, []byte) {
		if auth == "Bearer fake-at" {
			return 429, err429
		}
		return 200, chatJSONBytes
	}}
	s := newPoolFixture(t, up)
	addAcct(t, s, "43", "at-2", "rt-2")

	r := doChat(t, s, false, nil)
	if r.Code != 200 {
		t.Fatalf("换人后应 200，得 %d body=%s", r.Code, r.Body.String())
	}
	seen := up.seenDistinct()
	if len(seen) != 2 || seen[0] != "Bearer fake-at" || seen[1] != "Bearer at-2" {
		t.Fatalf("应先试 fake-at 再换 at-2，实际 %v", seen)
	}
	a1 := s.Pool.Get("42")
	if a1.TotalFail != 1 || !a1.CooldownUntil.After(time.Now()) {
		t.Fatalf("账号 1 应记失败并冷却: fail=%d cooldown=%v", a1.TotalFail, a1.CooldownUntil)
	}
	if a2 := s.Pool.Get("43"); a2.TotalOK != 1 {
		t.Fatalf("账号 2 应记成功: ok=%d", a2.TotalOK)
	}
}

// 非流式伪回复换人：账号 1 返回配额耗尽伪 200 → 冷却并切账号 2。
func TestFailoverPseudo_NonStream(t *testing.T) {
	quotaBody := []byte(`{"id":"q1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"模型「glm5.3-flash」在当前 CodingPlan 用量窗口内已达上限。额度约在当日 03:00 结束并重置额度，请稍后再试。"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	up := &authSwitch{decide: func(auth string) (int, []byte) {
		if auth == "Bearer fake-at" {
			return 200, quotaBody
		}
		return 200, chatJSONBytes
	}}
	s := newPoolFixture(t, up)
	addAcct(t, s, "43", "at-2", "rt-2")

	r := doChat(t, s, false, nil)
	if r.Code != 200 {
		t.Fatalf("换人后应 200，得 %d body=%s", r.Code, r.Body.String())
	}
	a1 := s.Pool.Get("42")
	if a1.TotalFail != 1 || !a1.CooldownUntil.After(time.Now()) {
		t.Fatalf("账号 1 应记伪回复失败并冷却: fail=%d", a1.TotalFail)
	}
	if len(up.seenDistinct()) != 2 {
		t.Fatalf("应换一次人，实际 %v", up.seenDistinct())
	}
}

// 流式窥探换人：账号 1 首个内容帧即伪回复 → 未写客户端，切账号 2 正常流出。
func TestFailoverStream_PseudoPeek(t *testing.T) {
	up := &authSwitch{decide: func(auth string) (int, []byte) {
		if auth == "Bearer fake-at" {
			return 200, pseudoStream
		}
		return 200, chatStream
	}}
	s := newPoolFixture(t, up)
	addAcct(t, s, "43", "at-2", "rt-2")

	r := doChat(t, s, true, nil)
	if r.Code != 200 {
		t.Fatalf("应 200，得 %d", r.Code)
	}
	body := r.Body.String()
	if !strings.Contains(body, "Hi!") {
		t.Fatalf("应透出账号 2 的正常流，得 %.200s", body)
	}
	if strings.Contains(body, "负载过高") {
		t.Fatal("伪回复不应透给客户端")
	}
	if a1 := s.Pool.Get("42"); a1.TotalFail != 1 {
		t.Fatalf("账号 1 应记失败: %d", a1.TotalFail)
	}
}

// 换人上限：5 个账号全 429 → 最多试 3 个；终局回上游 429。
func TestFailoverCap(t *testing.T) {
	up := &authSwitch{decide: func(auth string) (int, []byte) { return 429, err429 }}
	s := newPoolFixture(t, up)
	for i, id := range []string{"43", "44", "45", "46"} {
		addAcct(t, s, id, "at-"+id, "rt-"+id)
		_ = i
	}

	r := doChat(t, s, false, nil)
	if r.Code != 429 {
		t.Fatalf("终局应 429，得 %d", r.Code)
	}
	if n := len(up.seenDistinct()); n != 3 {
		t.Fatalf("换人上限应为 3，实际试了 %d 个", n)
	}
}

// 池耗尽：全部账号冷却中 → 429 pool_exhausted + Retry-After。
func TestPoolExhausted(t *testing.T) {
	up := &authSwitch{decide: func(auth string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)
	addAcct(t, s, "43", "at-2", "rt-2")
	s.Pool.RecordFailure(s.Pool.Get("42"), "429", "x", 300)
	s.Pool.RecordFailure(s.Pool.Get("43"), "429", "x", 600)

	r := doChat(t, s, false, nil)
	if r.Code != 429 {
		t.Fatalf("应 429，得 %d", r.Code)
	}
	if !strings.Contains(r.Body.String(), "pool_exhausted") {
		t.Fatalf("应标 pool_exhausted: %s", r.Body.String())
	}
	ra := r.Header().Get("Retry-After")
	if ra == "" || ra == "0" {
		t.Fatalf("应带 Retry-After=最早冷却结束，得 %q", ra)
	}
	if len(up.seen()) != 0 {
		t.Fatal("池耗尽不应打上游")
	}
}

// X-Account-Id 调试头：API_KEY 配置时指定账号；未知/不可用账号明确报错；
// 未配置 API_KEY 时忽略该头。
func TestXAccountID(t *testing.T) {
	up := &authSwitch{decide: func(auth string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)
	addAcct(t, s, "43", "at-2", "rt-2")
	s.Cfg.APIKey = "sk-test"
	s.recomputeAuth()
	auth := map[string]string{"Authorization": "Bearer sk-test"}

	// 指定账号 43 → 上游只见 at-2
	h := map[string]string{"Authorization": "Bearer sk-test", "X-Account-Id": "43"}
	r := doChat(t, s, false, h)
	if r.Code != 200 {
		t.Fatalf("指定账号应 200，得 %d body=%s", r.Code, r.Body.String())
	}
	if seen := up.seenDistinct(); len(seen) != 1 || seen[0] != "Bearer at-2" {
		t.Fatalf("应只打 at-2，实际 %v", seen)
	}

	// 未知账号 → 400
	h2 := map[string]string{"Authorization": "Bearer sk-test", "X-Account-Id": "nope"}
	if r := doChat(t, s, false, h2); r.Code != 400 {
		t.Fatalf("未知账号应 400，得 %d", r.Code)
	}

	// 不可用账号（冷却）→ 409
	s.Pool.RecordFailure(s.Pool.Get("43"), "429", "x", 600)
	if r := doChat(t, s, false, h); r.Code != 409 {
		t.Fatalf("冷却账号应 409，得 %d", r.Code)
	}

	// 未配置 API_KEY → 忽略该头，走正常调度（43 冷却中 → 选 42）
	s.Cfg.APIKey = ""
	s.recomputeAuth()
	h3 := map[string]string{"X-Account-Id": "43"}
	r = doChat(t, s, false, h3)
	if r.Code != 200 {
		t.Fatalf("忽略头后应正常调度 200，得 %d", r.Code)
	}
	last := up.seen()[len(up.seen())-1]
	if last != "Bearer fake-at" {
		t.Fatalf("未配 API_KEY 应忽略头走池调度（fake-at），实际 %q", last)
	}
	_ = auth
}
