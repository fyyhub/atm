// P3 路由级测试：粘性键优先级、端到端粘性、/pool/status、批量导入。
package handler

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sessionKey 优先级：X-Session-Id > metadata.user_id > 内容 hash。
func TestSessionKey_Priority(t *testing.T) {
	body := map[string]any{"messages": []any{
		map[string]any{"role": "system", "content": "sys"},
		map[string]any{"role": "user", "content": "hello"},
	}}
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)

	// 内容 hash 兜底
	k1 := sessionKey(r, body, body)
	if !strings.HasPrefix(k1, "c:") {
		t.Fatalf("应为内容 hash 键，得 %q", k1)
	}
	// 同内容同键
	if sessionKey(httptest.NewRequest("POST", "/", nil), body, body) != k1 {
		t.Fatal("同内容应同键")
	}
	// metadata.user_id 压过内容 hash
	raw := map[string]any{"metadata": map[string]any{"user_id": "u9"}}
	if k := sessionKey(r, body, raw); k != "m:u9" {
		t.Fatalf("metadata 优先，得 %q", k)
	}
	// 请求头最高优先
	r2 := httptest.NewRequest("POST", "/", nil)
	r2.Header.Set("X-Session-Id", "sess-1")
	if k := sessionKey(r2, body, raw); k != "h:sess-1" {
		t.Fatalf("请求头最高优先，得 %q", k)
	}
	// 空消息不粘
	if k := sessionKey(httptest.NewRequest("POST", "/", nil), map[string]any{}, map[string]any{}); k != "" {
		t.Fatalf("空消息应不粘，得 %q", k)
	}
}

// 端到端粘性：两个账号，首请求绑定调度结果；次请求同键 → 即使对方打分更高也落同账号。
func TestSticky_EndToEnd(t *testing.T) {
	up := &authSwitch{decide: func(auth string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)
	addAcct(t, s, "43", "at-2", "rt-2")

	h := map[string]string{"X-Session-Id": "sess-A"}
	r1 := doChat(t, s, false, h)
	if r1.Code != 200 {
		t.Fatalf("首请求 %d", r1.Code)
	}
	first := up.seen()[len(up.seen())-1]

	// 人为反转打分：首中账号窗口拉满（剩 1），另一个全空（剩 400）。
	// 无粘性时第二请求必切到对方；粘性应压住调度。
	hit, other := s.Pool.Get("42"), s.Pool.Get("43")
	if strings.Contains(first, "at-2") {
		hit, other = other, hit
	}
	hit.WindowLimit, hit.WindowUsed = 400, 399
	other.WindowLimit, other.WindowUsed = 400, 0

	r2 := doChat(t, s, false, h)
	if r2.Code != 200 {
		t.Fatalf("次请求 %d", r2.Code)
	}
	if last := up.seen()[len(up.seen())-1]; last != first {
		t.Fatalf("同会话应落同账号：首次 %q 二次 %q", first, last)
	}

	// 不带头的请求走正常调度（应选窗口空的 other）
	r3 := doChat(t, s, false, nil)
	if r3.Code != 200 {
		t.Fatalf("无头请求 %d", r3.Code)
	}
	if last := up.seen()[len(up.seen())-1]; last == first {
		t.Fatal("无头请求应走正常调度选中对方账号")
	}
}

// /pool/status 结构：accounts + count/healthy/cap + success_rate 字段。
func TestPoolStatusEndpoint(t *testing.T) {
	up := &authSwitch{decide: func(auth string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)
	addAcct(t, s, "43", "at-2", "rt-2")
	s.Pool.RecordSuccess(s.Pool.Get("42"), nil)
	s.Pool.RecordFailure(s.Pool.Get("43"), "429", "x", 300)

	req := httptest.NewRequest("GET", "/pool/status", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("应 200，得 %d", w.Code)
	}
	var out struct {
		Accounts []struct {
			ID          string   `json:"id"`
			Status      string   `json:"status"`
			SuccessRate *float64 `json:"success_rate"`
			WindowUsed  int64    `json:"window_used"`
		} `json:"accounts"`
		Count   int `json:"count"`
		Healthy int `json:"healthy"`
		Cap     int `json:"cap"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 2 || out.Cap != 100 || out.Healthy != 1 {
		t.Fatalf("count=%d healthy=%d cap=%d", out.Count, out.Healthy, out.Cap)
	}
	if len(out.Accounts) != 2 {
		t.Fatal("应有两个账号")
	}
	m := map[string]string{}
	for _, a := range out.Accounts {
		m[a.ID] = a.Status
		if a.SuccessRate == nil {
			t.Fatalf("账号 %s 应有 success_rate", a.ID)
		}
	}
	if m["42"] != "ok" || m["43"] != "cooling" {
		t.Fatalf("状态=%v", m)
	}
}

// 批量导入：有效 TOML + 查重 + 垃圾 + 有效 JSON 四种条目各自出结果，互不中断。
func TestAccountsBatch(t *testing.T) {
	up := &authSwitch{decide: func(auth string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up) // 池里已有 fake-rt（fixture 账号）；status 校验走假上游
	now := time.Now().Unix()

	validNew := "access_token = \"at-new\"\nrefresh_token = \"rt-new\"\nexpires_in = 604800\ncreated_at = " +
		strconv.Itoa(int(now)) + "\n\n[user]\nid = \"99\"\nusername = \"newbie\"\n"
	dup := "access_token = \"at-x\"\nrefresh_token = \"fake-rt\"\nexpires_in = 604800\ncreated_at = 1\n"
	garbage := "这不是凭据"
	validJSON := `{"access_token":"at-j","refresh_token":"rt-j","expires_in":604800,"created_at":` + strconv.Itoa(int(now)) + `,"user":{"id":"98","username":"js"}}`

	text := validNew + "\n---\n" + dup + "\n---\n" + garbage + "\n---\n" + validJSON
	body, _ := json.Marshal(map[string]any{"text": text})
	req := httptest.NewRequest("POST", "/admin/api/accounts/batch", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("应 200，得 %d body=%s", w.Code, w.Body.String())
	}
	var out struct {
		Imported int `json:"imported"`
		Skipped  int `json:"skipped"`
		Failed   int `json:"failed"`
		Results  []struct {
			Index   int    `json:"index"`
			OK      bool   `json:"ok"`
			Skipped string `json:"skipped"`
			Error   string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 4 {
		t.Fatalf("应有 4 条结果: %s", w.Body.String())
	}
	if out.Imported != 2 || out.Skipped != 1 || out.Failed != 1 {
		t.Fatalf("imported=%d skipped=%d failed=%d（%s）", out.Imported, out.Skipped, out.Failed, w.Body.String())
	}
	if out.Results[2].OK || out.Results[2].Error == "" {
		t.Fatal("第三条应失败")
	}
	if s.Pool.Count() != 3 {
		t.Fatalf("池应为 3（fixture + 2 新），得 %d", s.Pool.Count())
	}
}
