// /v1/responses 路由端到端验证（httptest 假上游，不连真实 CodingPlan/OpenRouter），
// 移植 Python tests/test_responses_route.py 的 5 个场景：
//  1. /v1/responses 流式（CodingPlan 模型）：Responses SSE 合法
//  2. /v1/responses 非流式（CodingPlan 模型）：Responses JSON 合法
//  3. /v1/responses 流式（OpenRouter 模型）：模型映射后走 OpenRouter 分支
//  4. /v1/chat/completions 流式回归：_send_* 抽取不破坏老路由（含裸透传字节比对）
//  5. /v1/responses 流式额度伪回复拦截：首个内容命中即 response.failed
//
// 额外补齐 Python 测试未覆盖的关键路径：/health、API_KEY 闸门、未登录闸门、
// /v1/models、/status、非流式 {"data":{...}} 解包（Python 已知缺陷的修复证明）。
package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"atomcode2api/internal/config"
	"atomcode2api/internal/lanes"
)

// ── 假上游夹具 ───────────────────────────────────────────────────────────────

type capturedReq struct {
	url     string
	path    string
	payload map[string]any
	header  http.Header
}

type fakeUpstream struct {
	mu      sync.Mutex
	calls   []capturedReq
	kind    string // "stream" / "json" / "pseudo" / "quota"
	status  int    // 0 = 200
	body    string // kind=quota 时的响应体
	dataPkg bool   // 非流式响应外面多包一层 {"data":{...}}（已知缺陷场景）
	jsonBody []byte // kind=json 时替换默认样本（工具调用等场景用）
	streamBody []byte // kind=stream 时替换默认样本
}

func (f *fakeUpstream) record(r *http.Request, payload map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, capturedReq{
		url:     "http://" + r.Host + r.RequestURI,
		path:    r.URL.Path,
		payload: payload,
		header:  r.Header.Clone(),
	})
}

func (f *fakeUpstream) last(t *testing.T) capturedReq {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("假上游没有被调用")
	}
	return f.calls[len(f.calls)-1]
}

func (f *fakeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var payload map[string]any
	_ = json.Unmarshal(raw, &payload)
	f.record(r, payload)

	if f.status != 0 {
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, `{"error":"boom"}`)
		return
	}
	switch f.kind {
	case "json":
		body := string(chatJSONBytes)
		if f.jsonBody != nil {
			body = string(f.jsonBody)
		}
		if f.dataPkg {
			body = `{"data":` + body + `}`
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	case "quota":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(f.body))
	case "pseudo":
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write(pseudoStream)
	default:
		w.Header().Set("Content-Type", "text/event-stream")
		if f.streamBody != nil {
			_, _ = w.Write(f.streamBody)
			return
		}
		_, _ = w.Write(chatStream)
	}
}

// ── 服务夹具 ─────────────────────────────────────────────────────────────────

type fixture struct {
	s    *Server
	fake *fakeUpstream
	srv  *httptest.Server
}

func newFixture(t *testing.T, kind string) *fixture {
	t.Helper()
	fake := &fakeUpstream{kind: kind}
	up := httptest.NewServer(fake)
	t.Cleanup(up.Close)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{Host: "127.0.0.1", Port: 8788, StateDir: t.TempDir()}
	cred, err := lanes.NewCredential(newAuthTOML(t), newAuthTOML(t)+".json", logger)
	if err != nil {
		t.Fatalf("凭据装载失败: %v", err)
	}
	s := New(cfg, cred, logger)
	s.Up.CodingPlanBase = up.URL + "/v1"
	s.Up.OpenRouterBase = up.URL + "/v1"
	s.Con.Base = up.URL + "/api/v5/coding-plan"
	s.OrKey = "fake-or-key"
	s.Up.OpenRouterKey = "fake-or-key"
	// 重试退避不真的等（生产是 0.5/1/2s）
	s.Up.Backoff = []time.Duration{time.Millisecond}
	return &fixture{s: s, fake: fake, srv: up}
}

// newAuthTOML 写一份临时凭据文件并返回路径（handler 与 lanes 测试共用）。
func newAuthTOML(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.toml")
	writeAuthTOML(t, path, "fake-at", "fake-rt", time.Now().Unix())
	return path
}

func writeAuthTOML(t *testing.T, path, at, rt string, created int64) {
	t.Helper()
	text := fmt.Sprintf("access_token = %q\ntoken_type = \"Bearer\"\nrefresh_token = %q\nexpires_in = 604800\ncreated_at = %d\n\n[user]\nid = \"42\"\nusername = \"tester\"\nname = \"Tester\"\nemail = \"\"\navatar_url = \"\"\n", at, rt, created)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) do(t *testing.T, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(w, req)
	return w
}

// ── Chat 上游样本（与 Python 测试逐字段一致）──────────────────────────────────

var sseUsage = map[string]any{
	"prompt_tokens": 10, "completion_tokens": 7, "total_tokens": 17,
	"completion_tokens_details": map[string]any{"reasoning_tokens": 3},
	"prompt_tokens_details":     map[string]any{"cached_tokens": 0},
}

func chunk(delta map[string]any, finish any, usage map[string]any, id string) []byte {
	o := map[string]any{
		"id": id, "object": "chat.completion.chunk", "created": 1, "model": "m",
		"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
	}
	if usage != nil {
		o["choices"] = []any{}
		o["usage"] = usage
	}
	return append(append([]byte("data: "), marshalCompactJSON(o)...), '\n', '\n')
}

func marshalCompactJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

var chatStream = concat(
	chunk(map[string]any{"role": "assistant", "reasoning_content": "think "}, nil, nil, "c1"),
	chunk(map[string]any{"reasoning_content": "ok"}, nil, nil, "c1"),
	chunk(map[string]any{"content": "Hi!"}, nil, nil, "c1"),
	chunk(map[string]any{"tool_calls": []any{map[string]any{
		"index": 0, "id": "call_1", "type": "function",
		"function": map[string]any{"name": "get_weather", "arguments": `{"city": "BJ"}`},
	}}}, nil, nil, "c1"),
	chunk(map[string]any{}, "tool_calls", nil, "c1"),
	chunk(map[string]any{}, nil, sseUsage, "c1"),
	[]byte("data: [DONE]\n\n"),
)

var chatJSON = map[string]any{
	"id": "c2", "object": "chat.completion", "created": 1, "model": "m",
	"choices": []any{map[string]any{
		"index": 0,
		"message": map[string]any{"role": "assistant", "content": "Hi!",
			"reasoning_content": "think ok"},
		"finish_reason": "stop",
	}},
	"usage": sseUsage,
}

var chatJSONBytes = marshalCompactJSON(chatJSON)

// 命中 PSEUDO_REPLY_RES 的 overload 模板
var pseudoStream = concat(
	chunk(map[string]any{"role": "assistant",
		"content": "模型「qwen3.8-27b」的请求负载过高，请稍后再试。"}, nil, nil, "c3"),
	chunk(map[string]any{}, "stop", nil, "c3"),
	[]byte("data: [DONE]\n\n"),
)

var respReq = map[string]any{
	"model":        "qwen3.8-27b",
	"stream":       true,
	"instructions": "sys prompt",
	"input":        []any{map[string]any{"type": "message", "role": "user", "content": "hello"}},
	"tools": []any{map[string]any{
		"type": "function", "name": "get_weather", "description": "w",
		"parameters": map[string]any{"type": "object",
			"properties": map[string]any{"city": map[string]any{"type": "string"}}},
	}},
}

// parseFrames 把 Responses SSE 原始响应切成事件对象。
func parseFrames(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, block := range strings.Split(string(raw), "\n\n") {
		block = strings.TrimSpace(block)
		if !strings.HasPrefix(block, "data:") {
			continue
		}
		payload := strings.TrimSpace(block[len("data:"):])
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var o map[string]any
		if err := json.Unmarshal([]byte(payload), &o); err != nil {
			t.Fatalf("SSE 帧解析失败: %v\n%s", err, payload)
		}
		events = append(events, o)
	}
	return events
}

// ── 场景 1：/v1/responses 流式（CodingPlan）──────────────────────────────────

func TestResponsesStreamCodingPlan(t *testing.T) {
	fx := newFixture(t, "stream")
	r := fx.do(t, http.MethodPost, "/v1/responses", respReq, nil)
	if r.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", r.Code, r.Body.String()[:min(500, r.Body.Len())])
	}
	if ct := r.Header().Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("Content-Type=%q", ct)
	}

	last := fx.fake.last(t)
	if !strings.Contains(last.url, "/v1/chat/completions") {
		t.Errorf("上游 URL=%s", last.url)
	}
	cb := last.payload
	msgs := asList(cb["messages"])
	if len(msgs) != 2 {
		t.Fatalf("messages=%v", cb["messages"])
	}
	if got := asMap(msgs[0]); got["role"] != "system" || got["content"] != "sys prompt" {
		t.Errorf("messages[0]=%v，期望 system/\"sys prompt\"", got)
	}
	if got := asMap(msgs[1]); got["role"] != "user" || got["content"] != "hello" {
		t.Errorf("messages[1]=%v", got)
	}
	if cb["stream"] != true {
		t.Errorf("stream=%v", cb["stream"])
	}
	if so := asMap(cb["stream_options"]); so == nil || so["include_usage"] != true {
		t.Errorf("stream_options=%v，期望 include_usage=true", cb["stream_options"])
	}
	tools := asList(cb["tools"])
	if len(tools) != 1 {
		t.Fatalf("tools=%v", cb["tools"])
	}
	fn := asMap(asMap(tools[0])["function"])
	if fn == nil || fn["name"] != "get_weather" {
		t.Errorf("tools[0].function=%v", asMap(tools[0])["function"])
	}
	// UA 门：上游必须收到中性 UA
	if ua := last.header.Get("User-Agent"); !strings.HasPrefix(ua, "ac2api/") {
		t.Errorf("上游 UA=%q，必须中性（不得 atomcode/*）", ua)
	}

	events := parseFrames(t, r.Body.Bytes())
	seqs := make([]int, 0, len(events))
	for _, e := range events {
		n, ok := e["sequence_number"].(float64)
		if !ok {
			t.Fatalf("事件缺 sequence_number: %v", e["type"])
		}
		seqs = append(seqs, int(n))
	}
	for i, n := range seqs {
		if n != i {
			t.Fatalf("sequence_number 不连续: %v", seqs)
		}
	}
	types := make([]string, 0, len(events))
	for _, e := range events {
		types = append(types, asString(e["type"]))
	}
	t.Logf("responses 流事件序列（%d 帧）: %v", len(events), types)
	if types[0] != "response.created" {
		t.Errorf("首帧=%q", types[0])
	}
	if types[len(types)-1] != "response.completed" {
		t.Errorf("末帧=%q", types[len(types)-1])
	}
	final := asMap(events[len(events)-1]["response"])
	for _, k := range []string{"id", "object", "created_at", "model", "status", "output"} {
		if _, ok := final[k]; !ok {
			t.Errorf("final response 缺字段 %q", k)
		}
	}
	if final["status"] != "completed" {
		t.Errorf("status=%v", final["status"])
	}
	var outTypes []string
	for _, oi := range asList(final["output"]) {
		outTypes = append(outTypes, asString(asMap(oi)["type"]))
	}
	want := "[reasoning message function_call]"
	if fmt.Sprint(outTypes) != want {
		t.Errorf("output 类型=%v，期望 %s", outTypes, want)
	}
	usage := asMap(final["usage"])
	if usage == nil || usage["total_tokens"] != float64(17) {
		t.Errorf("usage=%v", final["usage"])
	}
	fn2 := asMap(asList(final["output"])[2])
	if fn2["call_id"] != "call_1" || fn2["arguments"] != `{"city": "BJ"}` {
		t.Errorf("function_call=%v", fn2)
	}
}

// ── 场景 2：/v1/responses 非流式（CodingPlan）────────────────────────────────

func TestResponsesJSONCodingPlan(t *testing.T) {
	fx := newFixture(t, "json")
	r := fx.do(t, http.MethodPost, "/v1/responses", mergeBody(respReq, map[string]any{"stream": false}), nil)
	if r.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", r.Code, r.Body.String()[:min(500, r.Body.Len())])
	}
	var out map[string]any
	if err := json.Unmarshal(r.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应非 JSON: %v / %s", err, r.Body.String())
	}
	if out["object"] != "response" || out["status"] != "completed" {
		t.Errorf("object=%v status=%v", out["object"], out["status"])
	}
	var outTypes []string
	for _, oi := range asList(out["output"]) {
		outTypes = append(outTypes, asString(asMap(oi)["type"]))
	}
	if fmt.Sprint(outTypes) != "[reasoning message]" {
		t.Errorf("output 类型=%v", outTypes)
	}
	if u := asMap(out["usage"]); u == nil || u["total_tokens"] != float64(17) {
		t.Errorf("usage=%v", out["usage"])
	}
}

// ── 场景 3：/v1/responses 流式（OpenRouter 模型映射）─────────────────────────

func TestResponsesStreamOpenRouter(t *testing.T) {
	fx := newFixture(t, "stream")
	r := fx.do(t, http.MethodPost, "/v1/responses",
		mergeBody(respReq, map[string]any{"model": "openrouter/thinkingmachines/inkling:free"}), nil)
	if r.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", r.Code, r.Body.String()[:min(500, r.Body.Len())])
	}
	last := fx.fake.last(t)
	if last.path != "/v1/chat/completions" {
		t.Errorf("path=%s", last.path)
	}
	if got := asString(last.payload["model"]); got != "thinkingmachines/inkling:free" {
		t.Errorf("上游 model=%q，期望剥掉 openrouter/ 前缀", got)
	}
	// OpenRouter app-attribution 头：缺这两个头免费模型会被 403
	if last.header.Get("HTTP-Referer") == "" || last.header.Get("X-Title") != "AtomCode" {
		t.Errorf("缺 OpenRouter attribution 头: %v", last.header)
	}
	if auth := last.header.Get("Authorization"); auth != "Bearer fake-or-key" {
		t.Errorf("OpenRouter Authorization=%q", auth)
	}
	events := parseFrames(t, r.Body.Bytes())
	if len(events) == 0 || asString(events[len(events)-1]["type"]) != "response.completed" {
		t.Errorf("末帧不是 response.completed")
	}
}

// ── 场景 4：/v1/chat/completions 流式回归（裸透传字节不变）───────────────────

func TestChatStreamPassthrough(t *testing.T) {
	fx := newFixture(t, "stream")
	r := fx.do(t, http.MethodPost, "/v1/chat/completions", map[string]any{
		"model": "qwen3.8-27b", "stream": true,
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	}, nil)
	if r.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", r.Code, r.Body.String()[:min(300, r.Body.Len())])
	}
	body := r.Body.Bytes()
	if !bytesContain(body, []byte("data: ")) || !bytesContain(body, []byte("[DONE]")) {
		t.Errorf("响应不像 SSE: %s", body)
	}
	if string(body) != string(chatStream) {
		t.Errorf("透传行为变了：期望逐字节等于上游\n got=%s\nwant=%s", body, chatStream)
	}
	// include_usage 由网关注入
	if so := asMap(fx.fake.last(t).payload["stream_options"]); so == nil || so["include_usage"] != true {
		t.Errorf("stream_options=%v", fx.fake.last(t).payload["stream_options"])
	}
}

// ── 场景 5：流内额度伪回复拦截 → response.failed ─────────────────────────────

func TestResponsesStreamPseudoFailed(t *testing.T) {
	fx := newFixture(t, "pseudo")
	r := fx.do(t, http.MethodPost, "/v1/responses", respReq, nil)
	if r.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", r.Code, r.Body.String()[:min(500, r.Body.Len())])
	}
	events := parseFrames(t, r.Body.Bytes())
	if len(events) == 0 {
		t.Fatal("无事件")
	}
	last := events[len(events)-1]
	if asString(last["type"]) != "response.failed" {
		t.Fatalf("末帧=%v，期望 response.failed", last["type"])
	}
	resp := asMap(last["response"])
	err := asMap(resp["error"])
	if err == nil {
		t.Fatalf("response 缺 error: %v", resp)
	}
	if err["code"] != "overloaded" {
		t.Errorf("error.code=%v，期望 overloaded", err["code"])
	}
}

// ── 以下补齐 Python 测试未覆盖的关键路径 ─────────────────────────────────────

// chat 非流式伪回复 → 429 + OpenAI 错误体（含 code/reset_at）
func TestChatNonStreamPseudo429(t *testing.T) {
	fx := newFixture(t, "json")
	fx.fake.body = ""
	// 让假上游回一段 quota 伪回复
	fx.fake.kind = "quota"
	fakeQuota(fx)
	r := fx.do(t, http.MethodPost, "/v1/chat/completions", map[string]any{
		"model": "glm5.3-flash", "stream": false,
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	}, nil)
	if r.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d body=%s", r.Code, r.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(r.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	e := asMap(out["error"])
	if e["type"] != "rate_limit_error" || e["code"] != "quota_exhausted" {
		t.Errorf("error=%v", e)
	}
	if e["reset_at"] != "03:13" {
		t.Errorf("reset_at=%v", e["reset_at"])
	}
	if ra := r.Header().Get("Retry-After"); !isPositiveInt(ra) {
		t.Errorf("Retry-After=%q，期望正整数秒", ra)
	}
}

// quota 文案命中需要一个动态 reset 时刻（03:13），用专用 kind 回包
func fakeQuota(fx *fixture) {
	fx.fake.body = string(marshalCompactJSON(map[string]any{
		"id": "c9", "object": "chat.completion", "created": 1, "model": "glm5.3-flash",
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{
			"role": "assistant",
			"content": "模型「glm5.3-flash」在当前 CodingPlan 用量窗口内已达上限。" +
				"当前滚动窗口约在当日 03:13 结束并重置额度，请稍后重试。",
		}, "finish_reason": "stop"}},
		"usage": sseUsage,
	}))
}

// 非流式上游多包一层 {"data":{...}}：Python 版已知缺陷（responses 直接解析失败），
// Go 版必须解开并正常出 Responses JSON。
func TestResponsesUnwrapDataLayer(t *testing.T) {
	fx := newFixture(t, "json")
	fx.fake.dataPkg = true
	r := fx.do(t, http.MethodPost, "/v1/responses", mergeBody(respReq, map[string]any{"stream": false}), nil)
	if r.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s —— 包裹层没解开", r.Code, r.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(r.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["object"] != "response" {
		t.Errorf("object=%v", out["object"])
	}
	// chat 路由同样要解开（Python 原样透传是缺陷）
	fx2 := newFixture(t, "json")
	fx2.fake.dataPkg = true
	r2 := fx2.do(t, http.MethodPost, "/v1/chat/completions", map[string]any{
		"model": "glm5.3-flash", "stream": false,
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	}, nil)
	if r2.Code != http.StatusOK {
		t.Fatalf("chat status=%d", r2.Code)
	}
	var chat map[string]any
	if err := json.Unmarshal(r2.Body.Bytes(), &chat); err != nil {
		t.Fatal(err)
	}
	if _, ok := chat["choices"]; !ok {
		t.Errorf("chat 路由没解包: %s", r2.Body.String())
	}
}

// Anthropic 路由：流式与伪回复（补齐 Python 无测试的第三协议面）
func TestMessagesStreamAndPseudo(t *testing.T) {
	fx := newFixture(t, "stream")
	r := fx.do(t, http.MethodPost, "/v1/messages", map[string]any{
		"model":  "qwen3.8-27b",
		"stream": true,
		"messages": []any{map[string]any{"role": "user",
			"content": []any{map[string]any{"type": "text", "text": "hi"}}}},
	}, nil)
	if r.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", r.Code, r.Body.String())
	}
	if ct := r.Header().Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("Content-Type=%q", ct)
	}
	body := r.Body.String()
	for _, want := range []string{"message_start", "content_block_delta", "message_stop"} {
		if !strings.Contains(body, want) {
			t.Errorf("Anthropic SSE 缺 %q:\n%s", want, body)
		}
	}

	// 非流式
	fx2 := newFixture(t, "json")
	r2 := fx2.do(t, http.MethodPost, "/v1/messages", map[string]any{
		"model": "qwen3.8-27b",
		"messages": []any{map[string]any{"role": "user",
			"content": []any{map[string]any{"type": "text", "text": "hi"}}}},
	}, nil)
	if r2.Code != http.StatusOK {
		t.Fatalf("非流式 status=%d body=%s", r2.Code, r2.Body.String())
	}
	var msg map[string]any
	if err := json.Unmarshal(r2.Body.Bytes(), &msg); err != nil {
		t.Fatal(err)
	}
	if msg["type"] != "message" || msg["role"] != "assistant" {
		t.Errorf("非流式形状=%v / %v", msg["type"], msg["role"])
	}

	// 流内伪回复 → Anthropic error 帧。
	// adapters/anthropic.py 把上游 error 帧固定转成 {"type":"api_error"}
	// （Python chat_sse_to_anthropic 的 upstream_error 分支），不是 overloaded_error；
	// 这里断言的是与 Python 一致的实际形状。
	fx3 := newFixture(t, "pseudo")
	r3 := fx3.do(t, http.MethodPost, "/v1/messages", map[string]any{
		"model":  "qwen3.8-27b",
		"stream": true,
		"messages": []any{map[string]any{"role": "user",
			"content": []any{map[string]any{"type": "text", "text": "hi"}}}},
	}, nil)
	body3 := r3.Body.String()
	if !strings.Contains(body3, `event: error`) ||
		!strings.Contains(body3, `"type":"api_error"`) ||
		!strings.Contains(body3, "请求负载过高") {
		t.Errorf("伪回复未转 Anthropic error 帧:\n%s", body3)
	}
}

// 鉴权闸门：API_KEY（_guard）与未登录（_cred_guard）
func TestAuthGates(t *testing.T) {
	fx := newFixture(t, "stream")

	// 配置 API_KEY 后无 Bearer → 401 auth_error
	fx.s.Cfg.APIKey = "sk-test"
	fx.s.recomputeAuth() // P4 起鉴权读运行时快照，改 Cfg 后需重算
	for _, path := range []string{"/v1/chat/completions", "/v1/responses", "/v1/messages", "/v1/models", "/status"} {
		method := http.MethodPost
		var body any = map[string]any{"model": "m", "messages": []any{
			map[string]any{"role": "user", "content": "hi"}}}
		if path == "/v1/models" || path == "/status" {
			method, body = http.MethodGet, nil
		}
		r := fx.do(t, method, path, body, nil)
		if r.Code != http.StatusUnauthorized {
			t.Errorf("%s 无 key 应 401，得 %d", path, r.Code)
		}
		if !strings.Contains(r.Body.String(), "invalid api key") {
			t.Errorf("%s 错误体=%s", path, r.Body.String())
		}
	}
	// /health 不在闸门内
	if r := fx.do(t, http.MethodGet, "/health", nil, nil); r.Code != http.StatusOK {
		t.Errorf("/health 应放行，得 %d", r.Code)
	}
	// 带对 key 放行
	r := fx.do(t, http.MethodPost, "/v1/chat/completions", map[string]any{
		"model": "m", "messages": []any{map[string]any{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer sk-test"})
	if r.Code != http.StatusOK {
		t.Errorf("带 key 应 200，得 %d body=%s", r.Code, r.Body.String())
	}

	// 未登录：cred = nil → /v1/chat/completions 401 且带 login_url
	fx.s.ClearCred()
	r2 := fx.do(t, http.MethodPost, "/v1/chat/completions", map[string]any{
		"model": "m", "messages": []any{map[string]any{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer sk-test"})
	if r2.Code != http.StatusUnauthorized {
		t.Fatalf("未登录应 401，得 %d", r2.Code)
	}
	if !strings.Contains(r2.Body.String(), `"login_url"`) {
		t.Errorf("未登录错误体缺 login_url: %s", r2.Body.String())
	}
	// OpenRouter 分支不受登录闸门影响？——Python 版 _cred_guard 在最前，一律 401
	r3 := fx.do(t, http.MethodPost, "/v1/chat/completions", map[string]any{
		"model":    "openrouter/thinkingmachines/inkling:free",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer sk-test"})
	if r3.Code != http.StatusUnauthorized {
		t.Errorf("未登录时 OpenRouter 也应被 _cred_guard 拦住（与 Python 一致），得 %d", r3.Code)
	}
}

// 控制面端点：/v1/models（plan_available 过滤 + OpenRouter 追加）与 /status
func TestControlEndpoints(t *testing.T) {
	var modelsBody = []byte(`[
	  {"display_model_name":"glm5.3-flash","plan_available":true},
	  {"display_model_name":"hidden-model","plan_available":false},
	  {"display_model_name":"default-avail"}
	]`)
	var mu sync.Mutex
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/models-v2"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(modelsBody)
		case strings.HasSuffix(r.URL.Path, "/status-v2"):
			_, _ = io.WriteString(w, `{"codingplan_free":{"plan_name":"Lite-体验版",
			  "status":"active","remaining_days":5,"expires_at":"2026-10-30"},
			  "current_usage":{"window_tokens_used":123,"window_token_limit":1000000,
			  "reset_at":"2026-10-25T03:13:00Z","seconds_until_reset":3600}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(up.Close)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{Host: "127.0.0.1", Port: 8788, StateDir: t.TempDir()}
	cred, err := lanes.NewCredential(newAuthTOML(t), newAuthTOML(t)+".json", logger)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, cred, logger)
	s.Con.Base = up.URL + "/api/v5/coding-plan"
	s.OrKey = ""
	fx := &fixture{s: s, srv: up}

	r := fx.do(t, http.MethodGet, "/v1/models", nil, nil)
	if r.Code != http.StatusOK {
		t.Fatalf("models status=%d body=%s", r.Code, r.Body.String())
	}
	var ml map[string]any
	if err := json.Unmarshal(r.Body.Bytes(), &ml); err != nil {
		t.Fatal(err)
	}
	if ml["object"] != "list" {
		t.Errorf("object=%v", ml["object"])
	}
	ids := modelIDs(t, ml)
	if fmt.Sprint(ids) != "[glm5.3-flash default-avail]" {
		t.Errorf("ids=%v，期望过滤掉 plan_available=false", ids)
	}

	// OrKey 非空时追加 OpenRouter 清单（owned_by=openrouter）
	s.OrKey = "k"
	r2 := fx.do(t, http.MethodGet, "/v1/models", nil, nil)
	var ml2 map[string]any
	if err := json.Unmarshal(r2.Body.Bytes(), &ml2); err != nil {
		t.Fatal(err)
	}
	ids = modelIDs(t, ml2)
	if len(ids) != 2+len(config.OpenRouterModels) {
		t.Errorf("含 OpenRouter 时 ids 数=%d，期望 %d", len(ids), 2+len(config.OpenRouterModels))
	}

	// /status 字段映射
	r3 := fx.do(t, http.MethodGet, "/status", nil, nil)
	var st map[string]any
	if err := json.Unmarshal(r3.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st["plan"] != "Lite-体验版" || st["window_used"] != float64(123) ||
		st["window_limit"] != float64(1000000) || st["seconds_until_reset"] != float64(3600) {
		t.Errorf("/status=%v", st)
	}
	if _, ok := st["window_reset"]; !ok {
		t.Errorf("/status 缺 window_reset: %v", st)
	}

	// 控制面挂掉 → /status 502（Python: get_status() 异常 → None → 502）
	s.Con.Base = "http://127.0.0.1:1/api/v5/coding-plan"
	if r4 := fx.do(t, http.MethodGet, "/status", nil, nil); r4.Code != http.StatusBadGateway {
		t.Errorf("控制面不可达时 /status=%d，期望 502", r4.Code)
	}
}

func modelIDs(t *testing.T, ml map[string]any) []string {
	t.Helper()
	var ids []string
	for _, di := range asList(ml["data"]) {
		ids = append(ids, asString(asMap(di)["id"]))
	}
	return ids
}

// 上游错误直传：非 200 → SendError 的 status 原样回给客户端（含 403 UA 门不重试）
func TestUpstreamErrorPassthrough(t *testing.T) {
	fx := newFixture(t, "stream")
	fx.fake.mu.Lock()
	fx.fake.status = 403
	fx.fake.mu.Unlock()
	r := fx.do(t, http.MethodPost, "/v1/chat/completions", map[string]any{
		"model": "m", "messages": []any{map[string]any{"role": "user", "content": "hi"}},
	}, nil)
	if r.Code != http.StatusForbidden {
		t.Fatalf("status=%d，期望 403 直传", r.Code)
	}
	// 403 不在重试集合里：上游只被打了 1 次
	fx.fake.mu.Lock()
	n := len(fx.fake.calls)
	fx.fake.mu.Unlock()
	if n != 1 {
		t.Errorf("403 被重试了 %d 次，期望 1 次（UA 门/权限错不重试）", n)
	}

	// 502 会被重试（0.5/1/2s），共 4 次；为不把测试拖到秒级，改用 429→ 同样在重试集合
	// ——所以断言次数即可，退避时长在生产里是固定的。
	fx2 := newFixture(t, "stream")
	fx2.fake.mu.Lock()
	fx2.fake.status = 500
	fx2.fake.mu.Unlock()
	r2 := fx2.do(t, http.MethodPost, "/v1/chat/completions", map[string]any{
		"model": "m", "messages": []any{map[string]any{"role": "user", "content": "hi"}},
	}, nil)
	if r2.Code != http.StatusInternalServerError {
		t.Errorf("重试耗尽后应回 500，得 %d", r2.Code)
	}
	fx2.fake.mu.Lock()
	n2 := len(fx2.fake.calls)
	fx2.fake.mu.Unlock()
	if n2 != 4 {
		t.Errorf("500 重试次数=%d，期望 4（1+3）", n2)
	}
}

// 请求体校验（三协议各自的形状与文案）
func TestBadRequestShapes(t *testing.T) {
	fx := newFixture(t, "stream")
	r := fx.do(t, http.MethodPost, "/v1/chat/completions", map[string]any{"model": "m"}, nil)
	if r.Code != http.StatusBadRequest || !strings.Contains(r.Body.String(), "'messages' is required") {
		t.Errorf("chat 400=%d %s", r.Code, r.Body.String())
	}
	r = fx.do(t, http.MethodPost, "/v1/responses", map[string]any{"model": "m"}, nil)
	if r.Code != http.StatusBadRequest || !strings.Contains(r.Body.String(), "'input' is required") {
		t.Errorf("responses 400=%d %s", r.Code, r.Body.String())
	}
	r = fx.do(t, http.MethodPost, "/v1/messages", map[string]any{"model": "m"}, nil)
	if r.Code != http.StatusBadRequest {
		t.Errorf("messages 400=%d", r.Code)
	}
	if !strings.HasPrefix(r.Body.String(), `{"error":`) && !strings.Contains(r.Body.String(), `"type":"error"`) {
		t.Errorf("messages 错误体不是 Anthropic 形状: %s", r.Body.String())
	}
}

func bytesContain(haystack, needle []byte) bool {
	return strings.Contains(string(haystack), string(needle))
}

func isPositiveInt(s string) bool {
	if s == "" {
		return false
	}
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n > 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
