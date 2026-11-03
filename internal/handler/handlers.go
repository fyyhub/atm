// 三协议路由，对应 Python 版 routes/chat.py、routes/responses.py、routes/anthropic.py。
//
// 共同约定（与 Python 一致）：
//   - 逐端点显式过 _guard / _cred_guard
//   - 上游两条通道按模型前缀分流（openrouter/* → OpenRouter，其余 → CodingPlan）
//   - _send_* 失败时把 (jsonify, status) 原样回给客户端
//   - 流式必带 stream_options.include_usage（客户端已带则尊重客户端）
//   - 上游把额度耗尽/过载伪装成 HTTP 200 的正常回复文本，由 DetectPseudoReply
//     识别：非流式转 429 + Retry-After，流式在首个内容段替换为 SSE error 帧
//
// 已知缺陷修复（不照抄 Python）：非流式上游响应间歇性多包一层 {"data":{...}}，
// Python 版 chat 路由原样透传、responses/messages 路由直接解析失败；Go 版在
// 所有 CodingPlan 非流式路径上先 UnwrapDataLayer 再处理。
package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"atomcode2api/internal/adapters"
	"atomcode2api/internal/config"
	"atomcode2api/internal/pool"
	"atomcode2api/internal/upstream"
)

// ── /v1/chat/completions ─────────────────────────────────────────────────────

func (s *Server) chatCompletions(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) || !s.credGuard(w) {
		return
	}
	body, bodyLen, ok := readJSONBody(r)
	if !ok || len(asList(body["messages"])) == 0 {
		writeJSON(w, http.StatusBadRequest, openAIErrorBody(
			"invalid request: 'messages' is required", "invalid_request_error"))
		return
	}

	modelID := asString(body["model"])
	rid := s.nextRID()
	tIn := time.Now()
	s.logIn(rid, r, body, bodyLen)
	wantStream := truthy(body["stream"])

	// ── OpenRouter 分支（免费模型，不吃 CodingPlan 额度）──
	if config.IsOpenRouterModel(modelID) {
		if s.OrKey == "" {
			writeJSON(w, http.StatusUnauthorized, openAIErrorBody(
				"OpenRouter API key 未配置（在 ~/.atomcode/config.toml 或 OPENROUTER_API_KEY 环境变量）",
				"auth_error"))
			return
		}
		orBody := mergeBody(body, map[string]any{"model": config.OpenRouterUpstreamModel(modelID)})
		resp, serr := s.Up.SendOpenRouter(r.Context(), marshalCompact(orBody), rid)
		if serr != nil {
			writeJSON(w, serr.Status, serr.Body)
			return
		}
		defer resp.Body.Close()
		t0 := time.Now()
		if !wantStream {
			content, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
			s.doneLog(rid, "openrouter", len(content), t0)
			writeRaw(w, http.StatusOK, "application/json; charset=utf-8", content)
			return
		}
		// OpenRouter 分支：纯透传，不做伪回复拦截（Python 同）；不纳入账号池
		s.passthroughStream(w, r, rid, tIn, t0, resp.Body, "openrouter", nil, nil, false)
		return
	}

	// ── CodingPlan 分支 ──
	// 对齐官方 CLI（openai_compat.rs:1335）：必带 include_usage，上游才会在流末尾
	// 发 usage 块——这是额度观察与记账的依据。客户端已带则尊重客户端。
	if wantStream && body["stream_options"] == nil {
		body = mergeBody(body, map[string]any{"stream_options": map[string]any{"include_usage": true}})
	}
	payload := marshalCompact(body)
	key := sessionKey(r, body, body) // chat 请求体即 Chat 形状

	if !wantStream {
		t0 := time.Now()
		res := s.sendNonStream(r, payload, rid, modelID, key)
		if res.serr != nil {
			s.writeSendError(w, res.serr)
			return
		}
		if res.pseudo != nil {
			s.logQuota(rid, res.pseudo, modelID, "200 伪回复转 429")
			s.pseudoOpenAIHTTP(w, res.pseudo, res.txt)
			return
		}
		s.doneLog(rid, "chat", len(res.content), t0)
		writeRaw(w, http.StatusOK, "application/json; charset=utf-8", res.content)
		return
	}

	// SSE 透传：换人循环（只在尚未向客户端写出任何字节前允许换人——
	// SendError 与窥探期伪回复满足；开始透传后故障只能注 error 帧）。
	t0 := time.Now()
	maxAtt := s.Pool.MaxAttempts()
	for attempt := 0; ; attempt++ {
		acct, pinned, aerr := s.acquireForSend(r, key, attempt == 0)
		if aerr != nil {
			s.writeSendError(w, aerr)
			return
		}
		resp, serr := s.Up.SendCodingPlan(r.Context(), acct.Cred, payload, rid, modelID)
		if serr != nil {
			s.Pool.OnSendError(acct, serr.Status, errSummary(serr))
			s.Pool.Release(acct)
			if !pinned && failoverable(serr.Status) && attempt+1 < maxAtt {
				s.Log.Info("换人重试", slog.String("rid", rid),
					slog.Int("status", serr.Status), slog.Int("attempt", attempt+1))
				continue
			}
			s.writeSendError(w, serr)
			return
		}
		tail := &pseudoTail{}
		canFailover := !pinned && attempt+1 < maxAtt
		out := s.passthroughStream(w, r, rid, tIn, t0, resp.Body, "chat", tail, acct, canFailover)
		resp.Body.Close()
		if out == outDone && !pinned {
			s.Pool.BindSticky(key, acct.ID)
		}
		s.Pool.Release(acct)
		if out == outFailover {
			s.Log.Info("换人重试", slog.String("rid", rid),
				slog.String("reason", "流窥探命中伪回复"), slog.Int("attempt", attempt+1))
			continue
		}
		// 流末后置伪回复检测（已透传，只记日志与冷却）
		if out == outDone {
			if p := DetectPseudoReply(tail.text()); p != nil {
				s.Pool.RecordPseudo(acct, p.Kind, RetryAfterSeconds(p.Reset))
				s.Log.Warn("done:", slog.String("rid", rid),
					slog.String("line", fmt.Sprintf("quota(%s) reset=%s —— 上游 200 伪回复（已透传）",
						p.Kind, orQ(p.Reset))), slog.String("model", modelID))
			}
		}
		return
	}
}

// pseudoTail 累积透传流的正文（上限 4KB）与 usage，供流末后置检测与 tokens 汇报。
type pseudoTail struct {
	parts   []string
	size    int
	usage   map[string]any
	usageOK bool
}

func (t *pseudoTail) add(contents []string) {
	if t.size < 4096 {
		t.parts = append(t.parts, contents...)
		for _, c := range contents {
			t.size += len(c)
		}
	}
}

func (t *pseudoTail) text() string { return joinAll(t.parts) }

// noteLine 从原始 SSE 行记录 usage（流末 tokens= 汇报用）。
func (t *pseudoTail) noteLine(line string) {
	if t.usageOK {
		return
	}
	if u := usageFromSSELine(line); u != nil {
		t.usage = u
		t.usageOK = true
	}
}

// streamOutcome 流式转发的终局。
type streamOutcome int

const (
	outDone      streamOutcome = iota // 正常流完
	outFailover                       // 窥探期命中伪回复/读失败，未写客户端 → 可换人
	outClosed                         // 客户端断开或流中断
)

// peekMaxChunks 流窥探的 chunk 上限（8×4096=32KB）。
const peekMaxChunks = 8

// peekStream 转发前窥探：逐 chunk 读上游，直到首个内容段出现或达上限/EOF/出错。
// 返回已读原始字节（供回放）与首段内容（可能跨多行累积）。
func peekStream(body io.Reader, tap *lineTap) (pre []byte, content string, err error) {
	tmp := make([]byte, 4096)
	for i := 0; i < peekMaxChunks; i++ {
		n, rerr := body.Read(tmp)
		if n > 0 {
			chunk := tmp[:n]
			pre = append(pre, chunk...)
			for _, line := range tap.feed(chunk) {
				if c := FirstContentLine(line); c != "" {
					content += c
				}
			}
			if content != "" {
				return pre, content, nil
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return pre, "", nil
			}
			return pre, "", rerr
		}
	}
	return pre, "", nil
}

// passthroughStream 裸字节转发上游流（chat 路由专用，保留上游帧格式不动）。
//
// tail 非 nil（CodingPlan 分支）时同时按行切出内容做伪回复拦截：首个内容段命中
// 就吐 error + [DONE] 并停止转发；流末 done 行带 ttft 与 tokens。
// tail 为 nil（OpenRouter 分支）时只转发与计测。
// acct 非 nil 时在拦截点/流末给账号池记账。
//
// canFailover（CodingPlan 且仍有换人余量）时先窥探：读至首个内容段再决定——
// 伪回复或读失败直接返回 outFailover（一字节未写客户端）；正常则回放缓冲并
// 进入主循环（首段已审，拦截解除）。canFailover=false 时行为与旧版一致。
//
// 对应 routes/chat.py 的 generate() / or_generate()。
func (s *Server) passthroughStream(
	w http.ResponseWriter, r *http.Request,
	rid string, tIn, t0 time.Time,
	upstreamBody io.Reader, kind string, tail *pseudoTail, acct *pool.Account, canFailover bool,
) streamOutcome {
	tap := &lineTap{}
	intercept := tail != nil // 上游伪回复必以首个 content delta 整段出现，只拦那一段

	var pre []byte
	if canFailover && tail != nil {
		buf, content, perr := peekStream(upstreamBody, tap)
		pre = buf
		if perr != nil {
			s.Pool.RecordFailure(acct, "net", "流窥探读失败: "+perr.Error(), 0)
			s.Log.Warn("流窥探读失败，换人", slog.String("rid", rid), slog.String("err", perr.Error()))
			return outFailover
		}
		if content != "" {
			if p := DetectPseudoReply(content); p != nil {
				s.Pool.RecordPseudo(acct, p.Kind, RetryAfterSeconds(p.Reset))
				s.logQuota(rid, p, "", "窥探命中伪回复（未写客户端）")
				return outFailover
			}
			intercept = false // 首段已审
			tail.add([]string{content})
		}
	}

	sseHeaders(w)
	flusher, _ := w.(http.Flusher)

	total := 0
	if len(pre) > 0 {
		if _, werr := w.Write(pre); werr != nil {
			s.logDisconnect(rid, kind, total, t0)
			return outClosed
		}
		total += len(pre)
		if flusher != nil {
			flusher.Flush()
		}
	}

	var ttft time.Duration
	ttftOK := len(pre) > 0
	if ttftOK {
		ttft = time.Since(tIn)
	}

	buf := make([]byte, 4096) // Python iter_content(chunk_size=4096)
	for {
		if err := r.Context().Err(); err != nil {
			s.logDisconnect(rid, kind, total, t0)
			return outClosed
		}
		n, rerr := upstreamBody.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if !ttftOK {
				ttft = time.Since(tIn)
				ttftOK = true
			}
			total += n

			var contents []string
			if intercept || tail != nil {
				for _, line := range tap.feed(chunk) {
					if c := FirstContentLine(line); c != "" {
						contents = append(contents, c)
					}
					if tail != nil {
						tail.noteLine(line)
					}
				}
			}
			if len(contents) > 0 {
				if intercept {
					joined := joinAll(contents)
					if p := DetectPseudoReply(joined); p != nil {
						s.Pool.RecordPseudo(acct, p.Kind, RetryAfterSeconds(p.Reset))
						s.logQuota(rid, p, "", "流内伪回复替换为 SSE error")
						// Python: f"data: {json.dumps(err, ensure_ascii=False)}\n\n"（默认分隔符，带空格）
						frame := marshalSpaced(map[string]any{"error": ssePseudoErrFields(p, joined)})
						_, _ = w.Write(append(append([]byte("data: "), frame...), '\n', '\n'))
						_, _ = w.Write([]byte("data: [DONE]\n\n"))
						if flusher != nil {
							flusher.Flush()
						}
						return outDone
					}
					intercept = false
				}
				if tail != nil {
					tail.add(contents)
				}
			}

			if _, werr := w.Write(chunk); werr != nil {
				s.logDisconnect(rid, kind, total, t0)
				return outClosed
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			s.Log.Error("流中断", slog.String("rid", rid), slog.String("err", rerr.Error()),
				slog.String("line", fmt.Sprintf("%s %dB %.1fs", kind, total, time.Since(t0).Seconds())))
			return outClosed
		}
	}

	info := fmt.Sprintf("%dB %.1fs ttft=%s", total, time.Since(t0).Seconds(), fmtTTFT(ttft, ttftOK))
	if tail != nil && tail.usageOK {
		info += fmt.Sprintf(" tokens=%s/%s", pyVal(tail.usage["prompt_tokens"]), pyVal(tail.usage["completion_tokens"]))
		if acct != nil {
			s.Pool.RecordSuccess(acct, tail.usage)
		}
	}
	if kind == "chat" {
		// Python CodingPlan 分支 done 行不带协议标签（"done: %dB %.1fs ttft=..."）
		s.Log.Info("done:", slog.String("rid", rid), slog.String("line", info))
		return outDone
	}
	s.Log.Info("done:", slog.String("rid", rid), slog.String("line", kind+" "+info))
	return outDone
}

func (s *Server) logDisconnect(rid, kind string, total int, t0 time.Time) {
	s.Log.Warn("client 断开", slog.String("rid", rid),
		slog.String("line", fmt.Sprintf("%s %dB %.1fs", kind, total, time.Since(t0).Seconds())))
}

// ── /v1/responses ────────────────────────────────────────────────────────────

func (s *Server) responsesAPI(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) || !s.credGuard(w) {
		return
	}
	body, _, ok := readJSONBody(r)
	if !ok || len(body) == 0 {
		writeJSON(w, http.StatusBadRequest, openAIErrorBody(
			"invalid request: JSON object body required", "invalid_request_error"))
		return
	}
	chatBody := adapters.ResponsesToChat(body)
	if len(asList(chatBody["messages"])) == 0 {
		writeJSON(w, http.StatusBadRequest, openAIErrorBody(
			"invalid request: 'input' is required", "invalid_request_error"))
		return
	}

	modelID := asString(body["model"])
	rid := s.nextRID()
	wantStream := truthy(chatBody["stream"])
	// 与 chat 同款：流式必带 include_usage，上游才会在流末发 usage 块
	if wantStream && chatBody["stream_options"] == nil {
		chatBody = mergeBody(chatBody, map[string]any{"stream_options": map[string]any{"include_usage": true}})
	}

	// OpenRouter 分支：未配 key 时 Python 版回 OpenAI 形状 401
	if denied, msg := s.guardOpenRouter(modelID); denied {
		writeJSON(w, http.StatusUnauthorized, openAIErrorBody(msg, "auth_error"))
		return
	}

	// OpenRouter 分支：不纳入账号池，单次发送
	if config.IsOpenRouterModel(modelID) {
		orBody := mergeBody(chatBody, map[string]any{"model": config.OpenRouterUpstreamModel(modelID)})
		resp, serr := s.Up.SendOpenRouter(r.Context(), marshalCompact(orBody), rid)
		if serr != nil {
			writeJSON(w, serr.Status, serr.Body)
			return
		}
		defer resp.Body.Close()
		t0 := time.Now()
		if wantStream {
			s.streamAdapter(w, r, rid, t0, resp.Body, "responses", modelID, nil, false, func(lines adapters.SSELines) iter_seq_bytes {
				return adapters.ChatSSEToResponses(lines, modelID)
			})
			return
		}
		content, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		content = upstream.UnwrapDataLayer(content)
		chatJSON, txt := decodeChatJSON(content)
		if p := DetectPseudoReply(txt); p != nil {
			s.logQuota(rid, p, modelID, "200 伪回复转 429")
			s.pseudoOpenAIHTTP(w, p, txt)
			return
		}
		if chatJSON == nil {
			writeJSON(w, http.StatusBadGateway, openAIErrorBody(
				"upstream returned non-JSON body", "upstream_error"))
			return
		}
		out := marshalCompact(adapters.ChatJSONToResponses(chatJSON, modelID))
		s.doneLog(rid, "responses", len(out), t0)
		writeRaw(w, http.StatusOK, "application/json; charset=utf-8", out)
		return
	}

	// CodingPlan 分支：账号池换人循环（key 从翻译后的 chatBody + 原始 body 提取）
	payload := marshalCompact(chatBody)
	key := sessionKey(r, chatBody, body)
	if wantStream {
		t0 := time.Now()
		s.streamAdapterCodingPlan(w, r, rid, t0, payload, "responses", modelID, key, func(lines adapters.SSELines) iter_seq_bytes {
			return adapters.ChatSSEToResponses(lines, modelID)
		})
		return
	}
	t0 := time.Now()
	res := s.sendNonStream(r, payload, rid, modelID, key)
	if res.serr != nil {
		s.writeSendError(w, res.serr)
		return
	}
	if res.pseudo != nil {
		s.logQuota(rid, res.pseudo, modelID, "200 伪回复转 429")
		s.pseudoOpenAIHTTP(w, res.pseudo, res.txt)
		return
	}
	if res.chatJSON == nil {
		writeJSON(w, http.StatusBadGateway, openAIErrorBody(
			"upstream returned non-JSON body", "upstream_error"))
		return
	}
	out := marshalCompact(adapters.ChatJSONToResponses(res.chatJSON, modelID))
	s.doneLog(rid, "responses", len(out), t0)
	writeRaw(w, http.StatusOK, "application/json; charset=utf-8", out)
}

// ── /v1/messages（Anthropic）─────────────────────────────────────────────────

func (s *Server) messagesAPI(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) || !s.credGuard(w) {
		return
	}
	body, _, ok := readJSONBody(r)
	if !ok || len(asList(body["messages"])) == 0 {
		writeJSON(w, http.StatusBadRequest, adapters.AnthropicErrorBody(
			"invalid_request_error", "invalid request: 'messages' is required"))
		return
	}
	chatBody := adapters.AnthropicToChat(body)
	if len(asList(chatBody["messages"])) == 0 {
		writeJSON(w, http.StatusBadRequest, adapters.AnthropicErrorBody(
			"invalid_request_error", "invalid request: 'messages' is required"))
		return
	}

	modelID := asString(body["model"])
	rid := s.nextRID()
	wantStream := truthy(chatBody["stream"])
	if wantStream && chatBody["stream_options"] == nil {
		chatBody = mergeBody(chatBody, map[string]any{"stream_options": map[string]any{"include_usage": true}})
	}

	// OpenRouter 分支：未配 key 时 Python 版回 Anthropic 形状 401（authentication_error）
	if denied, _ := s.guardOpenRouter(modelID); denied {
		writeJSON(w, http.StatusUnauthorized, adapters.AnthropicErrorBody(
			"authentication_error", "OpenRouter API key 未配置"))
		return
	}

	// OpenRouter 分支：不纳入账号池，单次发送
	if config.IsOpenRouterModel(modelID) {
		orBody := mergeBody(chatBody, map[string]any{"model": config.OpenRouterUpstreamModel(modelID)})
		resp, serr := s.Up.SendOpenRouter(r.Context(), marshalCompact(orBody), rid)
		if serr != nil {
			writeJSON(w, serr.Status, serr.Body)
			return
		}
		defer resp.Body.Close()
		t0 := time.Now()
		if wantStream {
			s.streamAdapter(w, r, rid, t0, resp.Body, "messages", modelID, nil, false, func(lines adapters.SSELines) iter_seq_bytes {
				return adapters.ChatSSEToAnthropic(lines.Seq, modelID)
			})
			return
		}
		content, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		content = upstream.UnwrapDataLayer(content)
		chatJSON, txt := decodeChatJSON(content)
		if p := DetectPseudoReply(txt); p != nil {
			s.logQuota(rid, p, modelID, "200 伪回复转 429")
			s.pseudoAnthropicHTTP(w, p, txt)
			return
		}
		if chatJSON == nil {
			writeJSON(w, http.StatusBadGateway, adapters.AnthropicErrorBody(
				"api_error", "upstream returned non-JSON body"))
			return
		}
		out := marshalCompact(adapters.ChatJSONToAnthropic(chatJSON, modelID))
		s.doneLog(rid, "messages", len(out), t0)
		writeRaw(w, http.StatusOK, "application/json; charset=utf-8", out)
		return
	}

	// CodingPlan 分支：账号池换人循环（key 从翻译后的 chatBody + 原始 body 提取）
	payload := marshalCompact(chatBody)
	key := sessionKey(r, chatBody, body)
	if wantStream {
		t0 := time.Now()
		s.streamAdapterCodingPlan(w, r, rid, t0, payload, "messages", modelID, key, func(lines adapters.SSELines) iter_seq_bytes {
			return adapters.ChatSSEToAnthropic(lines.Seq, modelID)
		})
		return
	}
	t0 := time.Now()
	res := s.sendNonStream(r, payload, rid, modelID, key)
	if res.serr != nil {
		s.writeSendError(w, res.serr)
		return
	}
	if res.pseudo != nil {
		s.logQuota(rid, res.pseudo, modelID, "200 伪回复转 429")
		s.pseudoAnthropicHTTP(w, res.pseudo, res.txt)
		return
	}
	if res.chatJSON == nil {
		writeJSON(w, http.StatusBadGateway, adapters.AnthropicErrorBody(
			"api_error", "upstream returned non-JSON body"))
		return
	}
	out := marshalCompact(adapters.ChatJSONToAnthropic(res.chatJSON, modelID))
	s.doneLog(rid, "messages", len(out), t0)
	writeRaw(w, http.StatusOK, "application/json; charset=utf-8", out)
}

// ── 共用：上游分流 / adapter 流转发 / 伪回复 ─────────────────────────────────

// ── P2：选人、换人重试、非流式/流式发送循环 ─────────────────────────────────

// debugAccountHeader 调试指定账号的请求头（仅 API_KEY 配置时生效——开放问题 8）。
const debugAccountHeader = "X-Account-Id"

// sessionHeader 会话粘性显式键（优先级最高）。
const sessionHeader = "X-Session-Id"

// sessionKey 会话粘性键（P3）：
//	X-Session-Id 请求头 → metadata.user_id（Anthropic/Responses）→
//	内容 hash（system 前 64 字符 + 首条 user 消息的 sha256 前 16 hex）。
// chatBody 是翻译后的 Chat 形状（三协议统一从这里取消息）；
// rawBody 是原始请求体（metadata 只在这里有）。返回 "" = 不粘。
func sessionKey(r *http.Request, chatBody, rawBody map[string]any) string {
	if v := strings.TrimSpace(r.Header.Get(sessionHeader)); v != "" {
		return "h:" + v
	}
	if m := asMap(rawBody["metadata"]); m != nil {
		if v := strings.TrimSpace(asString(m["user_id"])); v != "" {
			return "m:" + v
		}
	}
	var sys, firstUser string
	for _, mi := range asList(chatBody["messages"]) {
		m := asMap(mi)
		if m == nil {
			continue
		}
		switch asString(m["role"]) {
		case "system":
			if sys == "" {
				sys = text64(contentText(m["content"]))
			}
		case "user":
			if firstUser == "" {
				firstUser = contentText(m["content"])
			}
		}
	}
	if sys == "" && firstUser == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(sys + "\n" + firstUser))
	return "c:" + hex.EncodeToString(sum[:])[:16]
}

// contentText 取消息文本：string 原样；块数组拼接 text 块（tool_use 等不计）。
func contentText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	var b strings.Builder
	for _, bi := range asList(v) {
		if m := asMap(bi); m != nil && asString(m["type"]) == "text" {
			b.WriteString(asString(m["text"]))
		}
	}
	return b.String()
}

func text64(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

// failoverable SendError 是否值得换人重试（401 刷新失败/429/5xx）。
// 400/403 是请求或权限问题，换人无用，直接回客户端。
func failoverable(status int) bool { return status == 401 || status == 429 || status >= 500 }

// acquireForSend 为一次发送选人。pinned=true 表示 X-Account-Id 指定
// （跳过粘性、不再换人）。粘性只在首次尝试读取（换人重试时旧映射可能正指向
// 失败账号）；成功后的绑定由调用方 BindSticky。
// 失败返回 serr：池耗尽 429（带 Retry-After=最早冷却结束）或指定账号 400/409。
func (s *Server) acquireForSend(r *http.Request, key string, firstAttempt bool) (*pool.Account, bool, *upstream.SendError) {
	if id := r.Header.Get(debugAccountHeader); id != "" && s.currentAPIKey() != "" {
		a, err := s.Pool.AcquireSpecific(id)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, pool.ErrAccountUnavailable) {
				status = http.StatusConflict
			}
			return nil, false, &upstream.SendError{Status: status, Body: openAIErrorBody(
				fmt.Sprintf("X-Account-Id 指定失败: %v", err), "invalid_request_error")}
		}
		return a, true, nil
	}
	var a *pool.Account
	if firstAttempt && key != "" {
		a = s.Pool.AcquireSticky(key)
	} else {
		a = s.Pool.Acquire()
	}
	if a == nil {
		return nil, false, &upstream.SendError{
			Status:     http.StatusTooManyRequests,
			RetryAfter: s.Pool.MinCooldownSeconds(),
			Body: openAIErrorBody(
				"账号池暂无可用账号（全部冷却/失效/禁用中），请稍后重试或到 /admin 检查账号状态",
				"pool_exhausted"),
		}
	}
	return a, false, nil
}

// writeSendError 统一回发送层错误（带 Retry-After，若有）。
func (s *Server) writeSendError(w http.ResponseWriter, serr *upstream.SendError) {
	if serr.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(serr.RetryAfter))
	}
	writeJSON(w, serr.Status, serr.Body)
}

// nonStreamResult sendNonStream 的终局（三者取一：成功 / 伪回复 / 发送错误）。
type nonStreamResult struct {
	content  []byte              // 成功：上游原始正文（已 UnwrapDataLayer）
	chatJSON map[string]any      // 成功：解析后 JSON（responses/messages 转换用）
	txt      string              // choices[0].content（伪回复时是错误文本）
	pseudo   *PseudoResult       // 终局伪回复（所有账号试完仍命中）
	serr     *upstream.SendError // 终局发送错误
}

// sendNonStream 非流式 CodingPlan 发送：换人重试循环（上限 MaxAttempts）。
// 非流式在回客户端前必读完整个 body，天然满足「未写客户端前才换人」。
// 成功时已 RecordSuccess + Release；伪回复/错误终局时已按类记账 + Release。
// key 非空时首次尝试走粘性选人，成功后 BindSticky（失败不覆盖旧映射）。
func (s *Server) sendNonStream(r *http.Request, payload []byte, rid, modelID, key string) *nonStreamResult {
	maxAtt := s.Pool.MaxAttempts()
	var last *nonStreamResult
	for attempt := 0; ; attempt++ {
		acct, pinned, aerr := s.acquireForSend(r, key, attempt == 0)
		if aerr != nil {
			if last != nil {
				return last // 前面已有具体失败：回具体失败比回池耗尽信息量更大
			}
			return &nonStreamResult{serr: aerr}
		}
		resp, serr := s.Up.SendCodingPlan(r.Context(), acct.Cred, payload, rid, modelID)
		if serr != nil {
			s.Pool.OnSendError(acct, serr.Status, errSummary(serr))
			s.Pool.Release(acct)
			last = &nonStreamResult{serr: serr}
			if !pinned && failoverable(serr.Status) && attempt+1 < maxAtt {
				s.Log.Info("换人重试", slog.String("rid", rid),
					slog.Int("status", serr.Status), slog.Int("attempt", attempt+1))
				continue
			}
			return last
		}
		content, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		content = upstream.UnwrapDataLayer(content)
		chatJSON, txt := decodeChatJSON(content)
		if p := DetectPseudoReply(txt); p != nil {
			s.Pool.RecordPseudo(acct, p.Kind, RetryAfterSeconds(p.Reset))
			s.Pool.Release(acct)
			last = &nonStreamResult{pseudo: p, txt: txt}
			if !pinned && attempt+1 < maxAtt {
				s.logQuota(rid, p, modelID, "伪回复，换人重试")
				continue
			}
			return last
		}
		if chatJSON != nil {
			s.Pool.RecordSuccess(acct, asMap(chatJSON["usage"]))
		}
		if !pinned {
			s.Pool.BindSticky(key, acct.ID)
		}
		s.Pool.Release(acct)
		return &nonStreamResult{content: content, chatJSON: chatJSON, txt: txt}
	}
}

// streamAdapterCodingPlan responses/messages 共用的流式发送：选人 + 换人循环，
// 流本体走 streamAdapter（窥探期可整体换人）。key 非空时首次尝试走粘性选人，
// 流正常结束（outDone）后 BindSticky。
func (s *Server) streamAdapterCodingPlan(
	w http.ResponseWriter, r *http.Request, rid string, t0 time.Time,
	payload []byte, kind, modelID, key string,
	build func(adapters.SSELines) iter_seq_bytes,
) {
	maxAtt := s.Pool.MaxAttempts()
	for attempt := 0; ; attempt++ {
		acct, pinned, aerr := s.acquireForSend(r, key, attempt == 0)
		if aerr != nil {
			s.writeSendError(w, aerr)
			return
		}
		resp, serr := s.Up.SendCodingPlan(r.Context(), acct.Cred, payload, rid, modelID)
		if serr != nil {
			s.Pool.OnSendError(acct, serr.Status, errSummary(serr))
			s.Pool.Release(acct)
			if !pinned && failoverable(serr.Status) && attempt+1 < maxAtt {
				s.Log.Info("换人重试", slog.String("rid", rid),
					slog.Int("status", serr.Status), slog.Int("attempt", attempt+1))
				continue
			}
			s.writeSendError(w, serr)
			return
		}
		canFailover := !pinned && attempt+1 < maxAtt
		out := s.streamAdapter(w, r, rid, t0, resp.Body, kind, modelID, acct, canFailover, build)
		resp.Body.Close()
		if out == outDone && !pinned {
			s.Pool.BindSticky(key, acct.ID)
		}
		s.Pool.Release(acct)
		if out == outFailover {
			s.Log.Info("换人重试", slog.String("rid", rid),
				slog.String("reason", "流窥探命中伪回复"), slog.Int("attempt", attempt+1))
			continue
		}
		return
	}
}

// guardOpenRouter 两协议路由的 OpenRouter key 检查（错误体形状由调用方决定）。
// 返回 (denied, message)。
func (s *Server) guardOpenRouter(modelID string) (bool, string) {
	if !config.IsOpenRouterModel(modelID) || s.OrKey != "" {
		return false, ""
	}
	return true, "OpenRouter API key 未配置（在 ~/.atomcode/config.toml 或 OPENROUTER_API_KEY 环境变量）"
}

// iter_seq_bytes adapter 输出帧序列（iter.Seq[[]byte] 的具名别名，便于传参）。
type iter_seq_bytes = func(func([]byte) bool)

// peekMaxLines streamAdapter 窥探的行数上限（ reasoning 先行时首内容可能靠后）。
const peekMaxLines = 128

// streamAdapter 通用 adapter 流转发：上游 body → 行流（带伪回复前置拦截）→
// adapter 帧流 → 客户端。对应 Python chat_lines() + generate()。
// acct 非 nil 时给账号池记账（伪回复拦截/流末 usage）。
//
// canFailover 时先窥探行流前 peekMaxLines 行：首内容行命中伪回复直接返回
// outFailover（一字节未写客户端）；正常则回放缓冲行并继续（拦截解除）。
// canFailover=false 时行为与旧版一致（行流前置拦截，命中注 error 帧）。
func (s *Server) streamAdapter(
	w http.ResponseWriter, r *http.Request, rid string, t0 time.Time,
	upstreamBody io.Reader, kind, modelID string, acct *pool.Account, canFailover bool,
	build func(adapters.SSELines) iter_seq_bytes,
) streamOutcome {
	lines, errRef := sseLineFeed(upstreamBody)
	next, stop := iter.Pull(lines)
	defer stop()

	armed := true // 伪回复前置拦截（首内容行）
	var buf []string
	if canFailover {
		for len(buf) < peekMaxLines {
			line, ok := next()
			if !ok {
				break
			}
			buf = append(buf, line)
			if c := FirstContentLine(line); c != "" {
				if p := DetectPseudoReply(c); p != nil {
					s.Pool.RecordPseudo(acct, p.Kind, RetryAfterSeconds(p.Reset))
					s.logQuota(rid, p, modelID, "窥探命中伪回复（未写客户端）")
					return outFailover
				}
				armed = false // 首内容行已审
			}
		}
	}

	sseHeaders(w)
	flusher, _ := w.(http.Flusher)

	var streamUsage map[string]any
	noteLine := func(line string) {
		if acct == nil {
			return
		}
		if u := usageFromSSELine(line); u != nil {
			streamUsage = u
		}
	}
	// 行流前置拦截：首个内容行命中伪回复就吐一条 SSE error 行并终止行流。
	// Python 用紧凑分隔符 json.dumps(separators=(",",":"))，与 adapter 帧同形。
	filtered := func(yield func(string) bool) {
		intercept := armed
		for _, line := range buf { // 回放窥探缓冲（已逐行审过或本来就无内容）
			noteLine(line)
			if !yield(line) {
				return
			}
		}
		for {
			line, ok := next()
			if !ok {
				return
			}
			noteLine(line)
			if intercept {
				if c := FirstContentLine(line); c != "" {
					if p := DetectPseudoReply(c); p != nil {
						s.Pool.RecordPseudo(acct, p.Kind, RetryAfterSeconds(p.Reset))
						s.logQuota(rid, p, modelID, "流内伪回复替换为 SSE error")
						frame := marshalCompact(map[string]any{"error": ssePseudoErrFields(p, c)})
						if !yield("data: " + string(frame)) {
							return
						}
						return
					}
					intercept = false
				}
			}
			if !yield(line) {
				return
			}
		}
	}

	total := 0
	for frame := range build(adapters.SSELines{Seq: filtered, Err: errRef}) {
		if err := r.Context().Err(); err != nil {
			s.logDisconnect(rid, kind, total, t0)
			return outClosed
		}
		if _, werr := w.Write(frame); werr != nil {
			s.logDisconnect(rid, kind, total, t0)
			return outClosed
		}
		total += len(frame)
		if flusher != nil {
			flusher.Flush()
		}
	}
	// 上游行流读取报错（非 EOF）：Python 版由 generate() 的 except Exception 记
	// 「流中断」；adapter 已尽力收尾，这里只补日志，不再改已发内容。
	if err := errRef(); err != nil {
		s.Log.Error("流中断", slog.String("rid", rid), slog.String("err", err.Error()),
			slog.String("line", fmt.Sprintf("%s %dB %.1fs", kind, total, time.Since(t0).Seconds())))
		return outClosed
	}
	if streamUsage != nil {
		s.Pool.RecordSuccess(acct, streamUsage)
	}
	s.doneLog(rid, kind, total, t0)
	return outDone
}

// errSummary 从 SendError 提取一行错误摘要（给账号池 LastError 用）。
func errSummary(serr *upstream.SendError) string {
	if serr == nil {
		return ""
	}
	if m := asMap(serr.Body["error"]); m != nil {
		if msg := asString(m["message"]); msg != "" {
			const maxLen = 200
			if len(msg) > maxLen {
				return msg[:maxLen] + "…"
			}
			return msg
		}
	}
	return fmt.Sprintf("HTTP %d", serr.Status)
}

// ssePseudoErrFields 伪回复 → 流内 error 帧字段（含 retry_after，与 Python 一致）。
func ssePseudoErrFields(p *PseudoResult, message string) map[string]any {
	return map[string]any{
		"message":     message,
		"type":        ErrTypeForKind(p.Kind),
		"code":        p.Kind,
		"reset_at":    nullable(p.Reset),
		"retry_after": nullableSec(RetryAfterSeconds(p.Reset)),
	}
}

// pseudoOpenAIHTTP 非流式伪回复 → 429（chat/responses 的 OpenAI 错误体 + Retry-After）。
func (s *Server) pseudoOpenAIHTTP(w http.ResponseWriter, p *PseudoResult, message string) {
	if sec := RetryAfterSeconds(p.Reset); sec > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(sec))
	}
	writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": map[string]any{
		"message":  message,
		"type":     ErrTypeForKind(p.Kind),
		"code":     p.Kind,
		"reset_at": nullable(p.Reset),
	}})
}

// pseudoAnthropicHTTP 非流式伪回复 → 429（Anthropic 错误体只有 type/message）。
func (s *Server) pseudoAnthropicHTTP(w http.ResponseWriter, p *PseudoResult, message string) {
	if sec := RetryAfterSeconds(p.Reset); sec > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(sec))
	}
	writeJSON(w, http.StatusTooManyRequests,
		adapters.AnthropicErrorBody(ErrTypeForKind(p.Kind), message))
}

// logQuota 伪回复命中日志（Python: "[%s] quota(%s) model=%s reset=%s —— %s"）。
func (s *Server) logQuota(rid string, p *PseudoResult, modelID, what string) {
	s.Log.Warn("quota", slog.String("rid", rid),
		slog.String("line", fmt.Sprintf("quota(%s) model=%s reset=%s —— %s",
			p.Kind, orQ(modelID), orQ(p.Reset), what)))
}

// ── 小工具 ───────────────────────────────────────────────────────────────────

// mergeBody 浅合并（对应 Python dict(body, **extra)：extra 覆盖同名键）。
func mergeBody(base map[string]any, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func joinAll(parts []string) string {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	b := make([]byte, 0, n)
	for _, p := range parts {
		b = append(b, p...)
	}
	return string(b)
}

func fmtTTFT(d time.Duration, ok bool) string {
	if !ok {
		return "-"
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func orQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

// nullable 空串 → JSON null（Python 的 reset=None 直接进错误体）。
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableSec 0 → JSON null（Python _retry_after_seconds(None) → None）。
func nullableSec(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

// marshalSpaced Python json.dumps 默认分隔符（", " / ": "）形态，
// 用于 chat 路由流内 error 帧（那处 Python 未指定 separators）。
func marshalSpaced(v any) []byte {
	b := marshalCompact(v)
	var out []byte
	inString := false
	escaped := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
			out = append(out, c)
		case ',':
			out = append(append(out, c), ' ')
		case ':':
			out = append(append(out, c), ' ')
		default:
			out = append(out, c)
		}
	}
	return out
}

// usageFromSSELine 取一行 SSE data 里的 usage（无则 nil）。
func usageFromSSELine(line string) map[string]any {
	d := ssePayload(line)
	if d == nil {
		return nil
	}
	return asMap(d["usage"])
}

// ssePayload 解析 "data: {...}" 行为对象；非 data 行 / [DONE] / 解析失败返回 nil。
func ssePayload(line string) map[string]any {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, "data:") {
		return nil
	}
	payload := strings.TrimSpace(s[len("data:"):])
	if payload == "" || payload == "[DONE]" {
		return nil
	}
	var d map[string]any
	if json.Unmarshal([]byte(payload), &d) != nil {
		return nil
	}
	return d
}
