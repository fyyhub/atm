// Package upstream 对应 Python 版 server.py 的 _send_codingplan / _send_openrouter：
// 双上游发送分支与退避重试。
//
// 关键约束：数据面 UA 绝不能是 atomcode/* —— 那是 UA 门的开关
// （docs/atomcode-03-数据面与UA门.md：api-ai.gitcode.com + atomcode/* → 403；
// 中性 UA → 200 免签名）。lanes.Credential.Headers() 已带中性 UA。
package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"atomcode2api/internal/config"
)

// SendError 对应 Python _send_* 返回的 err=(jsonify, status)：路由层直接回给客户端。
type SendError struct {
	Status int
	Body   map[string]any // {"error": {"message":..., "type":...}}
	// RetryAfter 秒（>0 时路由层设 Retry-After 头；目前仅账号池耗尽使用）。
	RetryAfter int
}

// Cred 上游凭据来源（*lanes.Credential 实现）。每次发送现取 Headers()——
// 刷新后拿到的是新 token。
type Cred interface {
	Headers() http.Header
	Refresh() error
}

// Client 双通道上游。Base 可注入 httptest 假上游。
type Client struct {
	CodingPlanBase string // https://api-ai.gitcode.com/v1
	OpenRouterBase string // https://openrouter.ai/api/v1
	OpenRouterKey  string
	HTTP           *http.Client

	// Backoff 重试等待表（默认 0.5/1/2s）；测试置为极短值以免拖慢用例。
	// 长度不足时按最后一个元素取值。
	Backoff []time.Duration
	// Sleep 退避等待函数（默认 time.Sleep，测试可注入计数）。
	Sleep func(time.Duration)
}

func New() *Client {
	return &Client{
		CodingPlanBase: config.LLMBase,
		OpenRouterBase: config.OpenRouterBase,
		HTTP:           newHTTPClient(),
	}
}

// defaultBackoff Python: wait = 0.5 * (2 ** attempt)，attempt = 0/1/2
var defaultBackoff = []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}

func (c *Client) backoff(attempt int) time.Duration {
	table := c.Backoff
	if len(table) == 0 {
		table = defaultBackoff
	}
	if attempt >= len(table) {
		return table[len(table)-1]
	}
	return table[attempt]
}

func (c *Client) sleep(d time.Duration) {
	if c.Sleep != nil {
		c.Sleep(d)
		return
	}
	time.Sleep(d)
}

// newHTTPClient 对齐 requests 的 timeout=120 语义：它是「单次 socket 读」超时，
// 不是整请求总时限——长流式回答不会因总时长被掐。Go 的 http.Client.Timeout 是
// 全局时限，直接用会把 >120s 的正常 agent 长流切掉，故改用 Transport 层：
//   - 拨号 30s、响应头 120s（覆盖「上游请求超时(120s)」的主场景：连上但迟迟不回头）
//   - 连接建立后的空闲由 idleTimeoutConn 每次 Read 续 120s 期限
func newHTTPClient() *http.Client {
	tr := &http.Transport{
		DialContext:           dialIdle(120 * time.Second),
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 120 * time.Second,
		MaxIdleConnsPerHost:   16,
	}
	return &http.Client{Transport: tr}
}

// dialIdle 包一层 net.Conn：每次 Read 前续一个空闲期限，读成功后不等待时长上限
// （即「120 秒无任何字节 = timeout」，与 requests 行为一致）。
func dialIdle(idle time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	base := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := base.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &idleTimeoutConn{Conn: conn, idle: idle}, nil
	}
}

type idleTimeoutConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleTimeoutConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		// 归一化成 net.Error 超时形态，上层 isTimeout 判定走 504 分支
		return n, timeoutError{}
	}
	return n, err
}

func (c *idleTimeoutConn) Write(p []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "connection timed out (idle 120s)" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// retryStatuses 瞬时错误退避重试集合：上游 LiteLLM 偶发 502/503（客户端表现为
// 「请求负载过高」），网关层重试吃掉。403 是 UA 门/权限错不重试；401 只刷新一次。
var retryStatuses = map[int]bool{429: true, 500: true, 502: true, 503: true, 504: true}

// SendCodingPlan POST <base>/chat/completions：瞬时错误退避重试（0.5/1/2s 共 1+3 次）
// + 401 刷新重试一次。成功返回 resp（调用方负责关闭 Body）；失败返回 SendError。
// 对应 Python _send_codingplan。
func (c *Client) SendCodingPlan(ctx context.Context, cred Cred, payload []byte, rid, model string) (*http.Response, *SendError) {
	url := c.CodingPlanBase + "/chat/completions"

	var resp *http.Response
	var err error
	refreshed := false
	for attempt := 0; attempt < 4; attempt++ {
		resp, err = c.postOnce(ctx, url, cred.Headers(), payload)
		if err != nil {
			if isTimeout(err) {
				slog.Error("上游超时 (120s)", slog.String("rid", rid), slog.String("model", model),
					slog.Int("attempt", attempt+1))
				return nil, &SendError{Status: 504, Body: openAIError(
					"上游请求超时 (120s)，模型响应过慢或服务繁忙", "upstream_error")}
			}
			slog.Error("上游连接失败", slog.String("rid", rid), slog.String("err", err.Error()),
				slog.Int("attempt", attempt+1))
			return nil, &SendError{Status: 502, Body: openAIError(
				fmt.Sprintf("上游连接失败: %v", err), "upstream_error")}
		}
		if resp.StatusCode == http.StatusUnauthorized && !refreshed {
			refreshed = true
			resp.Body.Close()
			slog.Warn("上游 401，刷新 token 重试", slog.String("rid", rid))
			if rerr := cred.Refresh(); rerr != nil {
				slog.Error("token 刷新失败", slog.String("err", rerr.Error()))
				return nil, &SendError{Status: 401, Body: openAIError(
					fmt.Sprintf("token 刷新失败: %v", rerr), "auth_error")}
			}
			continue
		}
		if retryStatuses[resp.StatusCode] && attempt < 3 {
			// 退避 0.5/1/2s（Python: wait = 0.5 * (2 ** attempt)）
			wait := c.backoff(attempt)
			slog.Warn("上游可重试状态码", slog.String("rid", rid), slog.Int("status", resp.StatusCode),
				slog.Int("attempt", attempt+1), slog.Duration("wait", wait), slog.String("model", model))
			resp.Body.Close()
			select {
			case <-ctx.Done():
				return nil, &SendError{Status: 502, Body: openAIError("请求已取消: "+ctx.Err().Error(), "upstream_error")}
			default:
			}
			c.sleep(wait)
			continue
		}
		break
	}

	if resp.StatusCode != http.StatusOK {
		errText := readTruncated(resp.Body, 1000)
		resp.Body.Close()
		slog.Error("上游非 200", slog.String("rid", rid), slog.Int("status", resp.StatusCode),
			slog.String("model", model), slog.String("err", errText))
		return nil, &SendError{Status: resp.StatusCode, Body: openAIError(
			fmt.Sprintf("上游错误 (HTTP %d): %s", resp.StatusCode, errText), "upstream_error")}
	}
	return resp, nil
}

// SendOpenRouter POST <base>/chat/completions（OpenRouter 免费模型分支，单次请求）。
// 对应 Python _send_openrouter。HTTP-Referer/X-Title 是 OpenRouter 官方 CLI 同款
// app-attribution 头（openai_compat.rs: OPENROUTER_ATTRIBUTION_HEADERS）：
// 免费模型有 agentic harness 门，缺这两个头会被 403。
func (c *Client) SendOpenRouter(ctx context.Context, payload []byte, rid string) (*http.Response, *SendError) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+c.OpenRouterKey)
	h.Set("Content-Type", "application/json")
	h.Set("User-Agent", config.UpstreamUA)
	h.Set("HTTP-Referer", "https://gitcode.com/atomgit_atomcode/atomcode")
	h.Set("X-Title", "AtomCode")

	resp, err := c.postOnce(ctx, c.OpenRouterBase+"/chat/completions", h, payload)
	if err != nil {
		if isTimeout(err) {
			slog.Error("OpenRouter 超时 (120s)", slog.String("rid", rid), slog.String("model", modelOf(payload)))
			return nil, &SendError{Status: 504, Body: openAIError("OpenRouter 上游请求超时 (120s)", "upstream_error")}
		}
		slog.Error("OpenRouter 连接失败", slog.String("rid", rid), slog.String("err", err.Error()))
		return nil, &SendError{Status: 502, Body: openAIError(
			fmt.Sprintf("OpenRouter 上游连接失败: %v", err), "upstream_error")}
	}
	if resp.StatusCode != http.StatusOK {
		errText := readTruncated(resp.Body, 1000)
		resp.Body.Close()
		slog.Error("OpenRouter 非 200", slog.String("rid", rid), slog.Int("status", resp.StatusCode),
			slog.String("model", modelOf(payload)), slog.String("err", errText))
		return nil, &SendError{Status: resp.StatusCode, Body: openAIError(
			fmt.Sprintf("OpenRouter 错误 (HTTP %d): %s", resp.StatusCode, errText), "upstream_error")}
	}
	return resp, nil
}

func (c *Client) postOnce(ctx context.Context, url string, h http.Header, payload []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header = h
	return c.HTTP.Do(req)
}

func openAIError(message, typ string) map[string]any {
	return map[string]any{"error": map[string]any{"message": message, "type": typ}}
}

// readTruncated 读 body 前 n 字节（对应 resp.text[:1000]）。
func readTruncated(r io.Reader, n int) string {
	limited := io.LimitReader(r, int64(n))
	raw, _ := io.ReadAll(limited)
	return strings.ToValidUTF8(string(raw), "")
}

// modelOf 从请求体取 model 仅用于日志；解析失败返回空串。
func modelOf(payload []byte) string {
	var m struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(payload, &m) != nil {
		return ""
	}
	return m.Model
}
