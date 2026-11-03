// P4 面板 API 密钥管理测试：设置/读取/清除、优先级、掩码、生成、热更新、容错、回环闸门。
package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// 持久化：写读回环 + 缺失/损坏容错。
func TestSettings_PersistAndFaults(t *testing.T) {
	dir := t.TempDir()
	// 缺失 → 零值
	s := loadSettings(dir, nil)
	if s.APIKey != "" || s.AuthDisabled {
		t.Fatal("缺失文件应为零值")
	}
	// 写读回环
	s.APIKey = "sk-panel-1234"
	s.AuthDisabled = true
	if err := s.save(dir); err != nil {
		t.Fatal(err)
	}
	s2 := loadSettings(dir, nil)
	if s2.APIKey != "sk-panel-1234" || !s2.AuthDisabled {
		t.Fatalf("回读失败: %+v", s2)
	}
	// 权限 0600（Windows 上 os.WriteFile 的 perm 是建议性的，跳过断言）
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(dir, "settings.json"))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("权限=%o 期望 600", fi.Mode().Perm())
		}
	}
	// 损坏 → 零值 + 告警回调
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	warned := false
	s3 := loadSettings(dir, func(string) { warned = true })
	if s3.APIKey != "" || !warned {
		t.Fatal("损坏应按空设置继续并告警")
	}
}

// 优先级：面板 > env > 未启用；auth_disabled 压过 env。
func TestAuthPriority(t *testing.T) {
	up := &authSwitch{decide: func(string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)
	s.Cfg.APIKey = "sk-env-key"
	s.recomputeAuth()
	if s.currentAPIKey() != "sk-env-key" || s.authSourceLabel() != "环境变量" {
		t.Fatal("env 应生效")
	}
	s.settings.APIKey = "sk-panel-key"
	s.recomputeAuth()
	if s.currentAPIKey() != "sk-panel-key" || s.authSourceLabel() != "面板" {
		t.Fatal("面板应压过 env")
	}
	s.settings.APIKey = ""
	s.settings.AuthDisabled = true
	s.recomputeAuth()
	if s.currentAPIKey() != "" || s.authSourceLabel() != "已禁用（面板关闭）" {
		t.Fatal("禁用应压过 env")
	}
	s.settings.AuthDisabled = false
	s.recomputeAuth()
	if s.currentAPIKey() != "sk-env-key" {
		t.Fatal("取消禁用应回落 env")
	}
}

// 校验/掩码/生成格式。
func TestKeyValidateMaskGen(t *testing.T) {
	for _, bad := range []string{"", "   ", "short", "has space here", "带中文的密钥key"} {
		if err := validateAPIKey(bad); err == nil {
			t.Fatalf("%q 应被拒绝", bad)
		}
	}
	if err := validateAPIKey("sk-good-key-123"); err != nil {
		t.Fatal(err)
	}
	if m := maskKey("sk-abcd1234efgh"); m != "sk-a…efgh" {
		t.Fatalf("掩码=%q", m)
	}
	if m := maskKey("short12"); m != "••••••••" {
		t.Fatalf("短钥应全掩，得 %q", m)
	}
	k1, k2 := genAPIKey(), genAPIKey()
	if len(k1) != 32 || k1 == k2 {
		t.Fatal("生成应为 32 位且不重复")
	}
	for _, c := range k1 {
		if !strings.ContainsRune(genKeyAlphabet, c) {
			t.Fatalf("生成字符越界: %c", c)
		}
	}
}

// 热更新端到端：设置 → 无钥 401/带钥 200 → 清除回落 → 禁用全开。
func TestAuthHotUpdate_EndToEnd(t *testing.T) {
	up := &authSwitch{decide: func(string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up) // env 无 key

	authReq := func(key string) *httptest.ResponseRecorder {
		// 用 /v1/chat/completions 做闸门探测（假上游对 CodingPlan 返回正常 JSON）
		body := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:9999"
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}
	post := func(path string, body any, remote, key string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
		req.RemoteAddr = remote
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}

	// 初始：未启用，放行
	if r := authReq(""); r.Code != 200 {
		t.Fatalf("初始应放行，得 %d", r.Code)
	}
	// 设置密钥 → 立即生效
	r := post("/admin/api/auth", map[string]any{"api_key": "sk-live-test-1"}, "127.0.0.1:9999", "")
	if r.Code != 200 {
		t.Fatalf("设置失败: %d %s", r.Code, r.Body.String())
	}
	if r := authReq(""); r.Code != 401 {
		t.Fatalf("设置后无钥应 401，得 %d", r.Code)
	}
	if r := authReq("sk-live-test-1"); r.Code != 200 {
		t.Fatalf("带正确密钥应 200，得 %d", r.Code)
	}
	if r := authReq("wrong-key-000"); r.Code != 401 {
		t.Fatalf("错误密钥应 401，得 %d", r.Code)
	}
	// 视图来源正确（鉴权后需带密钥）
	greq := httptest.NewRequest(http.MethodGet, "/admin/api/auth", nil)
	greq.RemoteAddr = "127.0.0.1:9999"
	greq.Header.Set("Authorization", "Bearer sk-live-test-1")
	gw := httptest.NewRecorder()
	s.Handler().ServeHTTP(gw, greq)
	var view map[string]any
	_ = json.Unmarshal(gw.Body.Bytes(), &view)
	if view["source"] != "面板" || view["masked_key"] != "sk-l…st-1" {
		t.Fatalf("视图=%v", view)
	}
	// 清除面板值 → 回落（env 无 → 未启用）
	post("/admin/api/auth", map[string]any{"api_key": ""}, "127.0.0.1:9999", "sk-live-test-1")
	if r := authReq(""); r.Code != 200 {
		t.Fatalf("清除后应回落未启用，得 %d", r.Code)
	}
	// env 有值时清除 → 回落 env
	s.Cfg.APIKey = "sk-env-fallback"
	s.recomputeAuth()
	post("/admin/api/auth", map[string]any{"api_key": "sk-panel-x9"}, "127.0.0.1:9999", "sk-env-fallback")
	post("/admin/api/auth", map[string]any{"api_key": ""}, "127.0.0.1:9999", "sk-panel-x9")
	if r := authReq("sk-env-fallback"); r.Code != 200 {
		t.Fatalf("清除后应回落 env，得 %d", r.Code)
	}
	// 禁用鉴权 → env 也失效
	post("/admin/api/auth/disable", map[string]any{"disable": true}, "127.0.0.1:9999", "sk-env-fallback")
	if r := authReq(""); r.Code != 200 {
		t.Fatalf("禁用后应全开，得 %d", r.Code)
	}
	post("/admin/api/auth/disable", map[string]any{"disable": false}, "127.0.0.1:9999", "")
	if r := authReq(""); r.Code != 401 {
		t.Fatalf("恢复后应重新鉴权，得 %d", r.Code)
	}
	// 回环闸门：非回环写 → 403
	if r := post("/admin/api/auth", map[string]any{"api_key": "sk-remote-hack"}, "10.0.0.5:1234", "sk-env-fallback"); r.Code != 403 {
		t.Fatalf("非回环写应 403，得 %d", r.Code)
	}
}

// 防锁死（事故回归）：密钥生效后 /admin 页面、auth 读/写（回环）必须可达；
// 生成不自动启用；面板可清除密钥自救。
func TestAuthNoLockout(t *testing.T) {
	up := &authSwitch{decide: func(string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)
	s.settings.APIKey = "sk-lock-test"
	s.recomputeAuth()

	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:9999"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}
	post := func(path string, body any, remote string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}

	// 数据面已锁
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`
	dreq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	dreq.RemoteAddr = "127.0.0.1:9999"
	dw := httptest.NewRecorder()
	s.Handler().ServeHTTP(dw, dreq)
	if dw.Code != 401 {
		t.Fatalf("数据面无钥应 401，得 %d", dw.Code)
	}
	// 面板与 auth 端点不挂 API_KEY 闸门（锁死自救通道）
	if r := get("/admin"); r.Code != 200 {
		t.Fatalf("/admin 应始终可开，得 %d", r.Code)
	}
	if r := get("/admin/api/auth"); r.Code != 200 {
		t.Fatalf("auth 读应无钥可达，得 %d", r.Code)
	}
	// 生成只回传不落盘不启用
	r := post("/admin/api/auth", map[string]any{"generate": true}, "127.0.0.1:9999")
	var gres map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &gres)
	if gres["generated_key"] == nil || gres["generated_key"] == "" {
		t.Fatal("应返回生成密钥")
	}
	if s.currentAPIKey() != "sk-lock-test" {
		t.Fatal("生成不应改变当前密钥")
	}
	// 无钥回环清除 → 自救成功
	if r := post("/admin/api/auth", map[string]any{"api_key": ""}, "127.0.0.1:9999"); r.Code != 200 {
		t.Fatalf("无钥回环清除应 200，得 %d", r.Code)
	}
	if s.currentAPIKey() != "" {
		t.Fatal("清除后应无鉴权")
	}
	// 恢复设置后，非回环写仍被挡
	s.settings.APIKey = "sk-lock-test"
	s.recomputeAuth()
	if r := post("/admin/api/auth", map[string]any{"api_key": ""}, "10.9.9.9:80"); r.Code != 403 {
		t.Fatalf("非回环清除应 403，得 %d", r.Code)
	}
	if s.currentAPIKey() != "sk-lock-test" {
		t.Fatal("非回环清除不应生效")
	}
}

// 重启持久化：settings.json 重载后设置仍在。
func TestAuth_RestartPersist(t *testing.T) {
	up := &authSwitch{decide: func(string) (int, []byte) { return 200, chatJSONBytes }}
	s := newPoolFixture(t, up)
	s.settings.APIKey = "sk-persist-1"
	if err := s.settings.save(s.Cfg.StateDir); err != nil {
		t.Fatal(err)
	}
	// 同 StateDir 重建 Server（模拟重启）
	s2 := New(s.Cfg, nil, s.Log)
	if s2.currentAPIKey() != "sk-persist-1" || s2.authSourceLabel() != "面板" {
		t.Fatal("重启后面板密钥应继续生效")
	}
}
