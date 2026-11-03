// 面板登录保护（P5）：PBKDF2 密码哈希 + HMAC 签名会话 cookie + 登录限速。
//
// 防死锁设计（本文件的第一优先级）：
//   - 未设密码 = 面板全开（现状）；设密码的入口在面板里，首次设置无需登录
//   - 忘记密码的主恢复路径：POST /admin/api/password/reset（仅回环，无需会话）
//     冗余路径：删 settings.json 的 panel_password 字段（或整文件）重启
//   - /admin/api/auth*（API_KEY 自救通道）不吃面板密码——两条自救链互相独立，
//     任一被忘都能从另一条解开
//   - 登录限速是「同 IP 连败 5 次锁 60s」，自动恢复，绝不永久封禁
package handler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── 密码哈希：PBKDF2-HMAC-SHA256（零依赖，标准库）─────────────────────────────
//
// 参数：210k 迭代（OWASP 2023 对 PBKDF2-SHA256 的推荐量级）+ 16 字节随机盐。
// 存储格式：pbkdf2$<iter>$<salt hex>$<hash hex>。比较走常量时间。

const (
	pbkdf2Iter     = 210000
	pbkdf2SaltLen  = 16
	pbkdf2KeyLen   = 32
	minPasswordLen = 8
)

// pbkdf2SHA256 标准 PBKDF2：DK = T1 || T2 ...，本实现只取单块（32B 输出恰好一块）。
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	dk := make([]byte, 0, keyLen)
	for block := 1; len(dk) < keyLen; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// hashPassword 生成存储串（新随机盐）。
func hashPassword(password string) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2SHA256([]byte(password), salt, pbkdf2Iter, pbkdf2KeyLen)
	return fmt.Sprintf("pbkdf2$%d$%s$%s", pbkdf2Iter, hex.EncodeToString(salt), hex.EncodeToString(dk)), nil
}

// verifyPassword 常量时间校验；格式坏/密码错都返回 false。
func verifyPassword(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// validatePassword 强度下限：非空白、>=8 位。
func validatePassword(pw string) error {
	if strings.TrimSpace(pw) == "" {
		return errors.New("密码不能为空白")
	}
	if len(pw) < minPasswordLen {
		return fmt.Errorf("密码至少 %d 位", minPasswordLen)
	}
	return nil
}

// ── 会话：HMAC 签名 cookie ────────────────────────────────────────────────────
//
// cookie 值："<expiry_unix>|<nonce hex>|<hmac hex>"，HMAC = HMAC-SHA256(
// sessionSecret, "expiry|nonce")。密钥存 settings.json（0600）——进程重启
// 会话不失效；删 settings.json（忘记密码的恢复路径之一）连带密钥失效，
// 旧会话自然作废，语义自洽。有效期 12h：本地管理面板的便利与暴露面平衡点。
// Cookie 属性：HttpOnly + SameSite=Lax + Path=/admin。

const (
	sessionCookieName = "ac2api_admin"
	sessionTTL        = 12 * time.Hour
)

// sessionSecret 取会话密钥（懒生成并落盘）。
func (s *Server) sessionSecret() []byte {
	if s.settings.SessionSecret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err == nil {
			s.settings.SessionSecret = hex.EncodeToString(b)
			_ = s.settings.save(s.Cfg.StateDir) // 尽力而为；失败则本次进程内有效
		}
	}
	raw, _ := hex.DecodeString(s.settings.SessionSecret)
	return raw
}

// sessionScope 会话绑定域：密码哈希末尾 8 字符（哈希 hex 尾，随盐+密码变化；
// 不能用头部——那是 "pbkdf2$" 格式常量）。改密/清除密码 → 所有旧会话失效
// （无状态 cookie 的服务端吊销语义）；登出仅丢弃当前 cookie（客户端语义）。
func (s *Server) sessionScope() string {
	h := s.settings.PanelPasswordHash
	if len(h) > 8 {
		return h[len(h)-8:]
	}
	return h
}

// validSession 校验请求里的会话 cookie。
func (s *Server) validSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	parts := strings.Split(c.Value, "|")
	if len(parts) != 3 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	mac := hmac.New(sha256.New, s.sessionSecret())
	_, _ = mac.Write([]byte(parts[0] + "|" + parts[1] + "|" + s.sessionScope()))
	want := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(want), []byte(parts[2])) == 1
}

// issueSession 签发会话 cookie。
func (s *Server) issueSession(w http.ResponseWriter) {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	exp := time.Now().Add(sessionTTL).Unix()
	expStr := strconv.FormatInt(exp, 10)
	mac := hmac.New(sha256.New, s.sessionSecret())
	_, _ = mac.Write([]byte(expStr + "|" + hex.EncodeToString(nonce) + "|" + s.sessionScope()))
	sig := hex.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    fmt.Sprintf("%s|%s|%s", expStr, hex.EncodeToString(nonce), sig),
		Path:     "/admin",
		Expires:  time.Unix(exp, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSession 登出：立即过期 cookie。
func (s *Server) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/admin",
		MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// ── 登录限速：同 IP 连败 5 次锁 60s（内存态，自动恢复，无永久封禁）──────────

type loginRateState struct {
	fails       int
	firstFail   time.Time
	lockedUntil time.Time
}

type loginRateLimiter struct {
	mu     sync.Mutex
	m      map[string]*loginRateState
	window time.Duration // 失败计数窗口（10min）
	max    int           // 窗口内连败上限（5）
	lock   time.Duration // 锁定时长（60s）
	now    func() time.Time
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{m: map[string]*loginRateState{}, window: 10 * time.Minute, max: 5, lock: 60 * time.Second, now: time.Now}
}

// check 登录前检查：锁定中返回剩余秒数（>0）。
func (l *loginRateLimiter) check(ip string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.m[ip]
	if st == nil {
		return 0
	}
	if d := st.lockedUntil.Sub(l.now()); d > 0 {
		return int(d.Seconds()) + 1
	}
	return 0
}

// fail 记一次失败（连败超阈值 → 锁 60s）。
func (l *loginRateLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.m[ip]
	if st == nil || l.now().Sub(st.firstFail) > l.window {
		st = &loginRateState{firstFail: l.now()}
		l.m[ip] = st
	}
	st.fails++
	if st.fails >= l.max {
		st.lockedUntil = l.now().Add(l.lock)
		st.fails = 0 // 锁后重新计数
	}
}

// ok 登录成功清零。
func (l *loginRateLimiter) ok(ip string) {
	l.mu.Lock()
	delete(l.m, ip)
	l.mu.Unlock()
}

// ── 路由与闸门 ────────────────────────────────────────────────────────────────

// panelOpenPaths 面板登录闸门的豁免路径：登录/登出/密码管理/密码重置/API_KEY 自救。
var panelOpenPaths = map[string]bool{
	"/admin/api/login":          true,
	"/admin/api/logout":         true,
	"/admin/api/password":       true,
	"/admin/api/password/reset": true,
	"/admin/api/auth":           true,
	"/admin/api/auth/disable":   true,
}

// panelGate /admin 与 /admin/api/* 的会话闸门（Handler 最外层）。
// 未设密码 → 直通（现状）；未登录 GET /admin → 登录页（200，不是 401 空白）；
// 未登录 /admin/api/* → 401 JSON。
func (s *Server) panelGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if (p != "/admin" && !strings.HasPrefix(p, "/admin/api/")) || panelOpenPaths[p] {
			next.ServeHTTP(w, r)
			return
		}
		if s.settings.PanelPasswordHash == "" || s.validSession(r) {
			next.ServeHTTP(w, r)
			return
		}
		if p == "/admin" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(loginPageHTML))
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "需要登录", "login": "/admin"})
	})
}

// panelLogin POST /admin/api/login {"password"}：限速 + 校验 + 发会话。
func (s *Server) panelLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if sec := s.loginRate.check(ip); sec > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(sec))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"ok": false, "error": fmt.Sprintf("失败次数过多，%d 秒后重试", sec)})
		return
	}
	body, _, ok := readJSONBody(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "需要 JSON 请求体"})
		return
	}
	if s.settings.PanelPasswordHash == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "未设置面板密码"})
		return
	}
	if !verifyPassword(asString(body["password"]), s.settings.PanelPasswordHash) {
		s.loginRate.fail(ip)
		time.Sleep(300 * time.Millisecond) // 失败定速，减缓爆破
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "密码错误"})
		return
	}
	s.loginRate.ok(ip)
	s.issueSession(w)
	s.Log.Info("面板登录成功", "ip", ip)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// panelLogout POST /admin/api/logout。
func (s *Server) panelLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// panelPassword POST /admin/api/password：设置/修改/清除面板密码。
//   - 未设密码：{"new_password"} 直接设置（首次设置无需登录——防死锁）
//   - 已设密码：需有效会话；修改要 {"current_password","new_password"}，
//     清除要 {"clear":true}
func (s *Server) panelPassword(w http.ResponseWriter, r *http.Request) {
	body, _, ok := readJSONBody(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "需要 JSON 请求体"})
		return
	}
	hasPassword := s.settings.PanelPasswordHash != ""
	if hasPassword {
		if !s.validSession(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "需要登录"})
			return
		}
		if truthy(body["clear"]) {
			s.settings.PanelPasswordHash = ""
			if err := s.settings.save(s.Cfg.StateDir); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			s.clearSession(w)
			s.Log.Warn("面板密码已清除（恢复无密码访问）")
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "password_set": false})
			return
		}
		if !verifyPassword(asString(body["current_password"]), s.settings.PanelPasswordHash) {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "当前密码错误"})
			return
		}
	}
	newPw := asString(body["new_password"])
	if err := validatePassword(newPw); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	hash, err := hashPassword(newPw)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.settings.PanelPasswordHash = hash
	if err := s.settings.save(s.Cfg.StateDir); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.issueSession(w) // 设置/修改后直接保持登录态
	s.Log.Info("面板密码已更新")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "password_set": true})
}

// panelPasswordReset POST /admin/api/password/reset：忘记密码的恢复主路径。
// 仅回环、无需会话——与「本机可直接改 settings.json」等权，不制造虚假安全。
func (s *Server) panelPasswordReset(w http.ResponseWriter, r *http.Request) {
	if !s.loopbackOnly(w, r) {
		return
	}
	s.settings.PanelPasswordHash = ""
	if err := s.settings.save(s.Cfg.StateDir); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.Log.Warn("面板密码已通过回环重置接口清除")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "password_set": false,
		"message": "面板密码已清除，恢复无密码访问"})
}

// clientIP 取客户端 IP（限速键）。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ── 登录页（独立极简页，不套用面板布局，绝无循环重定向）──────────────────────

const loginPageHTML = `<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>登录 — AtomCode2api</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f1115;color:#e6e9ef;font:14px/1.6 "Segoe UI",system-ui,sans-serif}
.card{background:#181b22;border:1px solid #262b36;border-radius:10px;padding:28px;width:320px}
h1{font-size:17px;margin:0 0 16px}
input{width:100%;box-sizing:border-box;background:#0d0f13;border:1px solid #262b36;border-radius:6px;color:#e6e9ef;padding:9px 12px;font-size:14px}
button{width:100%;margin-top:12px;background:#6ea8fe;border:none;border-radius:6px;color:#0b1220;padding:9px;font-size:14px;font-weight:600;cursor:pointer}
.err{color:#f87171;font-size:12px;min-height:16px;margin-top:8px}
</style></head><body>
<div class="card"><h1>AtomCode2api 控制台</h1>
<input id="pw" type="password" placeholder="面板密码" autofocus
  onkeydown="if(event.key==='Enter')go()">
<button onclick="go()">登录</button>
<div class="err" id="err"></div></div>
<script>
async function go(){
  const r=await fetch("/admin/api/login",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({password:document.getElementById("pw").value})});
  const j=await r.json().catch(()=>({}));
  if(r.ok&&j.ok){location.href="/admin";return}
  document.getElementById("err").textContent=j.error||("HTTP "+r.status);
}
</script></body></html>`
