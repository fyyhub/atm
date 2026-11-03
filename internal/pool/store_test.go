// 落盘、迁移、pool-state 损坏重建、快照回读的单元测试。
package pool

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newStorePool(t *testing.T, dir string) *Pool {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(dir, nil, logger)
}

func writeLegacyTOML(t *testing.T, path, at, rt string) {
	t.Helper()
	text := fmt.Sprintf("access_token = %q\ntoken_type = \"Bearer\"\nrefresh_token = %q\nexpires_in = 604800\ncreated_at = %d\n\n[user]\nid = \"u1\"\nusername = \"legacy\"\n", at, rt, time.Now().Unix())
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeLegacyJSON(t *testing.T, path, at, rt string) {
	t.Helper()
	text := fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer","refresh_token":%q,"expires_in":604800,"created_at":%d,"user":{"id":"u2","username":"jsonuser"}}`,
		at, rt, time.Now().Unix())
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// 迁移：accounts 为空 + auth.toml 存在 → 导入为账号 #1，原文件保留。
func TestMigrate_FromTOML(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(t.TempDir(), "auth.toml")
	writeLegacyTOML(t, src, "at-legacy", "rt-legacy")

	p := newStorePool(t, dir)
	if n := p.MigrateLegacy(src, filepath.Join(dir, "auth.json")); n != 1 {
		t.Fatalf("迁移数量=%d 期望 1", n)
	}
	a := p.Get("u1")
	if a == nil {
		t.Fatal("迁移后应能按 user.id 取到账号")
	}
	if a.Cred.AccessToken() != "at-legacy" {
		t.Fatalf("AccessToken=%q", a.Cred.AccessToken())
	}
	// 凭据副本落池目录
	if _, err := os.Stat(filepath.Join(dir, "accounts", "u1.json")); err != nil {
		t.Fatalf("池凭据文件缺失: %v", err)
	}
	// 原文件保留
	if raw, err := os.ReadFile(src); err != nil || !strings.Contains(string(raw), "rt-legacy") {
		t.Fatal("原 auth.toml 应原样保留")
	}
	// 再迁移不重复
	if n := p.MigrateLegacy(src, ""); n != 0 {
		t.Fatalf("重复迁移=%d 期望 0", n)
	}
}

// 迁移优先 auth.json（独立 RT 链较新）。
func TestMigrate_PrefersAuthJSON(t *testing.T) {
	dir := t.TempDir()
	tomlSrc := filepath.Join(t.TempDir(), "auth.toml")
	writeLegacyTOML(t, tomlSrc, "at-toml", "rt-toml")
	jsonSrc := filepath.Join(dir, "auth.json")
	writeLegacyJSON(t, jsonSrc, "at-json", "rt-json")

	p := newStorePool(t, dir)
	if n := p.MigrateLegacy(tomlSrc, jsonSrc); n != 1 {
		t.Fatalf("迁移数量=%d 期望 1", n)
	}
	if p.Get("u2") == nil {
		t.Fatal("应优先迁移 auth.json 的账号")
	}
	if a := p.Get("u2"); a.Cred.AccessToken() != "at-json" {
		t.Fatalf("AccessToken=%q 期望 at-json", a.Cred.AccessToken())
	}
}

// 重启回读：凭据文件 + pool-state 快照合并恢复调度状态。
func TestSnapshot_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := newStorePool(t, dir)
	a, err := p.Add(testCreds("u1", "rt-1"), false)
	if err != nil {
		t.Fatal(err)
	}
	a.WindowUsed, a.WindowLimit = 123, 400
	a.TotalOK, a.TotalFail, a.ConsecFail = 10, 2, 1
	a.Plan = "CodingPlan Lite"
	a.Disabled = true
	a.CooldownUntil = p.now().Add(time.Hour)

	p.mu.Lock()
	if err := p.snapshotLocked(); err != nil {
		p.mu.Unlock()
		t.Fatal(err)
	}
	p.mu.Unlock()

	p2 := newStorePool(t, dir)
	a2 := p2.Get("u1")
	if a2 == nil {
		t.Fatal("重启后账号应存在")
	}
	if a2.WindowUsed != 123 || a2.WindowLimit != 400 {
		t.Fatalf("窗口=%d/%d 期望 123/400", a2.WindowUsed, a2.WindowLimit)
	}
	if a2.TotalOK != 10 || a2.TotalFail != 2 || a2.ConsecFail != 1 {
		t.Fatalf("计数=%d/%d/%d", a2.TotalOK, a2.TotalFail, a2.ConsecFail)
	}
	if !a2.Disabled || a2.Plan != "CodingPlan Lite" || a2.CooldownUntil.IsZero() {
		t.Fatal("禁用/套餐/冷却未恢复")
	}
	if a2.Cred.AccessToken() != "at-u1" {
		t.Fatalf("凭据未恢复: %q", a2.Cred.AccessToken())
	}
}

// pool-state.json 损坏：丢弃统计从空状态重建，凭据文件仍正常装载（开放问题 9）。
func TestLoadState_Corrupt(t *testing.T) {
	dir := t.TempDir()
	p := newStorePool(t, dir)
	a, err := p.Add(testCreds("u1", "rt-1"), false)
	if err != nil {
		t.Fatal(err)
	}
	a.WindowUsed = 999
	p.mu.Lock()
	_ = p.snapshotLocked()
	p.mu.Unlock()

	// 写坏状态文件
	if err := os.WriteFile(filepath.Join(dir, "pool-state.json"), []byte("{corrupted!!"), 0o600); err != nil {
		t.Fatal(err)
	}

	p2 := newStorePool(t, dir) // 不应 panic，且账号仍在
	a2 := p2.Get("u1")
	if a2 == nil {
		t.Fatal("状态损坏时凭据文件仍应装载账号")
	}
	if a2.WindowUsed != 0 {
		t.Fatalf("损坏状态应丢弃统计，WindowUsed=%d", a2.WindowUsed)
	}
	if a2.Cred.AccessToken() != "at-u1" {
		t.Fatal("凭据应可用")
	}
}

// 删除账号：凭据文件一并删除。
func TestRemove(t *testing.T) {
	dir := t.TempDir()
	p := newStorePool(t, dir)
	a, err := p.Add(testCreds("u1", "rt-1"), false)
	if err != nil {
		t.Fatal(err)
	}
	credFile := filepath.Join(dir, "accounts", "u1.json")
	if _, err := os.Stat(credFile); err != nil {
		t.Fatal("凭据文件应存在")
	}
	if err := p.Remove(a.ID); err != nil {
		t.Fatal(err)
	}
	if p.Count() != 0 {
		t.Fatal("删除后池应为空")
	}
	if _, err := os.Stat(credFile); !os.IsNotExist(err) {
		t.Fatal("凭据文件应被删除")
	}
	if err := p.Remove("nope"); err == nil {
		t.Fatal("删除不存在 id 应报错")
	}
}

// 无 [user] 表的凭据：id 退化为 rt 指纹，文件可回读。
func TestAdd_NoUserTable(t *testing.T) {
	dir := t.TempDir()
	p := newStorePool(t, dir)
	sc := testCreds("", "rt-nouser")
	a, err := p.Add(sc, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a.ID, "acct_") {
		t.Fatalf("无 user.id 时 id 应为指纹，实际 %q", a.ID)
	}
	p2 := newStorePool(t, dir)
	if p2.Get(a.ID) == nil {
		t.Fatal("指纹 id 账号应能回读")
	}
}
