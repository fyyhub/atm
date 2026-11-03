// P2 单元测试：换人上限、指定账号、登录替换、目录扫描导入、每日复活。
package pool

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// MaxAttempts：min(3, 健康数)，空池/单账号为 1；冷却中的账号不算健康。
func TestMaxAttempts(t *testing.T) {
	p := testPool(t)
	if p.MaxAttempts() != 1 {
		t.Fatal("空池应为 1")
	}
	mustAdd(t, p, "1", "rt-1")
	if p.MaxAttempts() != 1 {
		t.Fatal("单账号应为 1")
	}
	mustAdd(t, p, "2", "rt-2")
	if p.MaxAttempts() != 2 {
		t.Fatal("两健康应为 2")
	}
	mustAdd(t, p, "3", "rt-3")
	mustAdd(t, p, "4", "rt-4")
	mustAdd(t, p, "5", "rt-5")
	if p.MaxAttempts() != 3 {
		t.Fatal("5 健康应封顶 3")
	}
	// 冷却 2 个 → 健康 3 → 上限 3；再冷却 2 个 → 健康 1 → 上限 1
	p.RecordFailure(p.Get("4"), "429", "x", 600)
	p.RecordFailure(p.Get("5"), "429", "x", 600)
	if p.MaxAttempts() != 3 {
		t.Fatalf("冷却 2 个后应为 3，得 %d", p.MaxAttempts())
	}
	p.RecordFailure(p.Get("2"), "429", "x", 600)
	p.RecordFailure(p.Get("3"), "429", "x", 600)
	if p.MaxAttempts() != 1 {
		t.Fatalf("只剩 1 健康应为 1，得 %d", p.MaxAttempts())
	}
}

// AcquireSpecific：指定账号调度（X-Account-Id 语义）。
func TestAcquireSpecific(t *testing.T) {
	p := testPool(t)
	a := mustAdd(t, p, "1", "rt-1")
	mustAdd(t, p, "2", "rt-2")

	if _, err := p.AcquireSpecific("nope"); !errors.Is(err, ErrUnknownAccount) {
		t.Fatalf("未知 id 应 ErrUnknownAccount，得 %v", err)
	}
	p.RecordFailure(a, "429", "x", 600)
	if _, err := p.AcquireSpecific("1"); !errors.Is(err, ErrAccountUnavailable) {
		t.Fatalf("冷却账号应 ErrAccountUnavailable，得 %v", err)
	}
	got, err := p.AcquireSpecific("2")
	if err != nil || got.ID != "2" {
		t.Fatalf("指定健康账号失败: %v", err)
	}
	if got.LastUsed.IsZero() {
		t.Fatal("指定调度应记账 lastUsed")
	}
}

// AddOrReplace：重新登录同账号 → 换凭据、清失效、保统计；新账号 → 正常添加。
func TestAddOrReplace(t *testing.T) {
	p := testPool(t)
	a := mustAdd(t, p, "1", "rt-1")
	a.TotalOK = 42
	p.RecordFailure(a, "auth", "rt dead", 0)
	if !a.AuthInvalid {
		t.Fatal("前置：账号应已失效")
	}

	sc := testCreds("1", "rt-1-new")
	sc.AccessToken = "at-1-new"
	b, err := p.AddOrReplace(sc)
	if err != nil {
		t.Fatal(err)
	}
	if b != a {
		t.Fatal("同 id 应复用原 Account 对象")
	}
	if a.AuthInvalid || a.LastError != "" {
		t.Fatal("替换应清失效标记")
	}
	if a.TotalOK != 42 {
		t.Fatal("替换应保留统计")
	}
	if a.Cred.AccessToken() != "at-1-new" || a.Cred.RefreshToken() != "rt-1-new" {
		t.Fatal("替换应换新凭据")
	}
	if p.Count() != 1 {
		t.Fatal("替换不应增加账号数")
	}

	if _, err := p.AddOrReplace(testCreds("2", "rt-2")); err != nil {
		t.Fatal(err)
	}
	if p.Count() != 2 {
		t.Fatal("新账号应正常添加")
	}
}

// ScanImportDir：新账号导入、查重命中跳过、坏文件改名 .bad、重复扫描幂等。
func TestScanImportDir(t *testing.T) {
	dir := t.TempDir()
	p := newStorePool(t, dir)
	mustAdd(t, p, "1", "rt-1")

	imp := filepath.Join(dir, "import")
	if err := os.MkdirAll(imp, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLegacyTOML(t, filepath.Join(imp, "new.toml"), "at-2", "rt-2")    // 新账号
	writeLegacyTOML(t, filepath.Join(imp, "dup.toml"), "at-1b", "rt-1")   // 同 RT 查重
	if err := os.WriteFile(filepath.Join(imp, "bad.toml"), []byte("not a toml = ["), 0o600); err != nil {
		t.Fatal(err)
	}

	if n := p.ScanImportDir(); n != 1 {
		t.Fatalf("新导入=%d 期望 1", n)
	}
	if p.Count() != 2 {
		t.Fatalf("池=%d 期望 2", p.Count())
	}
	// 文件处置：两个成功（含查重）移入 imported/，坏的改名 .bad
	for _, f := range []string{"new.toml", "dup.toml"} {
		if _, err := os.Stat(filepath.Join(imp, "imported", f)); err != nil {
			t.Fatalf("%s 应移入 imported/: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(imp, "bad.toml.bad")); err != nil {
		t.Fatal("坏文件应改名 .bad")
	}
	// 幂等：再扫不重复导入
	if n := p.ScanImportDir(); n != 0 {
		t.Fatalf("重复扫描=%d 期望 0", n)
	}
	if p.Count() != 2 {
		t.Fatal("重复扫描不应加账号")
	}
	// 目录不存在 = 常态
	p2 := newStorePool(t, t.TempDir())
	if n := p2.ScanImportDir(); n != 0 {
		t.Fatal("无导入目录应返回 0")
	}
}

// ScanImportDir 支持 .json（auth.json 形状，种子账号导入用）。
func TestScanImportDir_JSON(t *testing.T) {
	dir := t.TempDir()
	p := newStorePool(t, dir)
	imp := filepath.Join(dir, "import")
	if err := os.MkdirAll(imp, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLegacyJSON(t, filepath.Join(imp, "seed.json"), "at-seed", "rt-seed")

	if n := p.ScanImportDir(); n != 1 {
		t.Fatalf("JSON 种子应导入 1 个，得 %d", n)
	}
	a := p.Get("u2")
	if a == nil || a.Cred.AccessToken() != "at-seed" {
		t.Fatal("JSON 种子账号应可用")
	}
	if _, err := os.Stat(filepath.Join(imp, "imported", "seed.json")); err != nil {
		t.Fatal("种子文件应移入 imported/")
	}
	// 幂等
	if n := p.ScanImportDir(); n != 0 {
		t.Fatal("重复扫描不应重复导入")
	}
}

// revive：auth_invalid 账号 RT 试刷成功则复活回 ok。
func TestRevive(t *testing.T) {
	p := testPool(t)
	a := mustAdd(t, p, "1", "rt-1")
	p.RecordFailure(a, "auth", "rt dead", 0)
	if !a.AuthInvalid {
		t.Fatal("前置：应失效")
	}

	// 假刷新端点：成功
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"at-new","refresh_token":"rt-new","expires_in":604800}`)
	}))
	defer srv.Close()
	a.Cred.RefreshURL = srv.URL

	if !p.revive(a) {
		t.Fatal("刷新成功应复活")
	}
	if a.AuthInvalid || a.LastError != "" || a.ConsecFail != 0 {
		t.Fatal("复活后状态应干净")
	}
	if a.Cred.AccessToken() != "at-new" {
		t.Fatal("复活后应用新 token")
	}

	// 假刷新端点：失败
	a.AuthInvalid = true
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer bad.Close()
	a.Cred.RefreshURL = bad.URL
	if p.revive(a) {
		t.Fatal("刷新失败不应复活")
	}
	if !a.AuthInvalid {
		t.Fatal("复活失败应保持失效")
	}
}

// refreshAll 集成：失效账号经 revive 复活后继续 status 流程（con=nil 时不炸）。
func TestRefreshAll_RevivePath(t *testing.T) {
	p := testPool(t)
	a := mustAdd(t, p, "1", "rt-1")
	a.AuthInvalid = true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"at-r","refresh_token":"rt-r","expires_in":604800}`)
	}))
	defer srv.Close()
	a.Cred.RefreshURL = srv.URL

	p.refreshAll(context.Background())
	if a.AuthInvalid {
		t.Fatal("refreshAll 应复活失效账号")
	}
}
