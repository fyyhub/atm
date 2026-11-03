// 调度（pickBest 打分/过滤/单账号直通）、查重、上限、冷却记账的单元测试。
package pool

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"atomcode2api/internal/lanes"
)

func testPool(t *testing.T) *Pool {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(t.TempDir(), nil, logger)
}

func testCreds(uid, rt string) lanes.SaveCreds {
	return lanes.SaveCreds{
		AccessToken:  "at-" + uid,
		TokenType:    "Bearer",
		RefreshToken: rt,
		ExpiresIn:    604800,
		CreatedAt:    time.Now().Unix(),
		User:         lanes.User{ID: uid, Username: "u" + uid},
		HasUser:      uid != "",
	}
}

func mustAdd(t *testing.T, p *Pool, uid, rt string) *Account {
	t.Helper()
	a, err := p.Add(testCreds(uid, rt), false)
	if err != nil {
		t.Fatalf("Add(%s): %v", uid, err)
	}
	return a
}

// 打分主键：剩余窗口配额多者胜。
func TestPickBest_RemainingWindow(t *testing.T) {
	p := testPool(t)
	a := mustAdd(t, p, "1", "rt-1")
	b := mustAdd(t, p, "2", "rt-2")
	c := mustAdd(t, p, "3", "rt-3")
	for _, x := range []*Account{a, b, c} {
		x.WindowLimit = 100
	}
	a.WindowUsed, b.WindowUsed, c.WindowUsed = 90, 60, 70 // 剩余 10/40/30

	if got := p.Acquire(); got != b {
		t.Fatalf("期望选中剩余最多的 b，实际 %v", got)
	}
}

// 同分兜底：最久未用者胜。
func TestPickBest_LRUTieBreak(t *testing.T) {
	p := testPool(t)
	a := mustAdd(t, p, "1", "rt-1")
	b := mustAdd(t, p, "2", "rt-2")
	a.WindowLimit, b.WindowLimit = 100, 100
	a.WindowUsed, b.WindowUsed = 50, 50
	a.LastUsed = time.Now().Add(-time.Hour) // a 更久未用
	b.LastUsed = time.Now()

	if got := p.Acquire(); got != a {
		t.Fatalf("同分期望选中最久未用的 a，实际 %v", got)
	}
}

// 过滤：冷却/auth_invalid/禁用不参与调度（池 >1 时）；冷却到点自动恢复。
func TestPickBest_Filters(t *testing.T) {
	p := testPool(t)
	a := mustAdd(t, p, "1", "rt-1")
	b := mustAdd(t, p, "2", "rt-2")
	a.WindowLimit, b.WindowLimit = 100, 100

	// a 冷却中 → 只能选 b
	p.RecordFailure(a, "429", "test", 60)
	if got := p.Acquire(); got != b {
		t.Fatalf("a 冷却中期望选 b，实际 %v", got)
	}
	if st := a.Status(p.now()); st != StatusCooling {
		t.Fatalf("a 状态期望 cooling，实际 %s", st)
	}

	// 冷却到点自动回 ok（把冷却截止拨到过去）
	p.mu.Lock()
	a.CooldownUntil = p.now().Add(-time.Second)
	p.mu.Unlock()
	if st := a.Status(p.now()); st != StatusOK {
		t.Fatalf("冷却过期后期望 ok，实际 %s", st)
	}

	// b 失效 + a 恢复 → 选 a
	p.RecordFailure(b, "auth", "rt dead", 0)
	if got := p.Acquire(); got != a {
		t.Fatalf("b 失效期望选 a，实际 %v", got)
	}
	if st := b.Status(p.now()); st != StatusAuthInvalid {
		t.Fatalf("b 状态期望 auth_invalid，实际 %s", st)
	}

	// 全禁用 → nil
	_ = p.SetDisabled("1", true)
	_ = p.SetDisabled("2", true)
	if got := p.Acquire(); got != nil {
		t.Fatalf("全禁用期望 nil，实际 %v", got)
	}
}

// 单账号直通：冷却/失效不过滤（行为与池化前一致），但禁用仍生效。
func TestPickBest_SingleAccountFailThrough(t *testing.T) {
	p := testPool(t)
	a := mustAdd(t, p, "1", "rt-1")
	p.RecordFailure(a, "429", "test", 3600)
	p.RecordFailure(a, "auth", "rt dead", 0)

	if got := p.Acquire(); got != a {
		t.Fatalf("单账号期望直通返回 a，实际 %v", got)
	}
	_ = p.SetDisabled("1", true)
	if got := p.Acquire(); got != nil {
		t.Fatalf("单账号禁用期望 nil，实际 %v", got)
	}
}

// 查重：按 refresh token 与 user.id 拒绝（开放问题 1）。
func TestAdd_Dedupe(t *testing.T) {
	p := testPool(t)
	mustAdd(t, p, "1", "rt-1")

	if _, err := p.Add(testCreds("2", "rt-1"), false); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("同 RT 期望 ErrDuplicate，实际 %v", err)
	}
	if _, err := p.Add(testCreds("1", "rt-other"), false); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("同 user.id 期望 ErrDuplicate，实际 %v", err)
	}
	if _, err := p.Add(testCreds("3", "rt-3"), false); err != nil {
		t.Fatalf("不同账号应添加成功: %v", err)
	}
}

// 软上限 100（开放问题 5）。
func TestAdd_Cap(t *testing.T) {
	p := testPool(t)
	for i := 0; i < MaxAccounts; i++ {
		if _, err := p.Add(testCreds("", rt(i)), false); err != nil {
			t.Fatalf("第 %d 个账号添加失败: %v", i, err)
		}
	}
	if _, err := p.Add(testCreds("", "rt-over"), false); err == nil {
		t.Fatal("超过软上限应报错")
	}
}

func rt(i int) string {
	return "rt-" + time.Unix(int64(i), 0).Format("150405") + "-" + string(rune('a'+i%26)) + "-" + string(rune('A'+i/26))
}

// 记账：成功累加窗口估计并清连失；quota 记满窗口；net 三次起冷却。
func TestRecord(t *testing.T) {
	p := testPool(t)
	a := mustAdd(t, p, "1", "rt-1")
	b := mustAdd(t, p, "2", "rt-2")
	a.WindowLimit, b.WindowLimit = 400, 400

	p.RecordSuccess(a, map[string]any{"prompt_tokens": 100.0, "completion_tokens": 20.0})
	if a.WindowUsed != 120 {
		t.Fatalf("WindowUsed=%d 期望 120", a.WindowUsed)
	}

	p.RecordFailure(a, "quota", "耗尽", 1800)
	if a.WindowUsed != a.WindowLimit {
		t.Fatalf("quota 后窗口应记满，WindowUsed=%d", a.WindowUsed)
	}
	if !a.CooldownUntil.After(p.now().Add(1700 * time.Second)) {
		t.Fatal("quota 冷却应约 30 分钟")
	}

	for i := 0; i < 2; i++ {
		p.RecordFailure(b, "net", "boom", 0)
	}
	if !b.CooldownUntil.IsZero() {
		t.Fatal("连失 2 次不应触发冷却")
	}
	p.RecordFailure(b, "net", "boom", 0)
	if b.CooldownUntil.IsZero() {
		t.Fatal("连失 3 次应触发冷却")
	}

	p.RecordSuccess(b, nil)
	if b.ConsecFail != 0 {
		t.Fatal("成功后连失应清零")
	}
}

// 窗口到重置点自动清零。
func TestWindowRollover(t *testing.T) {
	p := testPool(t)
	a := mustAdd(t, p, "1", "rt-1")
	a.WindowLimit = 400
	a.WindowUsed = 399
	a.WindowReset = p.now().Add(-time.Minute) // 已过重置点

	p.RecordSuccess(a, map[string]any{"prompt_tokens": 1.0})
	if a.WindowUsed != 1 {
		t.Fatalf("重置后 WindowUsed=%d 期望 1", a.WindowUsed)
	}
}

// 重置状态按钮语义。
func TestResetState(t *testing.T) {
	p := testPool(t)
	a := mustAdd(t, p, "1", "rt-1")
	p.RecordFailure(a, "auth", "rt dead", 0)
	p.RecordFailure(a, "net", "x", 0)

	if err := p.ResetState(a.ID); err != nil {
		t.Fatal(err)
	}
	if a.AuthInvalid || a.ConsecFail != 0 || !a.CooldownUntil.IsZero() || a.LastError != "" {
		t.Fatal("ResetState 未清干净")
	}
	if err := p.ResetState("nope"); err == nil {
		t.Fatal("不存在 id 应报错")
	}
}
