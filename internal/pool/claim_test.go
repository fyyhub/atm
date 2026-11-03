// P3 修复测试：自动领取调度（录入即安排、错峰、失败重试、size=1 等价）。
package pool

import (
	"context"
	"encoding/json"
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

	"atomcode2api/internal/control"
)

// claimFake 控制面假服务器：记录 claim-v2 调用时刻与顺序。
type claimFake struct {
	mu     sync.Mutex
	claims []time.Time
	fail   bool
}

func (f *claimFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.Contains(r.URL.Path, "status-v2"):
		_, _ = io.WriteString(w, `{"codingplan_free":{"plan_name":"","plan_type":""},"current_usage":{"window_tokens_used":0,"window_token_limit":400}}`)
	case strings.Contains(r.URL.Path, "claim-v2"):
		f.mu.Lock()
		f.claims = append(f.claims, time.Now())
		fail := f.fail
		f.mu.Unlock()
		if fail {
			_, _ = io.WriteString(w, `{"success":false,"message":"控制面拒绝"}`)
			return
		}
		_, _ = io.WriteString(w, `{"success":true,"plan_name":"CodingPlan Max","plan_type":"Max"}`)
	}
}

func (f *claimFake) claimCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.claims)
}

func claimPool(t *testing.T, fail bool) (*Pool, *claimFake) {
	t.Helper()
	fake := &claimFake{fail: fail}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	con := control.New()
	con.Base = srv.URL
	logger := slogDiscard()
	p := New(t.TempDir(), con, logger)
	p.claimStagger = 20 * time.Millisecond // 测试不等真 10s
	return p, fake
}

func slogDiscard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// 新录入账号：NextClaimAt 立即到期；claimDue 成功领取 → 次日再领。
func TestClaimDue_NewAccountClaimed(t *testing.T) {
	p, fake := claimPool(t, false)
	a := mustAdd(t, p, "1", "rt-1")
	if a.NextClaimAt.After(p.now()) {
		t.Fatal("录入后应立即到期")
	}

	p.claimDue(context.Background())
	if fake.claimCount() != 1 {
		t.Fatalf("应领取 1 次，得 %d", fake.claimCount())
	}
	if d := time.Until(a.NextClaimAt); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("成功后应 24h 后再领，得 %v", d)
	}
	if a.LastError != "" {
		t.Fatalf("成功不应有 last_error: %q", a.LastError)
	}
	// 未到期不再领
	p.claimDue(context.Background())
	if fake.claimCount() != 1 {
		t.Fatal("未到期不应重复领取")
	}
}

// 领取失败：记 last_error + 30min 重试，不静默。
func TestClaimDue_FailureRetry(t *testing.T) {
	p, fake := claimPool(t, true)
	a := mustAdd(t, p, "1", "rt-1")

	p.claimDue(context.Background())
	if fake.claimCount() != 3 {
		t.Fatalf("ClaimBest 级联三档应 3 次调用，得 %d", fake.claimCount())
	}
	if !strings.Contains(a.LastError, "自动领取失败") {
		t.Fatalf("应记明确 last_error，得 %q", a.LastError)
	}
	if d := time.Until(a.NextClaimAt); d < 29*time.Minute || d > 31*time.Minute {
		t.Fatalf("失败后应 30min 重试，得 %v", d)
	}
}

// 错峰：两个到期账号的领取间隔 = claimStagger。
func TestClaimDue_Staggered(t *testing.T) {
	p, fake := claimPool(t, false)
	mustAdd(t, p, "1", "rt-1")
	mustAdd(t, p, "2", "rt-2")

	p.claimDue(context.Background())
	if fake.claimCount() != 2 {
		t.Fatalf("应领 2 次，得 %d", fake.claimCount())
	}
	fake.mu.Lock()
	gap := fake.claims[1].Sub(fake.claims[0])
	fake.mu.Unlock()
	if gap < p.claimStagger {
		t.Fatalf("错峰间隔应 >= %v，实际 %v", p.claimStagger, gap)
	}
}

// size=1：单账号到期领取照常（与旧单账号启动即领取语义等价）。
func TestClaimDue_Size1(t *testing.T) {
	p, fake := claimPool(t, false)
	mustAdd(t, p, "1", "rt-1")
	p.claimDue(context.Background())
	if fake.claimCount() != 1 {
		t.Fatal("单账号应正常领取")
	}
}

// 禁用/失效账号不领取。
func TestClaimDue_SkipsDisabledAndInvalid(t *testing.T) {
	p, fake := claimPool(t, false)
	a := mustAdd(t, p, "1", "rt-1")
	b := mustAdd(t, p, "2", "rt-2")
	_ = p.SetDisabled(a.ID, true)
	b.AuthInvalid = true

	p.claimDue(context.Background())
	if fake.claimCount() != 0 {
		t.Fatalf("禁用/失效不应领取，得 %d", fake.claimCount())
	}
}

// 重启后领取计划保留（pool-state 回读）；旧版状态文件无该字段 → 规整为立即领取。
func TestClaimSchedule_Persisted(t *testing.T) {
	dir := t.TempDir()
	p := newStorePool(t, dir)
	a, err := p.Add(testCreds("1", "rt-1"), false)
	if err != nil {
		t.Fatal(err)
	}
	a.NextClaimAt = p.now().Add(2 * time.Hour)
	p.mu.Lock()
	_ = p.snapshotLocked()
	p.mu.Unlock()

	p2 := newStorePool(t, dir)
	a2 := p2.Get("1")
	if d := a2.NextClaimAt.Sub(p.now()); d < time.Hour || d > 3*time.Hour {
		t.Fatalf("领取时刻应回读约 2h 后，得 %v", d)
	}

	// 旧版 pool-state（无 next_claim_at 字段）→ 装载规整为立即到期
	dir2 := t.TempDir()
	p3 := newStorePool(t, dir2)
	if _, err := p3.Add(testCreds("1", "rt-1"), false); err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(dir2, "pool-state.json")
	raw, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		t.Fatal(err)
	}
	for _, ai := range m["accounts"].([]any) {
		delete(ai.(map[string]any), "next_claim_at")
	}
	stripped, _ := json.Marshal(m)
	if err := os.WriteFile(stateFile, stripped, 0o600); err != nil {
		t.Fatal(err)
	}
	p4 := newStorePool(t, dir2)
	if a4 := p4.Get("1"); a4.NextClaimAt.After(p4.now()) {
		t.Fatal("旧状态文件缺字段时应规整为立即领取")
	}
}
