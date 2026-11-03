// P3 单元测试：粘性缓存（命中/TTL/LRU）、粘性选人、加权打分可解释性。
package pool

import (
	"testing"
	"time"
)

// StickyCache：命中/未命中/滑动续期/TTL 过期/LRU 淘汰。
func TestStickyCache_TTLAndLRU(t *testing.T) {
	c := NewStickyCache()
	c.cap = 3 // 小容量方便测淘汰
	base := time.Now()
	c.now = func() time.Time { return base }

	c.Set("k1", "a1")
	c.Set("k2", "a2")
	c.Set("k3", "a3")
	if _, ok := c.Get("k1"); !ok {
		t.Fatal("k1 应命中")
	}

	// 滑动续期：29 分钟后命中 k1 → 不过期
	c.now = func() time.Time { return base.Add(29 * time.Minute) }
	if id, ok := c.Get("k1"); !ok || id != "a1" {
		t.Fatal("k1 滑动续期后应仍命中")
	}
	// k2 自写入起 31 分钟未命中 → 过期
	c.now = func() time.Time { return base.Add(31 * time.Minute) }
	if _, ok := c.Get("k2"); ok {
		t.Fatal("k2 超 TTL 应过期")
	}

	// LRU：cap=3。此刻存活 {k1(29m 前命中), k3(base 写入)}；加 k4 → 满；加 k5 →
	// 淘汰最久未命中的 k3，k1 因近期命中保留。
	c.now = func() time.Time { return base.Add(32 * time.Minute) }
	c.Set("k4", "a4")
	c.Set("k5", "a5")
	if c.Len() != 3 {
		t.Fatalf("超出上限应淘汰到 3: %d", c.Len())
	}
	if _, ok := c.Get("k1"); !ok {
		t.Fatal("k1 近期命中应保留")
	}
	if _, ok := c.Get("k3"); ok {
		t.Fatal("k3 最久未命中应被淘汰")
	}
}

// AcquireSticky：命中健康账号 → 直接用（即使另一个账号打分更高）。
func TestAcquireSticky_HitHealthy(t *testing.T) {
	p := testPool(t)
	a := mustAdd(t, p, "1", "rt-1")
	b := mustAdd(t, p, "2", "rt-2")
	a.WindowLimit, b.WindowLimit = 100, 100
	a.WindowUsed, b.WindowUsed = 90, 0 // b 打分远高于 a

	p.BindSticky("s1", a.ID)
	for i := 0; i < 5; i++ {
		if got := p.AcquireSticky("s1"); got != a {
			t.Fatalf("粘性命中应恒为 a，第 %d 次得 %v", i, got)
		}
		p.Release(p.Get(a.ID))
	}
}

// 命中但不健康 → 落回调度；成功后 BindSticky 改写映射。
func TestAcquireSticky_UnhealthyRewrite(t *testing.T) {
	p := testPool(t)
	a := mustAdd(t, p, "1", "rt-1")
	b := mustAdd(t, p, "2", "rt-2")
	p.BindSticky("s1", a.ID)

	p.RecordFailure(a, "429", "x", 600) // a 冷却
	got := p.AcquireSticky("s1")
	if got != b {
		t.Fatalf("a 不健康应落调度选 b，得 %v", got)
	}
	// 模拟成功后绑定新账号
	p.BindSticky("s1", got.ID)
	if id, _ := p.Sticky.Get("s1"); id != b.ID {
		t.Fatalf("映射应改写为 b，得 %q", id)
	}
	// 后续请求直接命中 b
	if got := p.AcquireSticky("s1"); got != b {
		t.Fatal("改写后应命中 b")
	}
}

// size=1：粘性零开销直通，不写缓存。
func TestSticky_Size1NoOp(t *testing.T) {
	p := testPool(t)
	mustAdd(t, p, "1", "rt-1")
	a := p.AcquireSticky("s1")
	if a == nil {
		t.Fatal("单账号应直通")
	}
	p.BindSticky("s1", a.ID)
	if p.Sticky.Len() != 0 {
		t.Fatal("size=1 不应写粘性缓存")
	}
}

// 加权：套餐权重打破配额平衡，但不压过大差距；成功率修正只降权不否决冷却。
func TestPickBest_Weighted(t *testing.T) {
	p := testPool(t)
	lite := mustAdd(t, p, "1", "rt-1")
	max := mustAdd(t, p, "2", "rt-2")
	lite.WindowLimit, max.WindowLimit = 400, 400
	lite.Plan, max.Plan = "CodingPlan Lite-体验版", "CodingPlan Max"

	// 配额接近（300 vs 250）→ Max 权重压过 Lite
	lite.WindowUsed, max.WindowUsed = 100, 150
	if got := p.Acquire(); got != max {
		t.Fatalf("配额接近时应选 Max，得 %v", got)
	}
	p.Release(max)

	// 配额差距大（390 vs 50）→ 权重不越界，选 Lite
	lite.WindowUsed, max.WindowUsed = 10, 350
	if got := p.Acquire(); got != lite {
		t.Fatalf("差距大时应选剩余多的 Lite，得 %v", got)
	}
	p.Release(lite)

	// 成功率修正：样本足够且 <80% → 降权
	lite.WindowUsed, max.WindowUsed = 100, 150
	lite.TotalOK, lite.TotalFail = 5, 20 // 20% 成功率 → -500
	if got := p.Acquire(); got != max {
		t.Fatalf("Lite 低成功率应被降权选 Max，得 %v", got)
	}
	p.Release(max)

	// 冷却语义不被打分覆盖：Max 冷却 → 仍选 Lite（哪怕 Lite 成功率差）
	p.RecordFailure(max, "429", "x", 600)
	if got := p.Acquire(); got != lite {
		t.Fatalf("Max 冷却中应选 Lite，得 %v", got)
	}
}
