// 会话粘性缓存（P3）：map[key]accountID，滑动 TTL 30 分钟（命中即续期），
// 上限 1 万条，超出按 LRU 淘汰最久未命中条目。
//
// 写纪律（规则：换人成功写入新账号，失败不覆盖）：
//   - 选人用 Pool.AcquireSticky —— 只读缓存，不写；
//   - 请求成功后才 Pool.BindSticky —— 失败请求永不污染映射。
package pool

import (
	"container/list"
	"sync"
	"time"
)

const (
	stickyTTL = 30 * time.Minute // 滑动过期：命中即续期
	stickyCap = 10000            // LRU 上限
)

type stickyEntry struct {
	key       string
	accountID string
	touched   time.Time
	elem      *list.Element
}

// StickyCache 会话粘性缓存（独立小锁，不进池主锁的关键路径）。
type StickyCache struct {
	mu  sync.Mutex
	m   map[string]*stickyEntry
	lru *list.List // 首=最近命中，尾=最久未命中
	ttl time.Duration
	cap int
	now func() time.Time // 测试注入点
}

// NewStickyCache 默认参数（30min / 10000）。
func NewStickyCache() *StickyCache {
	return &StickyCache{m: map[string]*stickyEntry{}, lru: list.New(), ttl: stickyTTL, cap: stickyCap, now: time.Now}
}

// Get 命中且未过期 → 续期并返回 accountID；过期即淘汰。
func (c *StickyCache) Get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[key]
	if e == nil {
		return "", false
	}
	if c.now().Sub(e.touched) > c.ttl {
		c.removeLocked(e)
		return "", false
	}
	e.touched = c.now()
	c.lru.MoveToFront(e.elem)
	return e.accountID, true
}

// Set 写入/更新并置为最近命中；超出上限淘汰最久未命中者。
func (c *StickyCache) Set(key, accountID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.m[key]; e != nil {
		e.accountID = accountID
		e.touched = c.now()
		c.lru.MoveToFront(e.elem)
		return
	}
	e := &stickyEntry{key: key, accountID: accountID, touched: c.now()}
	e.elem = c.lru.PushFront(e)
	c.m[key] = e
	for len(c.m) > c.cap {
		back := c.lru.Back()
		if back == nil {
			break
		}
		c.removeLocked(back.Value.(*stickyEntry))
	}
}

// Len 当前条目数（测试/诊断用）。
func (c *StickyCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

func (c *StickyCache) removeLocked(e *stickyEntry) {
	delete(c.m, e.key)
	c.lru.Remove(e.elem)
}
