// Package pool 多账号池：凭据注册、调度、冷却与本地窗口估计。
//
// 调度：剩余窗口配额（window_limit - window_used）主键 + 最久未用兜底，
// 一把 RWMutex 锁内完成「过滤 → 打分 → 记账（lastUsed/inflight）」。
//
// P1 关键取舍：池内只剩 1 个账号时冷却与 auth_invalid 不参与过滤——没有备选，
// 冷却它买不来任何东西，故障直通上游，行为与池化前的单账号网关完全一致；
// disabled 是显式用户动作，永远生效。
//
// 窗口水位是本地估计：录入/每日错峰刷 status-v2 校准 + 每次请求后按 usage
// 累加；越过 window_reset 自动清零。status-v2 只描述官方客户端路径，估计值
// 仅供调度打分，不代表反代路径的硬限（见 control 包注释）。
package pool

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"atomcode2api/internal/control"
	"atomcode2api/internal/lanes"
)

// 账号状态（Status() 计算得出，不直接落盘）。
const (
	StatusOK          = "ok"
	StatusCooling     = "cooling"
	StatusAuthInvalid = "auth_invalid"
	StatusDisabled    = "disabled"
)

// MaxAccounts 账号软上限（开放问题 5）。
const MaxAccounts = 100

// 冷却时长常量。
const (
	cooldown429     = 60 * time.Second  // 上游 429 无 Retry-After 可考时的默认
	cooldownAuth    = 6 * time.Hour     // RT 刷新失败（视为凭据失效，需重新登录）
	cooldownQuota   = 5 * time.Minute   // 伪回复未提取到 reset 时刻时的兜底
	cooldownNet     = 5 * time.Minute   // 连续失败 >=3 次的起点（指数退避）
	cooldownNetMax  = time.Hour         // 网络类冷却封顶
	netFailCooldown = 3                 // 触发网络类冷却的连续失败阈值
)

// Account 池内一个账号：凭据 + 调度/健康状态。
type Account struct {
	ID       string // user.id；缺失时 "acct_" + rt 指纹前 12 位
	Username string
	Cred     *lanes.Credential

	Plan          string    // 套餐名（status-v2 校准）
	PlanExpiresAt string    // 套餐到期（上游原样字符串）
	WindowUsed    int64     // 本地估计的窗口已用 tokens
	WindowLimit   int64     // 窗口上限（0 = 未知，打分时给最小正分）
	WindowReset   time.Time // 窗口重置时刻（零点 = 未知/未设置）

	CooldownUntil time.Time
	ConsecFail    int
	TotalOK       int64
	TotalFail     int64
	LastUsed      time.Time
	LastError     string
	AddedAt       time.Time
	Disabled      bool
	AuthInvalid   bool
	// NextClaimAt 下次自动领取时刻（P3 修复：录入即安排领取）。
	// 零值 = 尽快（启动装载时规整为 now）；成功/已持有 → +24h；失败 → +30min。
	NextClaimAt time.Time

	inflight int // 在途请求数（记账用，不落盘）
}

// Status 计算展示态：disabled > auth_invalid > cooling > ok。
func (a *Account) Status(now time.Time) string {
	switch {
	case a.Disabled:
		return StatusDisabled
	case a.AuthInvalid:
		return StatusAuthInvalid
	case now.Before(a.CooldownUntil):
		return StatusCooling
	}
	return StatusOK
}

// available 是否可被调度选中。n 是池内账号总数：n==1 时故障直通（见包注释）。
func (a *Account) available(now time.Time, n int) bool {
	if a.Disabled {
		return false
	}
	if n == 1 {
		return true
	}
	return !a.AuthInvalid && !now.Before(a.CooldownUntil)
}

// remaining 剩余窗口配额（打分主键）。未知水位给 1，保持可被选中。
// 调用方须先 rolloverWindow。
func (a *Account) remaining() int64 {
	if a.WindowLimit <= 0 {
		return 1
	}
	if r := a.WindowLimit - a.WindowUsed; r > 0 {
		return r
	}
	return 0
}

// rolloverWindow 越过重置点清零本地窗口估计。
func (a *Account) rolloverWindow(now time.Time) {
	if !a.WindowReset.IsZero() && !now.Before(a.WindowReset) {
		a.WindowUsed = 0
		a.WindowReset = time.Time{}
	}
}

// Pool 账号池。
type Pool struct {
	mu       sync.RWMutex
	accounts map[string]*Account
	order    []string // 稳定展示顺序（按录入先后）

	// Sticky 会话粘性缓存（P3）。size<=1 时 AcquireSticky/BindSticky 直通不碰它。
	Sticky *StickyCache

	dir       string          // StateDir/accounts（凭据文件目录）
	statePath string          // StateDir/pool-state.json
	con       *control.Client // 录入校验与每日错峰刷新用
	log       *slog.Logger

	dirty bool              // 有待快照的状态变迁
	now   func() time.Time  // 测试注入点

	// claimStagger 领取错峰间隔（默认 10s；测试置为极短）。
	claimStagger time.Duration
}

// New 建池并尽量从 dir 装载已有账号（含 pool-state 合并）。装载失败不致命：
// 目录不可建/不可读时退化为纯内存池（日志告警）。
func New(stateDir string, con *control.Client, logger *slog.Logger) *Pool {
	if logger == nil {
		logger = slog.Default()
	}
	p := &Pool{
		accounts:  map[string]*Account{},
		Sticky:    NewStickyCache(),
		dir:       accountsDir(stateDir),
		statePath: stateFilePath(stateDir),
		con:       con,
		log:       logger,
		now:       time.Now,

		claimStagger: 10 * time.Second,
	}
	p.load()
	return p
}

// ── 调度 ─────────────────────────────────────────────────────────────────────

// Acquire 选最优账号并记账（lastUsed/inflight++）；无可用返回 nil。
// 调用方用完必须 Release。
func (p *Pool) Acquire() *Account {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.pickBestLocked()
	if a == nil {
		return nil
	}
	a.LastUsed = p.now()
	a.inflight++
	return a
}

// Release 归还账号（inflight--）。
func (p *Pool) Release(a *Account) {
	if a == nil {
		return
	}
	p.mu.Lock()
	a.inflight--
	p.mu.Unlock()
}

// ── 打分（P3 加权精调，全部线性可解释）───────────────────────────────────────
//
// score = 剩余窗口配额 + 套餐权重 + 成功率修正。
//
// 套餐权重量级对齐 Lite 窗口（400）的分数级：Max=120 / Pro=60 / Lite与未知=0。
// 语义：权重只在剩余配额差距 <30% 窗口时打破平衡——小余量的 Max 永远压不过
// 大余量的 Lite（差距 400+ 时权重无效），可解释、可心算验证。
//
// 成功率修正：样本 >=20 才生效；≥95% → +200（约半窗口）；<80% → -500
// （明显降权但不禁用——冷却/禁用语义由 available() 独立保证，打分永不覆盖）。
//
// planWeight 套餐等级权重。
func planWeight(plan string) int64 {
	switch {
	case strings.Contains(plan, "Max"):
		return 120
	case strings.Contains(plan, "Pro"):
		return 60
	default:
		return 0
	}
}

// successBonus 成功率修正（样本不足 20 不修正，避免冷启动抖动）。
func (a *Account) successBonus() int64 {
	total := a.TotalOK + a.TotalFail
	if total < 20 {
		return 0
	}
	rate := float64(a.TotalOK) / float64(total)
	if rate >= 0.95 {
		return 200
	}
	if rate < 0.8 {
		return -500
	}
	return 0
}

// score 调度分（调用方须先 rolloverWindow）。
func (a *Account) score() int64 {
	return a.remaining() + planWeight(a.Plan) + a.successBonus()
}

// pickBestLocked 调度分主键 + 最久未用兜底。锁内调用。
func (p *Pool) pickBestLocked() *Account {
	now := p.now()
	n := len(p.accounts)
	var best *Account
	var bestScore int64
	for _, id := range p.order {
		a := p.accounts[id]
		a.rolloverWindow(now)
		if !a.available(now, n) {
			continue
		}
		sc := a.score()
		if best == nil || sc > bestScore ||
			(sc == bestScore && a.LastUsed.Before(best.LastUsed)) {
			best, bestScore = a, sc
		}
	}
	return best
}

// AcquireSticky 粘性选人（只读缓存不写——成败未定不写映射）。
// 命中且账号健康 → 直接用该账号；命中但不健康 → 落回正常调度，
// 缓存改写留给成功后的 BindSticky（失败不覆盖既有映射）。
// size<=1 时不碰缓存直通（零开销、行为与 P2 一致）。
func (p *Pool) AcquireSticky(key string) *Account {
	if key == "" {
		return p.Acquire()
	}
	p.mu.RLock()
	n := len(p.accounts)
	p.mu.RUnlock()
	if n <= 1 {
		return p.Acquire()
	}
	if id, ok := p.Sticky.Get(key); ok {
		p.mu.Lock()
		a := p.accounts[id]
		if a != nil && a.available(p.now(), len(p.accounts)) {
			a.LastUsed = p.now()
			a.inflight++
			p.mu.Unlock()
			return a
		}
		p.mu.Unlock()
	}
	return p.Acquire()
}

// BindSticky 请求成功确认后写入粘性映射。size<=1 时不写（无意义）。
func (p *Pool) BindSticky(key, accountID string) {
	if key == "" || accountID == "" {
		return
	}
	if p.Count() <= 1 {
		return
	}
	p.Sticky.Set(key, accountID)
}

// Default 兼容单账号语义的「代表账号」（Headers/Refresh//status/overview 用）：
// 优先最优可用账号，全不可用退到第一个未禁用账号，一只都没有返回 nil。不记账。
func (p *Pool) Default() *Account {
	p.mu.Lock()
	defer p.mu.Unlock()
	if a := p.pickBestLocked(); a != nil {
		return a
	}
	now := p.now()
	for _, id := range p.order {
		if a := p.accounts[id]; !a.Disabled && a.Status(now) != StatusDisabled {
			return a
		}
	}
	return nil
}

// Count 池内账号总数（含禁用/失效）。
func (p *Pool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.accounts)
}

// Get 按 id 取账号。
func (p *Pool) Get(id string) *Account {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.accounts[id]
}

// List 稳定顺序的账号快照。
func (p *Pool) List() []*Account {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*Account, 0, len(p.order))
	for _, id := range p.order {
		out = append(out, p.accounts[id])
	}
	return out
}

// ── P2：换人重试 / 指定账号 / 复活 ───────────────────────────────────────────

// MaxAttempts 单次请求的换人上限：min(3, 当前健康账号数)，至少 1。
// 健康数在循环起点取一次；循环中账号被冷却导致后续 Acquire 返回 nil 时，
// 由调用方按「池耗尽」收尾，语义一致。
func (p *Pool) MaxAttempts() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	n := len(p.accounts)
	h := 0
	for _, a := range p.accounts {
		if a.available(now, n) {
			h++
		}
	}
	if h < 1 {
		return 1
	}
	if h > 3 {
		return 3
	}
	return h
}

// 指定账号调度的错误（X-Account-Id 调试头用）。
var (
	ErrUnknownAccount    = errors.New("账号不存在")
	ErrAccountUnavailable = errors.New("账号当前不可用（冷却/失效/禁用中）")
)

// AcquireSpecific 指定账号调度：成功同样记账（lastUsed/inflight++）。
// 单账号直通语义同样适用于指定调度（与 Acquire 一致）。
func (p *Pool) AcquireSpecific(id string) (*Account, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.accounts[id]
	if a == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownAccount, id)
	}
	if !a.available(p.now(), len(p.accounts)) {
		return nil, fmt.Errorf("%w: %s（%s）", ErrAccountUnavailable, id, a.Status(p.now()))
	}
	a.LastUsed = p.now()
	a.inflight++
	return a, nil
}

// AddOrReplace OAuth 登录入池：同 user.id 已存在则替换凭据（重新登录同账号，
// 保留调度统计并清除 auth_invalid/冷却），否则走 Add 的查重与上限路径。
func (p *Pool) AddOrReplace(sc lanes.SaveCreds) (*Account, error) {
	if sc.HasUser && sc.User.ID != "" {
		p.mu.RLock()
		existing := p.accounts[sc.User.ID]
		p.mu.RUnlock()
		if existing != nil {
			path := filepath.Join(p.dir, existing.ID+".json")
			if err := lanes.SaveAuthJSON(path, sc); err != nil {
				return nil, fmt.Errorf("凭据落盘失败: %w", err)
			}
			cred, err := lanes.NewCredential(p.placeholderTOML(), path, p.log)
			if err != nil {
				return nil, fmt.Errorf("凭据装载失败: %w", err)
			}
			p.mu.Lock()
			existing.Cred = cred
			existing.Username = orString(sc.User.Username, existing.Username)
			existing.AuthInvalid = false
			existing.CooldownUntil = time.Time{}
			existing.LastError = ""
			existing.NextClaimAt = p.now() // 重新登录 = 新套餐周期，尽快领取
			p.dirty = true
			err = p.snapshotLocked()
			p.mu.Unlock()
			return existing, err
		}
	}
	return p.Add(sc, false)
}

// reviveLocked auth_invalid 账号每日复活：RT 试刷一次，成功清标记（开放：复活）。
// 返回是否复活。调用方不持锁（Refresh 是网络调用）。
func (p *Pool) revive(a *Account) bool {
	if err := a.Cred.Refresh(); err != nil {
		p.log.Warn("[revive] 复活失败", slog.String("account", a.Username), slog.String("err", err.Error()))
		return false
	}
	p.mu.Lock()
	a.AuthInvalid = false
	a.CooldownUntil = time.Time{}
	a.ConsecFail = 0
	a.LastError = ""
	p.dirty = true
	p.mu.Unlock()
	p.log.Info("[revive] 账号已复活", slog.String("account", a.Username), slog.String("id", a.ID))
	return true
}

// Clear 清空池内账号（仅内存，不动凭据文件）。Server.ClearCred 的池侧
// 配套——「回到未登录」语义；当前只有测试走这条路径。
func (p *Pool) Clear() {
	p.mu.Lock()
	p.accounts = map[string]*Account{}
	p.order = nil
	p.dirty = true
	p.mu.Unlock()
}

// MinCooldownSeconds 距最近一个冷却结束的秒数（pool_exhausted 的 Retry-After）。
// 无冷却中的账号返回 0。
func (p *Pool) MinCooldownSeconds() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	now := p.now()
	min := 0
	for _, a := range p.accounts {
		if a.Disabled || a.AuthInvalid {
			continue
		}
		if d := int(a.CooldownUntil.Sub(now).Seconds()); d > 0 && (min == 0 || d < min) {
			min = d
		}
	}
	return min
}

// ── 账号管理 ─────────────────────────────────────────────────────────────────

// ErrDuplicate 查重命中（开放问题 1：按 refresh token / user.id 拒绝重复）。
var ErrDuplicate = errors.New("账号已存在（refresh token 或 user.id 重复）")

// Add 录入账号：上限检查 → 查重 → 落盘 → 装载 → 可选校验。
// validate=true 时：token 临期先试 Refresh（失败 → auth_invalid，仍入库）；
// 然后拉一次 status-v2 校准套餐/窗口（失败仅记 LastError，不算 auth 问题）。
func (p *Pool) Add(sc lanes.SaveCreds, validate bool) (*Account, error) {
	p.mu.Lock()
	if len(p.accounts) >= MaxAccounts {
		p.mu.Unlock()
		return nil, fmt.Errorf("账号数已达软上限 %d", MaxAccounts)
	}
	for _, a := range p.accounts {
		if a.Cred.RefreshToken() != "" && a.Cred.RefreshToken() == sc.RefreshToken {
			p.mu.Unlock()
			return nil, ErrDuplicate
		}
		if sc.HasUser && sc.User.ID != "" && a.ID == sc.User.ID {
			p.mu.Unlock()
			return nil, ErrDuplicate
		}
	}
	p.mu.Unlock()

	a, err := p.materialize(sc)
	if err != nil {
		return nil, err
	}
	if validate {
		p.validate(a)
	}

	p.mu.Lock()
	p.accounts[a.ID] = a
	p.order = append(p.order, a.ID)
	p.dirty = true
	err = p.snapshotLocked()
	p.mu.Unlock()
	if err != nil {
		p.log.Warn("pool-state 快照失败", slog.String("err", err.Error()))
	}
	return a, nil
}

// validate 录入校验：RT 链活性 + 套餐状态校准。只标状态，不删账号。
func (p *Pool) validate(a *Account) {
	if a.Cred.IsExpired() {
		if err := a.Cred.Refresh(); err != nil {
			p.mu.Lock()
			a.AuthInvalid = true
			a.LastError = "token 刷新失败: " + err.Error()
			p.dirty = true
			p.mu.Unlock()
			return
		}
	}
	p.refreshStatus(a)
}

// refreshStatus 拉一次 status-v2 校准 plan/窗口字段（失败仅记 LastError）。
func (p *Pool) refreshStatus(a *Account) {
	if p.con == nil {
		return
	}
	st := p.con.Status(a.Cred)
	if len(st) == 0 {
		p.mu.Lock()
		a.LastError = "status-v2 拉取失败"
		p.dirty = true
		p.mu.Unlock()
		return
	}
	free := asMap(st["codingplan_free"])
	usage := asMap(st["current_usage"])
	p.mu.Lock()
	a.Plan = asString(free["plan_name"])
	a.PlanExpiresAt = asString(free["expires_at"])
	a.WindowLimit = asInt(usage["window_token_limit"])
	a.WindowUsed = asInt(usage["window_tokens_used"])
	a.WindowReset = parseReset(asString(usage["reset_at"]))
	a.LastError = ""
	p.dirty = true
	p.mu.Unlock()
}

// Remove 删除账号（含凭据文件）。
func (p *Pool) Remove(id string) error {
	p.mu.Lock()
	a := p.accounts[id]
	if a == nil {
		p.mu.Unlock()
		return fmt.Errorf("账号不存在: %s", id)
	}
	delete(p.accounts, id)
	for i, x := range p.order {
		if x == id {
			p.order = append(p.order[:i], p.order[i+1:]...)
			break
		}
	}
	p.dirty = true
	err := p.snapshotLocked()
	p.mu.Unlock()
	removeErr := p.removeCredFile(a)
	if err != nil {
		return err
	}
	return removeErr
}

// SetDisabled 禁用/启用。
func (p *Pool) SetDisabled(id string, disabled bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.accounts[id]
	if a == nil {
		return fmt.Errorf("账号不存在: %s", id)
	}
	a.Disabled = disabled
	p.dirty = true
	return p.snapshotLocked()
}

// ResetState 重置状态：清冷却/连续失败/auth_invalid/last_error（面板「重置状态」按钮）。
func (p *Pool) ResetState(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.accounts[id]
	if a == nil {
		return fmt.Errorf("账号不存在: %s", id)
	}
	a.CooldownUntil = time.Time{}
	a.ConsecFail = 0
	a.AuthInvalid = false
	a.LastError = ""
	p.dirty = true
	return p.snapshotLocked()
}

// ── 结果记账（路由层调用）─────────────────────────────────────────────────────

// RecordSuccess 成功记账：窗口估计累加 usage、清连续失败。
func (p *Pool) RecordSuccess(a *Account, usage map[string]any) {
	if a == nil {
		return
	}
	p.mu.Lock()
	now := p.now()
	a.rolloverWindow(now)
	a.WindowUsed += asInt(usage["prompt_tokens"]) + asInt(usage["completion_tokens"])
	a.ConsecFail = 0
	a.TotalOK++
	p.dirty = true
	p.mu.Unlock()
}

// RecordFailure 失败记账与冷却。
//
//	kind="auth"     401 且刷新失败 → auth_invalid + 6h
//	kind="429"      上游 429 → 60s
//	kind="quota"    伪回复配额耗尽 → reset 换算秒数（缺省 5min），窗口记满
//	kind="overload" 伪回复负载过高 → 60s
//	kind="net"      5xx/超时/断连 → 连续失败 >=3 次起 5min×2^n（封顶 1h）
//	kind=""         其它（4xx 客户端错）只计数不冷却
func (p *Pool) RecordFailure(a *Account, kind, detail string, retryAfterSec int) {
	if a == nil {
		return
	}
	p.mu.Lock()
	now := p.now()
	a.TotalFail++
	a.LastError = detail
	switch kind {
	case "auth":
		a.AuthInvalid = true
		a.CooldownUntil = now.Add(cooldownAuth)
	case "429":
		if retryAfterSec <= 0 {
			retryAfterSec = int(cooldown429.Seconds())
		}
		a.CooldownUntil = now.Add(time.Duration(retryAfterSec) * time.Second)
	case "quota":
		if retryAfterSec <= 0 {
			retryAfterSec = int(cooldownQuota.Seconds())
		}
		a.CooldownUntil = now.Add(time.Duration(retryAfterSec) * time.Second)
		if a.WindowLimit > 0 {
			a.WindowUsed = a.WindowLimit // 打满，打分直接出局
		}
	case "overload":
		a.CooldownUntil = now.Add(cooldown429)
	case "net":
		a.ConsecFail++
		if a.ConsecFail >= netFailCooldown {
			shift := a.ConsecFail - netFailCooldown
			d := cooldownNet << shift
			if d > cooldownNetMax {
				d = cooldownNetMax
			}
			a.CooldownUntil = now.Add(d)
		}
	}
	p.dirty = true
	p.mu.Unlock()
}

// RecordPseudo 伪回复命中（quota_exhausted / overloaded），retryAfterSec 由
// RetryAfterSeconds(p.Reset) 换算好传入。
func (p *Pool) RecordPseudo(a *Account, kind string, retryAfterSec int) {
	if kind == "quota_exhausted" {
		p.RecordFailure(a, "quota", "配额窗口耗尽（伪回复）", retryAfterSec)
		return
	}
	p.RecordFailure(a, "overload", "上游负载过高（伪回复）", retryAfterSec)
}

// OnSendError upstream.SendError 分类记账（路由层统一入口）。
func (p *Pool) OnSendError(a *Account, status int, detail string) {
	switch {
	case status == 401:
		p.RecordFailure(a, "auth", detail, 0)
	case status == 429:
		p.RecordFailure(a, "429", detail, 0)
	case status >= 500:
		p.RecordFailure(a, "net", detail, 0)
	default:
		p.RecordFailure(a, "", detail, 0)
	}
}

// markDirty 外部状态变迁（每日循环刷新后）调一次，快照循环会落盘。
func (p *Pool) markDirty() {
	p.mu.Lock()
	p.dirty = true
	p.mu.Unlock()
}

// ── 小工具 ───────────────────────────────────────────────────────────────────

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asInt(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	case string:
		var n int64
		_, _ = fmt.Sscan(x, &n)
		return n
	}
	return 0
}

// parseReset 解析上游 reset_at（RFC3339 或 "2026-11-03T03:00:28" 本地时）。
func parseReset(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.ParseInLocation("2006-01-02T15:04:05", s, time.Local); err == nil {
		return t
	}
	return time.Time{}
}
