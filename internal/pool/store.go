// 账号池落盘与迁移：
//
//	<StateDir>/accounts/<id>.json   每账号凭据（lanes.SaveAuthJSON 原子写，0600）
//	<StateDir>/pool-state.json      池状态快照（调度/健康字段，0600 原子写）
//
// 快照时机：状态变迁置 dirty，60s 快照循环落盘；增删账号/禁用/重置立即落盘。
// pool-state.json 损坏只丢统计：凭据文件才是事实源，重建空状态继续跑（开放问题 9）。
package pool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"atomcode2api/internal/lanes"
)

func accountsDir(stateDir string) string  { return filepath.Join(stateDir, "accounts") }
func stateFilePath(stateDir string) string { return filepath.Join(stateDir, "pool-state.json") }

// placeholderTOML 池账号 Credential 的 toml 路径占位（永不存在的文件）。
//
// lanes.NewCredential(path="") 会回落到 ~/.atomcode/auth.toml，其 mtime 与池账号
// 的 jsonPath 无关，会让 reloadIfChanged 每次 Headers() 都空转重读一次文件；
// 指到池目录下一个不存在的路径后 modTime 直接报错早退，零开销且语义正确——
// 池账号凭据由池自管，不跟随官方 CLI 热加载。
func (p *Pool) placeholderTOML() string { return filepath.Join(p.dir, "pool-managed.toml") }

// materialize 把一份凭据落成 accounts/<id>.json 并装载为 Account（未注册进池）。
func (p *Pool) materialize(sc lanes.SaveCreds) (*Account, error) {
	id := sc.User.ID
	if !sc.HasUser || id == "" {
		sum := sha256.Sum256([]byte(sc.RefreshToken))
		id = "acct_" + hex.EncodeToString(sum[:])[:12]
	}
	path := filepath.Join(p.dir, id+".json")
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return nil, err
	}
	if err := lanes.SaveAuthJSON(path, sc); err != nil {
		return nil, fmt.Errorf("凭据落盘失败: %w", err)
	}
	cred, err := lanes.NewCredential(p.placeholderTOML(), path, p.log)
	if err != nil {
		return nil, fmt.Errorf("凭据装载失败: %w", err)
	}
	return &Account{
		ID:          id,
		Username:    sc.User.Username,
		Cred:        cred,
		AddedAt:     p.now(),
		NextClaimAt: p.now(), // 录入即安排尽快领取（P3 修复；错峰由 claimDue 保证）
	}, nil
}

// AddCredential 注册一个已装载的 Credential（SetCred 兼容路径：测试夹具与
// /login/poll 用）。快照凭据落池目录后换用池内文件，同 id 重复注册视为替换。
func (p *Pool) AddCredential(cred *lanes.Credential) (*Account, error) {
	now := p.now().Unix()
	sc := lanes.SaveCreds{
		AccessToken:  cred.AccessToken(),
		TokenType:    "Bearer",
		RefreshToken: cred.RefreshToken(),
		CreatedAt:    now,
		ExpiresIn:    cred.ExpiresAt() - now,
		User:         lanes.User{ID: cred.UserID(), Username: cred.Username()},
		HasUser:      cred.UserID() != "",
	}
	p.mu.Lock()
	if a := p.accounts[cred.UserID()]; a != nil && cred.UserID() != "" {
		// 同 id 替换（重新登录同账号）：换新凭据对象并重落盘
		a.Cred = cred
		p.dirty = true
		_ = p.snapshotLocked()
		p.mu.Unlock()
		return a, nil
	}
	p.mu.Unlock()
	a, err := p.materialize(sc)
	if err != nil {
		return nil, err
	}
	// 保留原 Credential 的文件链（登录流刚写出的 auth.json），
	// 池内副本作重启后的装载源——两条文件内容此刻一致，RT 轮换只走原对象，
	// 下一次重启从池副本装载，语义收敛为单源。
	a.Cred = cred
	p.mu.Lock()
	p.accounts[a.ID] = a
	p.order = append(p.order, a.ID)
	p.dirty = true
	err = p.snapshotLocked()
	p.mu.Unlock()
	return a, err
}

// removeCredFile 删除账号凭据文件（尽力而为）。
func (p *Pool) removeCredFile(a *Account) error {
	return os.Remove(filepath.Join(p.dir, a.ID+".json"))
}

// ── 装载 ─────────────────────────────────────────────────────────────────────

// load 启动装载：accounts/*.json → 账号；pool-state.json → 合并调度状态。
func (p *Pool) load() {
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		if !os.IsNotExist(err) {
			p.log.Warn("accounts 目录不可读，退化为内存池", slog.String("err", err.Error()))
		}
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(p.dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			p.log.Warn("账号凭据读取失败，跳过", slog.String("file", e.Name()), slog.String("err", err.Error()))
			continue
		}
		sc, err := lanes.ParseAuthJSON(raw)
		if err != nil {
			p.log.Warn("账号凭据解析失败，跳过", slog.String("file", e.Name()), slog.String("err", err.Error()))
			continue
		}
		cred, err := lanes.NewCredential(p.placeholderTOML(), path, p.log)
		if err != nil {
			p.log.Warn("账号凭据装载失败，跳过", slog.String("file", e.Name()), slog.String("err", err.Error()))
			continue
		}
		id := sc.User.ID
		if !sc.HasUser || id == "" {
			id = strings.TrimSuffix(e.Name(), ".json")
		}
		if _, dup := p.accounts[id]; dup {
			p.log.Warn("账号 id 重复，跳过后者", slog.String("file", e.Name()), slog.String("id", id))
			continue
		}
		p.accounts[id] = &Account{ID: id, Username: sc.User.Username, Cred: cred}
		p.order = append(p.order, id)
	}
	p.loadState()
	// 启动规整：无领取时刻的账号（旧 pool-state / 迁移导入）立即安排——
	// 对齐旧单账号「启动即领取」语义；错峰由 claimDue 保证。
	for _, a := range p.accounts {
		if a.NextClaimAt.IsZero() {
			a.NextClaimAt = p.now()
		}
	}
	if len(p.accounts) > 0 {
		p.log.Info("账号池已装载", slog.Int("accounts", len(p.accounts)))
	}
}

// ── pool-state.json ─────────────────────────────────────────────────────────

type accountState struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Plan          string `json:"plan,omitempty"`
	PlanExpiresAt string `json:"plan_expires_at,omitempty"`
	WindowUsed    int64  `json:"window_used"`
	WindowLimit   int64  `json:"window_limit"`
	WindowReset   int64  `json:"window_reset,omitempty"` // unix 秒
	CooldownUntil int64  `json:"cooldown_until,omitempty"`
	ConsecFail    int    `json:"consec_fail"`
	TotalOK       int64  `json:"total_ok"`
	TotalFail     int64  `json:"total_fail"`
	LastUsed      int64  `json:"last_used,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	AddedAt       int64  `json:"added_at"`
	Disabled      bool   `json:"disabled"`
	AuthInvalid   bool   `json:"auth_invalid"`
	NextClaimAt   int64  `json:"next_claim_at,omitempty"`
}

type poolState struct {
	Accounts []accountState `json:"accounts"`
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func timeOrZero(unix int64) time.Time {
	if unix <= 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0)
}

// snapshotLocked 池状态原子落盘（0600，tmp+rename）。调用方须持锁。
func (p *Pool) snapshotLocked() error {
	st := poolState{Accounts: make([]accountState, 0, len(p.order))}
	for _, id := range p.order {
		a := p.accounts[id]
		st.Accounts = append(st.Accounts, accountState{
			ID: a.ID, Username: a.Username,
			Plan: a.Plan, PlanExpiresAt: a.PlanExpiresAt,
			WindowUsed: a.WindowUsed, WindowLimit: a.WindowLimit,
			WindowReset:   unixOrZero(a.WindowReset),
			CooldownUntil: unixOrZero(a.CooldownUntil),
			ConsecFail:    a.ConsecFail, TotalOK: a.TotalOK, TotalFail: a.TotalFail,
			LastUsed: unixOrZero(a.LastUsed), LastError: a.LastError,
			AddedAt: unixOrZero(a.AddedAt), Disabled: a.Disabled, AuthInvalid: a.AuthInvalid,
			NextClaimAt: unixOrZero(a.NextClaimAt),
		})
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.statePath), 0o700); err != nil {
		return err
	}
	tmp := p.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p.statePath); err != nil {
		return err
	}
	p.dirty = false
	return nil
}

// loadState 合并 pool-state.json；损坏/缺失 → 告警后从空状态重建（开放问题 9）。
func (p *Pool) loadState() {
	raw, err := os.ReadFile(p.statePath)
	if err != nil {
		return // 缺失 = 首次运行，正常
	}
	var st poolState
	if json.Unmarshal(raw, &st) != nil {
		p.log.Warn("pool-state.json 损坏，丢弃统计从空状态重建",
			slog.String("path", p.statePath))
		return
	}
	for _, s := range st.Accounts {
		a := p.accounts[s.ID]
		if a == nil {
			continue // 凭据已删，状态自然失效
		}
		a.Username = orString(a.Username, s.Username)
		a.Plan, a.PlanExpiresAt = s.Plan, s.PlanExpiresAt
		a.WindowUsed, a.WindowLimit = s.WindowUsed, s.WindowLimit
		a.WindowReset = timeOrZero(s.WindowReset)
		a.CooldownUntil = timeOrZero(s.CooldownUntil)
		a.ConsecFail, a.TotalOK, a.TotalFail = s.ConsecFail, s.TotalOK, s.TotalFail
		a.LastUsed, a.LastError = timeOrZero(s.LastUsed), s.LastError
		a.AddedAt = timeOrZero(s.AddedAt)
		if a.AddedAt.IsZero() {
			a.AddedAt = p.now()
		}
		a.Disabled, a.AuthInvalid = s.Disabled, s.AuthInvalid
		a.NextClaimAt = timeOrZero(s.NextClaimAt)
	}
}

func orString(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ── 迁移 ─────────────────────────────────────────────────────────────────────

// MigrateLegacy 旧单账号凭据导入为池账号 #1（复制，原文件保留）。
// accounts 目录已有账号时跳过。优先 auth.json（独立 RT 链较新），其次 -auth
// 指定的/默认位置的 auth.toml。返回导入数量。
func (p *Pool) MigrateLegacy(authTOML, authJSON string) int {
	p.mu.RLock()
	n := len(p.accounts)
	p.mu.RUnlock()
	if n > 0 {
		return 0
	}
	if raw, err := os.ReadFile(authJSON); err == nil {
		if sc, perr := lanes.ParseAuthJSON(raw); perr == nil && sc.AccessToken != "" {
			if _, err := p.Add(sc, false); err == nil {
				p.log.Info("已迁移 auth.json 为池账号 #1", slog.String("from", authJSON))
				return 1
			} else {
				p.log.Warn("auth.json 迁移失败", slog.String("err", err.Error()))
			}
		}
	}
	if authTOML == "" {
		authTOML = lanes.AuthTOMLPath()
	}
	if raw, err := os.ReadFile(authTOML); err == nil {
		if sc, perr := lanes.ParseAuthTOML(raw); perr == nil && sc.AccessToken != "" {
			if _, err := p.Add(sc, false); err == nil {
				p.log.Info("已迁移 auth.toml 为池账号 #1", slog.String("from", authTOML))
				return 1
			} else {
				p.log.Warn("auth.toml 迁移失败", slog.String("err", err.Error()))
			}
		}
	}
	return 0
}

// ── 后台循环 ─────────────────────────────────────────────────────────────────

// SnapshotLoop 每 60s：dirty 状态落盘 + 扫描 import 目录（P2 定期导入）。
// 进程退出时的收尾丢失可接受——统计类状态，凭据本体不在其中。
func (p *Pool) SnapshotLoop(ctx context.Context) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.ScanImportDir()
			p.mu.Lock()
			if p.dirty {
				if err := p.snapshotLocked(); err != nil {
					p.log.Warn("pool-state 快照失败", slog.String("err", err.Error()))
				}
			}
			p.mu.Unlock()
		}
	}
}

// AutoLoop 领取与校准调度：
//   - 每 60s：claimDue——处理 NextClaimAt 到期的账号（新录入/重登/重试到期），
//     claim=false（ATOMCODE_AUTO_CLAIM=0）时跳过；
//   - 每 24h：refreshAll——auth_invalid 复活 + status-v2 校准（不再领取，
//     领取统一走 claimDue）。
// 错峰：账号间隔 claimStagger（默认 10s），不批量打控制面（开放问题 2）。
func (p *Pool) AutoLoop(ctx context.Context, claim bool) {
	tick := time.NewTicker(60 * time.Second)
	daily := time.NewTicker(24 * time.Hour)
	defer tick.Stop()
	defer daily.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if claim {
				p.claimDue(ctx)
			}
		case <-daily.C:
			p.refreshAll(ctx)
		}
	}
}

// claimDue 自动领取到期处理（P3 修复：账号录入即安排，不再等次日）。
//
// 成功/已持有 → 次日再领（NextClaimAt=+24h，对齐旧每日领取语义）；
// 失败 → LastError 记明确原因 + 30min 后重试，不静默。auth_invalid 账号
// 跳过（复活是 refreshAll 的职责）；disabled 跳过。错峰间隔 claimStagger。
func (p *Pool) claimDue(ctx context.Context) {
	if p.con == nil {
		return
	}
	now := p.now()
	var due []*Account
	p.mu.RLock()
	for _, a := range p.accounts {
		if a.Disabled || a.AuthInvalid || a.NextClaimAt.IsZero() {
			continue
		}
		if !now.Before(a.NextClaimAt) {
			due = append(due, a)
		}
	}
	p.mu.RUnlock()
	for i, a := range due {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(p.claimStagger):
			}
		}
		res := p.con.ClaimBest(a.Cred)
		p.refreshStatus(a) // 先校准套餐/窗口（成功会清 LastError），再落领取结论
		p.mu.Lock()
		if res.OK {
			a.NextClaimAt = p.now().Add(24 * time.Hour)
			p.log.Info("[claim] 池账号领取", slog.String("account", a.Username),
				slog.String("tier", res.Tier), slog.String("msg", res.Message))
		} else {
			a.NextClaimAt = p.now().Add(30 * time.Minute)
			a.LastError = "自动领取失败（30min 后重试）: " + res.Message
			p.log.Warn("[claim] 池账号领取失败，30min 后重试", slog.String("account", a.Username),
				slog.String("tier", res.Tier), slog.String("msg", res.Message))
		}
		p.dirty = true
		p.mu.Unlock()
	}
}

// refreshAll 逐账号错峰刷新：错峰 sleep 放在账号之间，首个账号立即执行。
// 只做复活与状态校准；领取归 claimDue（P3 起）。
func (p *Pool) refreshAll(ctx context.Context) {
	for i, a := range p.List() {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
		if a.Disabled {
			continue
		}
		// auth_invalid 每日复活：RT 试刷一次，成功回 ok 继续当日流程（P2）
		if a.AuthInvalid && !p.revive(a) {
			continue
		}
		p.refreshStatus(a)
	}
	p.markDirty()
	p.mu.Lock()
	if p.dirty {
		_ = p.snapshotLocked()
	}
	p.mu.Unlock()
}

// ── 目录扫描导入（P2）────────────────────────────────────────────────────────

// importDir 约定导入目录：StateDir/import/*.toml。
func (p *Pool) importDir() string { return filepath.Join(filepath.Dir(p.dir), "import") }

// ScanImportDir 扫描 import/ 导入账号：支持 .toml（auth.toml）与 .json
// （auth.json/池账号凭据，种子导入用）。导入成功（含查重命中=已存在）
// 的文件移入 imported/；解析失败的改名 .bad 防止每次扫描重复尝试。
// 录入不做网络校验（validate=false——无人值守路径，校验留给 AutoLoop 的
// 每日校准与首次请求的 401 刷新链路）。返回本次新导入数量。
func (p *Pool) ScanImportDir() int {
	dir := p.importDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0 // 目录不存在 = 常态
	}
	imported := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		var parse func([]byte) (lanes.SaveCreds, error)
		switch {
		case strings.HasSuffix(e.Name(), ".toml"):
			parse = lanes.ParseAuthTOML
		case strings.HasSuffix(e.Name(), ".json"):
			parse = lanes.ParseAuthJSON
		default:
			continue
		}
		src := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		sc, perr := parse(raw)
		if perr != nil || sc.AccessToken == "" {
			bad := src + ".bad"
			_ = os.Rename(src, bad)
			p.log.Warn("[import] 解析失败，已改名 .bad", slog.String("file", e.Name()))
			continue
		}
		_, aerr := p.Add(sc, false)
		if aerr != nil && !errors.Is(aerr, ErrDuplicate) {
			p.log.Warn("[import] 导入失败", slog.String("file", e.Name()), slog.String("err", aerr.Error()))
			continue // 留在原处，下轮再试（上限满等临时原因）
		}
		if errors.Is(aerr, ErrDuplicate) {
			p.log.Info("[import] 账号已存在（查重命中），跳过", slog.String("file", e.Name()))
		} else {
			imported++
			p.log.Info("[import] 导入成功", slog.String("file", e.Name()), slog.String("username", sc.User.Username))
		}
		dstDir := filepath.Join(dir, "imported")
		_ = os.MkdirAll(dstDir, 0o700)
		_ = os.Rename(src, filepath.Join(dstDir, e.Name()))
	}
	return imported
}
