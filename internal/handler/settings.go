// 面板设置（P4）：StateDir/settings.json，0600 原子写。
//
// API 鉴权密钥优先级（显式可解释，面板如实显示来源）：
//
//	settings.api_key 显式设置  >  环境变量 API_KEY  >  未启用
//
// 清除语义：清除面板值 = 回落到环境变量（env 有值仍鉴权），不是关闭鉴权。
// 要完全关闭需显式 auth_disabled=true（单独的「禁用鉴权」动作，UI 带风险提示）——
// 与「清除」分开是因为两者意图不同：清除是「我不想要面板这个覆盖了」，
// 禁用是「就算 env 有 key 也别拦」，混在一个动作里必然误伤一边。
package handler

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

// Settings 面板可改的运行时设置。
type Settings struct {
	APIKey       string `json:"api_key,omitempty"`        // 面板显式设置的密钥
	AuthDisabled bool   `json:"auth_disabled,omitempty"`  // 显式关闭鉴权（压过 env）
	// 面板登录保护（P5）：PBKDF2 哈希（绝不存明文）+ 会话签名密钥。
	PanelPasswordHash string `json:"panel_password,omitempty"`
	SessionSecret     string `json:"session_secret,omitempty"`
}

// settingsPath 设置文件路径。
func settingsPath(stateDir string) string { return filepath.Join(stateDir, "settings.json") }

// loadSettings 读设置；缺失 → 零值（正常），损坏 → 告警后按空设置继续
// （与 pool-state 同一容错哲学：设置文件不是凭据，坏了不致命）。
func loadSettings(stateDir string, logf func(string)) *Settings {
	s := &Settings{}
	raw, err := os.ReadFile(settingsPath(stateDir))
	if err != nil {
		return s // 缺失 = 首次运行
	}
	if json.Unmarshal(raw, s) != nil {
		if logf != nil {
			logf("settings.json 损坏，按空设置继续")
		}
		return &Settings{}
	}
	return s
}

// save 0600 原子写（tmp + rename，与凭据文件同规格）。
func (s *Settings) save(stateDir string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	tmp := settingsPath(stateDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, settingsPath(stateDir))
}

// ── 密钥校验 / 掩码 / 生成 ────────────────────────────────────────────────────

const (
	minAPIKeyLen = 8
	maxAPIKeyLen = 128
)

// validateAPIKey 基本校验：长度上下限、可见 ASCII、纯空白拒绝。
func validateAPIKey(key string) error {
	if strings.TrimSpace(key) == "" {
		return errors.New("密钥不能为空白")
	}
	if len(key) < minAPIKeyLen {
		return fmt.Errorf("密钥太短（至少 %d 字符）", minAPIKeyLen)
	}
	if len(key) > maxAPIKeyLen {
		return fmt.Errorf("密钥太长（至多 %d 字符）", maxAPIKeyLen)
	}
	for _, c := range key {
		if c < 0x21 || c > 0x7e {
			return errors.New("密钥只能包含可见 ASCII 字符（不含空格）")
		}
	}
	return nil
}

// maskKey 掩码显示：前后各 4 位，中间省略；过短则全掩。
func maskKey(key string) string {
	if key == "" {
		return ""
	}
	if len(key) <= 8 {
		return "••••••••"
	}
	return key[:4] + "…" + key[len(key)-4:]
}

// genKeyAlphabet base62（生成密钥字符集）。
const genKeyAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// genAPIKey 一键生成 32 位强随机密钥（crypto/rand，base62）。
func genAPIKey() string {
	var b strings.Builder
	b.Grow(32)
	max := big.NewInt(int64(len(genKeyAlphabet)))
	for b.Len() < 32 {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			// crypto/rand 失败几乎不可能；退化为固定字符也不泄露弱熵
			continue
		}
		b.WriteByte(genKeyAlphabet[n.Int64()])
	}
	return b.String()
}
