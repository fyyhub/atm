// config 包单元测试。
package config

import (
	"path/filepath"
	"testing"
)

// STATE_DIR 环境变量覆盖状态目录（部署把状态指到可写卷）。
func TestLoad_StateDirEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("STATE_DIR", dir)
	c := Load()
	if c.StateDir != dir {
		t.Fatalf("StateDir=%q 期望 %q", c.StateDir, dir)
	}
	if c.StateFilePath("accounts") != filepath.Join(dir, "accounts") {
		t.Fatal("StateFilePath 应跟随 STATE_DIR")
	}
}

// STATE_DIR 为空/空白时回落 exe 目录（不崩）。
func TestLoad_StateDirEmpty(t *testing.T) {
	t.Setenv("STATE_DIR", "   ")
	c := Load()
	if c.StateDir == "" {
		t.Fatal("空 STATE_DIR 不应清空 StateDir")
	}
}
