// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package sshkrl

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// Owner decision 2026-11-02 (item 2g g), proven on windows-latest: Apply's
// atomic KRL update needs Unix file locking, so on Windows it refuses cleanly
// and leaves the installed list and its rollback directory untouched. Windows
// ships OpenSSH Server too; Windows KRL apply is what comes next.
func TestApplyRefusesOnWindowsAndLeavesTheTargetUnchanged(t *testing.T) {
	cfg, checks, old, next := setupInstaller(t)
	_, err := Apply(context.Background(), cfg, next, crypto.SHA256Hex(next))
	if err == nil || !strings.Contains(err.Error(), "Windows is not yet supported") {
		t.Fatalf("Apply on Windows = %v, want a clean refusal", err)
	}
	after, readErr := os.ReadFile(cfg.TargetPath)
	if readErr != nil || !bytes.Equal(after, old) {
		t.Fatalf("the refused Apply changed the installed list: %v", readErr)
	}
	if _, statErr := os.Stat(cfg.RollbackDir); !os.IsNotExist(statErr) {
		t.Fatalf("the refused Apply created the rollback directory: %v", statErr)
	}
	if checks.reload != 0 || checks.health != 0 {
		t.Fatalf("the refused Apply reloaded sshd: reload=%d health=%d", checks.reload, checks.health)
	}
}
