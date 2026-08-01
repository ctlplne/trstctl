// SPDX-License-Identifier: MPL-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLocalOpsExecutesOnlyExactOperatorProfile(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	ops, err := NewLocalOps(LocalOpsConfig{
		AllowedRoots: []string{root},
		Actions: []LocalAction{{
			LogicalName: "reload",
			LogicalArgs: []string{"--exact"},
			Command:     executable,
			Args:        []string{"-test.run=^TestLocalOpsCommandHelper$", "-test.count=1"},
			Timeout:     5 * time.Second,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	executor, ok := ops.(ContextExecutor)
	if !ok {
		t.Fatal("local ops does not expose cancellation-aware execution")
	}
	if err := executor.ExecContext(context.Background(), "reload", []string{"--wrong"}); err == nil || !strings.Contains(err.Error(), "does not match operator profile") {
		t.Fatalf("mismatched logical argv error = %v", err)
	}
	if err := executor.ExecContext(context.Background(), "unknown", nil); err == nil || !strings.Contains(err.Error(), "not operator-approved") {
		t.Fatalf("unknown action error = %v", err)
	}
	if err := executor.ExecContext(context.Background(), "reload", []string{"--exact"}); err != nil {
		t.Fatalf("exact operator profile: %v", err)
	}
}

func TestLocalOpsRejectsShellAndSymlinkExecutables(t *testing.T) {
	root := t.TempDir()
	shell := "/bin/sh"
	if runtime.GOOS == "windows" {
		t.Skip("local connector actions require Unix filesystem semantics")
	}
	if _, err := os.Stat(shell); err != nil {
		t.Fatalf("stat %s: %v", shell, err)
	}
	if _, err := NewLocalOps(LocalOpsConfig{
		AllowedRoots: []string{root},
		Actions:      []LocalAction{{LogicalName: "reload", Command: shell}},
	}); err == nil || !strings.Contains(err.Error(), "unpinned shell interpreter") {
		t.Fatalf("shell action error = %v", err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "reload-command")
	if err := os.Symlink(executable, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalOps(LocalOpsConfig{
		AllowedRoots: []string{root},
		Actions:      []LocalAction{{LogicalName: "reload", Command: symlink}},
	}); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink action error = %v", err)
	}
}

func TestLocalOpsPowerShellRequiresFullyPinnedOperatorArgv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local connector action fixture uses Unix executable modes")
	}
	root := t.TempDir()
	pwsh := filepath.Join(root, "pwsh")
	if err := os.WriteFile(pwsh, []byte("fixture"), 0o700); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	if _, err := NewLocalOps(LocalOpsConfig{
		AllowedRoots: []string{root},
		Actions:      []LocalAction{{LogicalName: "powershell", Command: pwsh, PassArgs: true}},
	}); err == nil || !strings.Contains(err.Error(), "unpinned shell interpreter") {
		t.Fatalf("forwarded PowerShell argv error = %v", err)
	}
	if _, err := NewLocalOps(LocalOpsConfig{
		AllowedRoots: []string{root},
		Actions: []LocalAction{{
			LogicalName: "powershell",
			LogicalArgs: []string{"-NoProfile", "-NonInteractive", "-Command", "Import-PfxCertificate -FilePath C:\\fixed\\identity.pfx"},
			Command:     pwsh,
			Args:        []string{"-NoProfile", "-NonInteractive", "-Command", "Import-PfxCertificate -FilePath C:\\fixed\\identity.pfx"},
		}},
	}); err != nil {
		t.Fatalf("fully pinned PowerShell profile: %v", err)
	}
}

func TestLocalOpsCommandHelper(t *testing.T) {}
