package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRun_BackupRequiresExternalDatastores: trstctl --backup against the default
// (embedded) NATS fails fast, like serving does — a real backup targets the
// external event store an operator actually backs up, so a bundled-mode backup is
// rejected before it writes anything.
func TestRun_BackupRequiresExternalDatastores(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.jsonl")
	err := run(context.Background(), []string{"--backup=" + path}, emptyEnv, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("trstctl --backup with embedded NATS should fail fast (external datastores required)")
	}
}

func TestDRScriptsInvokeFullBackupRestoreFlags(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	fake := filepath.Join(dir, "trstctl-fake")
	if err := os.WriteFile(fake, []byte("#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$TRSTCTL_FAKE_LOG\"\n"), 0o700); err != nil {
		t.Fatalf("write fake trstctl: %v", err)
	}

	backupDir := filepath.Join(dir, "artifact")
	for _, script := range []string{
		filepath.Join("..", "..", "scripts", "dr", "full-backup.sh"),
		filepath.Join("..", "..", "scripts", "dr", "full-restore.sh"),
	} {
		cmd := exec.Command("bash", script, backupDir)
		cmd.Env = append(os.Environ(), "TRSTCTL_BIN="+fake, "TRSTCTL_FAKE_LOG="+logPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s failed: %v\n%s", script, err, out)
		}
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake trstctl log: %v", err)
	}
	got := string(calls)
	for _, want := range []string{"--full-backup-dir=" + backupDir, "--full-restore-dir=" + backupDir} {
		if !strings.Contains(got, want) {
			t.Fatalf("DR scripts invoked:\n%s\nmissing %q", got, want)
		}
	}
}
