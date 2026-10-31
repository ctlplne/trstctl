// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventprivacy"
)

// The original configured source and
// actual child signer are the existing native fixture; only this capture's
// custody configuration is absent. Keyless ciphertext export remains supported.
func TestEventProtectionFullBackupRefusesMissingCustodyForIndependentSQL(t *testing.T) {
	info := eventProtectionPostgresBackupFixture(t, time.Hour)
	originalPath := filepath.Join(info.Directory, "postgres-state.jsonl")
	original, err := os.ReadFile(originalPath) // #nosec G304 -- exact artifact in this test's owned fixture (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	digest := crypto.SHA256Hex(original)
	cfg := *info.Config
	cfg.Privacy.EventProtection.KeyDirectory = ""
	target := filepath.Join(cfg.Backup.Directory, "missing-custody")
	if _, err := RunFullBackup(t.Context(), &cfg, target); err == nil {
		t.Error("activated source without custody completed an independent SQL backup")
		raw, readErr := os.ReadFile(filepath.Join(target, "postgres-state.jsonl")) // #nosec G304 -- exact artifact in this test's owned fixture (CWE-22)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if bytes.Contains(raw, []byte("protected-sql-subject@example.invalid")) {
			t.Error("unavailable custody fell back to plaintext independent SQL")
		}
	} else {
		if !errors.Is(err, eventprivacy.ErrSource) {
			t.Fatalf("capture failed outside retained-custody authority: %v", err)
		}
		t.Logf("missing-custody capture refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, backup.FullManifestName)); !errors.Is(err, os.ErrNotExist) {
		t.Error("unavailable custody left a complete backup manifest")
	}
	after, err := os.ReadFile(originalPath) // #nosec G304 -- exact original artifact in this test's owned fixture (CWE-22)
	if err != nil || crypto.SHA256Hex(after) != digest {
		t.Fatal("failed capture rewrote original protected artifact")
	}
}
