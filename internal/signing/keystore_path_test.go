// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfinedKeystorePathRejectsEscape(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "issuing-ca.key")
	got, err := confinedKeystorePath(root, inside)
	if err != nil {
		t.Fatalf("confinedKeystorePath(inside): %v", err)
	}
	if got != inside {
		t.Fatalf("confined path = %q, want %q", got, inside)
	}

	outside := filepath.Join(filepath.Dir(root), "outside.key")
	if _, err := confinedKeystorePath(root, outside); err == nil {
		t.Fatal("confinedKeystorePath accepted a sibling outside the keystore")
	}
}

func TestStagedSaveDiscardCannotRemoveOutsideKeystore(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "do-not-remove")
	if err := os.WriteFile(outside, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}

	(&stagedSave{ks: &KeyStore{dir: root}, tmpPath: outside}).discard()
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("discard touched a path outside the keystore: %v", err)
	}
}

func TestStagedSaveCommitRejectsOutsideSource(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "staged.key")
	if err := os.WriteFile(outside, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}

	staged := &stagedSave{
		ks:        &KeyStore{dir: root},
		handle:    "issuing-ca",
		tmpPath:   outside,
		finalPath: filepath.Join(root, "issuing-ca.key"),
	}
	if err := staged.commit(); err == nil {
		t.Fatal("commit accepted a staged source outside the keystore")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("rejected commit touched the outside source: %v", err)
	}
}
