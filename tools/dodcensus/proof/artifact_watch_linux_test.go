// SPDX-License-Identifier: MPL-2.0

//go:build linux

package proof

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArtifactMutationWatchRejectsSwapRestoreInputs(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "trstctl-signer")
	if err := os.WriteFile(path, []byte("exact signer"), 0o500); err != nil {
		t.Fatal(err)
	}
	watch, err := newArtifactMutationWatch(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = watch.Close() }()
	if err := watch.AssertQuiet(); err != nil {
		t.Fatalf("new mutation watch is not quiet: %v", err)
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("foreign signer"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".saved", path); err != nil {
		t.Fatal(err)
	}
	if err := watch.AssertQuiet(); err == nil {
		t.Fatal("swap-then-restore mutation was not observed")
	} else if !strings.Contains(err.Error(), "trstctl-signer[MOVED_FROM]") {
		t.Fatalf("mutation evidence = %q, want exact affected artifact and operation", err)
	}
}
