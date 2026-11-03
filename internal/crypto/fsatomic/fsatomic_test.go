// SPDX-License-Identifier: BUSL-1.1

package fsatomic

import (
	"os"
	"path/filepath"
	"testing"
)

// SyncDirectory succeeds on a real directory on every OS (on Windows it has
// nothing to flush) and reports a missing one where it can open directories.
func TestSyncDirectoryFlushesARealDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SyncDirectory(dir); err != nil {
		t.Fatalf("sync %s: %v", dir, err)
	}
}
