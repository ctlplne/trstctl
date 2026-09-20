// SPDX-License-Identifier: BUSL-1.1

package transit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

// TestSaveSyncsFileThenDirectory is the crash-safety guard for AUD-201
// follow-up B4/V5. The checkpoint wrote WriteFile+Rename with no f.Sync and no
// directory fsync — unlike the signer keystore's own pattern — so a power loss
// could make the rename durable BEFORE the data, committing an empty or torn
// sealed file. Load then fails closed and the control plane refuses to start
// until an operator deletes the file, at which point the keys are gone anyway.
// Real power loss cannot be unit-tested, so the syncs are package seams and
// this test proves the write path issues both, in the only order that is
// crash-safe: file contents first, directory entry after the rename.
func TestSaveSyncsFileThenDirectory(t *testing.T) {
	ctx := context.Background()
	var order []string
	origFile, origDir := syncKeyringFile, syncKeyringDir
	t.Cleanup(func() { syncKeyringFile, syncKeyringDir = origFile, origDir })
	syncKeyringFile = func(f *os.File) error {
		order = append(order, "file")
		return f.Sync()
	}
	syncKeyringDir = func(path string) error {
		order = append(order, "dir")
		return origDir(path)
	}

	svc := &Service{audit: auditsink.Nop{}}
	if _, err := svc.CreateKey(ctx, "t1", "k", KindAEAD); err != nil {
		t.Fatal(err)
	}
	if err := NewStore(t.TempDir(), testWrapper(t)).Save(svc); err != nil {
		t.Fatalf("save: %v", err)
	}
	if strings.Join(order, ",") != "file,dir" {
		t.Fatalf("sync order = %v, want [file dir]: the data must be durable before the rename and the directory entry after it", order)
	}
}

// TestSaveFileSyncFailureLeavesNoTempAndFailsClosed pins the error path: a
// failed data fsync must fail the checkpoint (the mutation rolls back, B3) and
// must not leave the staging file behind.
func TestSaveFileSyncFailureLeavesNoTempAndFailsClosed(t *testing.T) {
	ctx := context.Background()
	origFile := syncKeyringFile
	t.Cleanup(func() { syncKeyringFile = origFile })
	syncKeyringFile = func(*os.File) error { return errors.New("sync refused") }

	dir := t.TempDir()
	svc := &Service{audit: auditsink.Nop{}}
	store := NewStore(dir, testWrapper(t))
	svc.SetPersist(func() error { return store.Save(svc) })

	if _, err := svc.CreateKey(ctx, "t1", "k", KindAEAD); err == nil {
		t.Fatal("CreateKey succeeded although the keyring data could not be made durable")
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, transitStateFile+".tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("failed sync left staging files behind: %v", leftovers)
	}
}
