// SPDX-License-Identifier: BUSL-1.1

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

func TestArtifactMutationWatchObservesPublishedDirectoryNotCompilerStaging(t *testing.T) {
	staging := t.TempDir()
	published := t.TempDir()
	stagedPath := filepath.Join(staging, "trstctl")
	publishedPath := filepath.Join(published, "trstctl")
	if err := os.WriteFile(stagedPath, []byte("verified compiler output"), 0o700); err != nil { // #nosec G306 -- private test fixture (CWE-276)
		t.Fatal(err)
	}
	if err := publishShippedExecutable(stagedPath, publishedPath); err != nil {
		t.Fatal(err)
	}
	stagedInfo, err := os.Stat(stagedPath)
	if err != nil {
		t.Fatal(err)
	}
	publishedInfo, err := os.Stat(publishedPath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(stagedInfo, publishedInfo) {
		t.Fatal("published executable reused the compiler-output inode")
	}
	if publishedInfo.Mode().Perm() != 0o500 {
		t.Fatalf("published executable mode = %04o, want 0500", publishedInfo.Mode().Perm())
	}

	watch, err := newArtifactMutationWatch(published)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = watch.Close() }()
	if err := os.WriteFile(stagedPath, []byte("late compiler activity"), 0o700); err != nil { // #nosec G306 -- private test fixture (CWE-276)
		t.Fatal(err)
	}
	if err := watch.AssertQuiet(); err != nil {
		t.Fatalf("compiler staging activity reached the execution-directory watch: %v", err)
	}
	if err := os.Chmod(publishedPath, 0o700); err != nil { // #nosec G302 -- adversarial mutation fixture (CWE-276)
		t.Fatal(err)
	}
	if err := watch.AssertQuiet(); err == nil || !strings.Contains(err.Error(), "trstctl[ATTRIB]") {
		t.Fatalf("published executable mutation evidence = %v, want exact ATTRIB event", err)
	}
}
