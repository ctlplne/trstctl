// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package safefile_test

import (
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/safefile"
)

func TestScanRootsChecksTheResolvedDirectory(t *testing.T) {
	directory := t.TempDir()
	for _, target := range []string{directory, os.TempDir()} {
		t.Run(filepath.Base(target), func(t *testing.T) {
			alias := filepath.Join(t.TempDir(), "mounted")
			if err := os.Symlink(target, alias); err != nil {
				t.Fatal(err)
			}
			roots, err := safefile.ScanRoots([]string{alias})
			if target == os.TempDir() {
				if err == nil || len(roots) != 0 {
					t.Fatal("scan roots admitted shared process temporary storage through an alias")
				}
				return
			}
			resolved, resolveErr := filepath.EvalSymlinks(target)
			if err != nil || resolveErr != nil || len(roots) != 1 || roots[0] != resolved {
				t.Fatalf("scan root did not retain the isolated mounted directory: %v, %v", err, resolveErr)
			}
		})
	}
}

// CR-090. Filesystem identity also anchors the temporary-directory exclusion
// when two spellings resolve to the same directory on a case-folding volume.
func TestScanRootsRejectsAnAlternateSpellingOfProcessTemp(t *testing.T) {
	parent := t.TempDir()
	temp := filepath.Join(parent, "Staging")
	if err := os.Mkdir(temp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", temp)
	alias := filepath.Join(parent, "staging")
	if _, err := os.Stat(alias); os.IsNotExist(err) {
		// This spelling names no directory on a case-sensitive volume.
		if _, err := safefile.ScanRoots([]string{alias}); err == nil {
			t.Fatal("admitted a directory that does not exist")
		}
		return
	} else if err != nil {
		t.Fatal(err)
	}
	if _, err := safefile.ScanRoots([]string{alias}); err == nil {
		t.Fatal("admitted process temporary storage through an alternate spelling")
	}
}
