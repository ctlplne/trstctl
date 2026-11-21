// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"os"
	"path/filepath"
	"testing"
)

// regularHostCommand resolves an OS command used only by test host profiles.
// Some distributions make /usr/bin/true and /usr/bin/touch symlinks, while
// production host authority correctly refuses a symlink at the command path.
func regularHostCommand(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		t.Fatalf("test command %q does not resolve to an executable regular file: %v", path, err)
	}
	return resolved
}

func TestRegularHostCommandResolvesOnlyFixtureSymlinks(t *testing.T) {
	want := regularHostCommand(t, "/usr/bin/true")
	link := filepath.Join(t.TempDir(), "true-link")
	if err := os.Symlink(want, link); err != nil {
		t.Fatal(err)
	}
	if got := regularHostCommand(t, link); got != want {
		t.Fatalf("test symlink resolved to %q, want %q", got, want)
	}
}
