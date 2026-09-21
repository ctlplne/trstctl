// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSignerSocketDirRefusesASymlink is the regression guard for the socket
// directory that was trusted without inspection.
//
// listenUDS called os.MkdirAll then os.Chmod and believed both. MkdirAll is a
// no-op when the path exists, and os.Chmod FOLLOWS SYMLINKS — so a pre-existing
// symlink at the socket directory path meant the signer chmod'd an attacker's
// directory to 0700 and then created its socket inside it. The socket itself was
// always Lstat-checked; the directory holding it was not, and that is the AN-4
// isolated signer's front door.
func TestSignerSocketDirRefusesASymlink(t *testing.T) {
	root := t.TempDir()
	elsewhere := filepath.Join(root, "attacker-controlled")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil { // #nosec G301 -- the loose mode IS the attack fixture this test defends against (CWE-276)
		t.Fatal(err)
	}
	link := filepath.Join(root, "run")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Skipf("symlinks unavailable on this filesystem: %v", err)
	}

	err := enforceExactSocketDirMode(link, 0o700)
	if err == nil {
		t.Fatal("the signer accepted a symlinked socket directory; its socket would be created " +
			"inside a directory the process does not control")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error should name the symlink so an operator can act on it, got: %v", err)
	}

	// The link target must be left alone — following it to chmod is the bug.
	info, statErr := os.Stat(elsewhere)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("the symlink target was chmod'd to %04o; the check followed the link", info.Mode().Perm())
	}
}

// TestSignerSocketDirTightensAWidePreexistingDir keeps the behavior that
// mattered: a real directory that already exists with loose permissions is
// narrowed to 0700 rather than rejected.
func TestSignerSocketDirTightensAWidePreexistingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.MkdirAll(dir, 0o777); err != nil { // #nosec G301 -- the wide mode IS the precondition this test proves gets narrowed (CWE-276)
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil { // #nosec G302 -- deliberately widened so enforceExactSocketDirMode has something to tighten (CWE-276)
		t.Fatal(err)
	}
	if err := enforceExactSocketDirMode(dir, 0o700); err != nil {
		t.Fatalf("a real, writable socket dir was rejected: %v", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("socket dir mode = %04o, want 0700; a world-writable dir was left as-is", info.Mode().Perm())
	}
}

// TestSignerSocketDirRefusesANonDirectory covers the last shape: a plain file
// sitting where the directory should be.
func TestSignerSocketDirRefusesANonDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run")
	if err := os.WriteFile(path, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := enforceExactSocketDirMode(path, 0o700); err == nil {
		t.Fatal("a regular file was accepted as the signer socket directory")
	}
}
