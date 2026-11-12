// SPDX-License-Identifier: BUSL-1.1

package decoy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Q6-O1: a decoy is planted only where no file is, as an SSH private key the
// agent generated, mode 0600; planting again keeps it; an existing file is
// refused; the agent's scans see it as a decoy.
func TestPlantWritesADecoyKeyOnlyWhereNoFileIsQ6O1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519_backup")
	state := filepath.Join(dir, "state", "decoys.json")
	decoys, err := Plant([]string{path}, state)
	if err != nil || len(decoys) != 1 || !strings.HasPrefix(decoys[0].PublicKey, "ssh-ed25519 ") {
		t.Fatalf("Plant = %+v, %v", decoys, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("decoy file = %v, %v", info, err)
	}
	body, err := os.ReadFile(path) // #nosec G304 -- the test's own decoy (CWE-22)
	if err != nil || !strings.HasPrefix(string(body), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatalf("decoy body is not an OpenSSH private key (%v)", err)
	}
	if !Is(path) || Is(filepath.Join(dir, "other")) {
		t.Fatal("the decoy registry does not name exactly the decoy")
	}
	again, err := Plant([]string{path}, state)
	if err != nil || len(again) != 1 || again[0].PublicKey != decoys[0].PublicKey {
		t.Fatalf("planting again = %+v, %v; want the same decoy kept", again, err)
	}
	real := filepath.Join(dir, "id_rsa")
	if err := os.WriteFile(real, []byte("a real key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Plant([]string{real}, state); !errors.Is(err, ErrExists) {
		t.Fatalf("an existing file: %v; want ErrExists", err)
	}
	if b, _ := os.ReadFile(real); string(b) != "a real key" { // #nosec G304 -- the test's own file (CWE-22)
		t.Fatal("a real file was changed")
	}
	if _, err := Plant([]string{"relative/path"}, state); err == nil {
		t.Fatal("a relative path was planted")
	}
}
