//go:build unix

package destination_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agent/destination"
)

// TestFilesystemInstallSetsPermissions asserts the POSIX permission guarantee of
// the filesystem destination: the key is owner-only (0600), the certificate is
// world-readable (0644), and the directory that holds them is private (0700),
// independent of umask. These are POSIX semantics; on Windows, Go reports
// fixed mode bits and NTFS ACLs govern access, so the certificate-store
// destination is used there instead.
func TestFilesystemInstallSetsPermissions(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "tls") // deliberately not pre-created
	certPath := filepath.Join(sub, "workload.crt")
	keyPath := filepath.Join(sub, "workload.key")

	if err := destination.NewFilesystem(certPath, keyPath).Install(context.Background(), makeCredential(t)); err != nil {
		t.Fatalf("Install: %v", err)
	}

	if ki, err := os.Stat(keyPath); err != nil {
		t.Fatal(err)
	} else if perm := ki.Mode().Perm(); perm != 0o600 {
		t.Errorf("key permissions = %o, want 0600", perm)
	}
	if ci, err := os.Stat(certPath); err != nil {
		t.Fatal(err)
	} else if perm := ci.Mode().Perm(); perm != 0o644 {
		t.Errorf("cert permissions = %o, want 0644", perm)
	}
	if di, err := os.Stat(sub); err != nil {
		t.Fatal(err)
	} else if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("key directory permissions = %o, want 0700", perm)
	}
}

// TestFilesystemReinstallTightensLoosePermissions: installing over a key file
// left world-readable re-tightens it to 0600 — the destination owns the final
// mode regardless of a permissive umask or a pre-existing loose file (POSIX).
func TestFilesystemReinstallTightensLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "workload.key")
	certPath := filepath.Join(dir, "workload.crt")

	if err := os.WriteFile(keyPath, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := destination.NewFilesystem(certPath, keyPath).Install(context.Background(), makeCredential(t)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	ki, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := ki.Mode().Perm(); perm != 0o600 {
		t.Errorf("key permissions after reinstall = %o, want 0600 (tightened)", perm)
	}
}
