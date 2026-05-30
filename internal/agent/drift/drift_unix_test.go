//go:build unix

package drift_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"certctl.io/certctl/internal/agent/drift"
)

// A key file whose permissions loosened (0600 -> 0644) is detected as a
// permission change, reporting the mode found on disk. This is the security
// regression drift detection most needs to catch.
func TestDetectPermissionChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.key")
	content := []byte("-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	w := drift.Watched{Path: path, Class: "private-key", Fingerprint: drift.Fingerprint(content), Mode: 0o600}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := drift.Detect([]drift.Watched{w})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Type != drift.PermissionChanged {
		t.Fatalf("expected PermissionChanged, got %+v", findings)
	}
	if findings[0].ActualMode.Perm() != 0o644 {
		t.Errorf("ActualMode = %o, want 0644", findings[0].ActualMode.Perm())
	}
}

// AutoRemediate of a permission change restores the declared mode without
// rewriting the (correct) content.
func TestAutoRemediatePermission(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.key")
	content := []byte("-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	w := drift.Watched{Path: path, Class: "private-key", Fingerprint: drift.Fingerprint(content), Mode: 0o600}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	r := &drift.Reconciler{
		Policy:   drift.ClassPolicy{"private-key": drift.AutoRemediate},
		Auditor:  &recorder{},
		Restorer: drift.NewFileRestorer(map[string][]byte{path: content}),
	}
	if _, err := r.Reconcile(context.Background(), []drift.Watched{w}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode after remediation = %o, want 0600", info.Mode().Perm())
	}
}

// A Restricted credential that is group/other-accessible is permission drift even
// without an exact declared Mode — the cross-platform "must not be broadly
// accessible" intent, enforced on POSIX as no 0o077 bits.
func TestDetectRestrictedWorldAccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.key")
	content := []byte("-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n")
	if err := os.WriteFile(path, content, 0o644); err != nil { // world-readable
		t.Fatal(err)
	}
	w := drift.Watched{Path: path, Class: "private-key", Fingerprint: drift.Fingerprint(content), Restricted: true}

	findings, err := drift.Detect([]drift.Watched{w})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Type != drift.PermissionChanged {
		t.Fatalf("expected PermissionChanged for a world-readable restricted key, got %+v", findings)
	}

	// Tightening to owner-only clears the drift.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	findings, _ = drift.Detect([]drift.Watched{w})
	if len(findings) != 0 {
		t.Errorf("an owner-only restricted key must not drift, got %+v", findings)
	}
}
