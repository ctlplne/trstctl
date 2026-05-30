//go:build windows

package drift_test

import (
	"os"
	"path/filepath"
	"testing"

	"certctl.io/certctl/internal/agent/drift"
)

// A restricted credential written to a per-test temp directory does not grant
// access to Everyone, Authenticated Users, or Users, so it must not be flagged
// as permission drift. This exercises the real DACL read + SDDL parse path and
// guards against false positives. (Positive detection of a broad ACE is covered
// by the platform-independent TestSDDLAllowsBroad.)
func TestWindowsRestrictedTempFileNoFalsePositive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.key")
	content := []byte("-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	w := drift.Watched{Path: path, Class: "private-key", Fingerprint: drift.Fingerprint(content), Restricted: true}

	findings, err := drift.Detect([]drift.Watched{w})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Type == drift.PermissionChanged {
			t.Errorf("unexpected permission drift on a fresh temp credential: %s", f.Detail)
		}
	}
}

// With Restricted unset, the DACL is never consulted and there is no permission
// drift regardless of access controls.
func TestWindowsUnrestrictedNeverPermissionDrift(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.crt")
	content := []byte("-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	w := drift.Watched{Path: path, Class: "certificate", Fingerprint: drift.Fingerprint(content)}

	findings, err := drift.Detect([]drift.Watched{w})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no drift for an unrestricted, matching file, got %+v", findings)
	}
}
