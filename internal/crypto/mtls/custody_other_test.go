// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package mtls_test

import (
	"os"
	"testing"
)

func assertPrivateStateCustody(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("persistent internal TLS state mode = %04o, want 0600", got)
	}
}

func assertPublicTrustCustody(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("published trust mode = %04o, want 0644", got)
	}
}

func makePrivateStateUnsafe(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o644); err != nil { // #nosec G302 -- deliberate over-permissive negative fixture (CWE-276)
		t.Fatal(err)
	}
}
