// SPDX-License-Identifier: MPL-2.0

package upsertarbiter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestDumpSites writes every upsert site the scanner sees in internal/store as
// JSON when UPSERTARBITER_SITES_OUT names a file. It is a maintenance aid for
// working the baseline down (which arbiter, which uncovered unique set, guarded
// or baselined); it asserts nothing on its own.
func TestDumpSites(t *testing.T) {
	out := os.Getenv("UPSERTARBITER_SITES_OUT")
	if out == "" {
		t.Skip("set UPSERTARBITER_SITES_OUT=<path> to dump the scanned sites")
	}
	sites, err := ScanDir(filepath.Join("..", "..", "..", "internal", "store"))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	raw, err := json.MarshalIndent(sites, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	out = filepath.Clean(out)
	if err := os.WriteFile(out, raw, 0o600); err != nil { // #nosec G703 G304 -- test-only maintenance dump to an operator-chosen path (CWE-22)
		t.Fatal(err)
	}
	t.Logf("wrote %d sites to %s", len(sites), out)
}
