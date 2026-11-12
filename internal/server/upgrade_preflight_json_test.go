// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

var updateUpgradePreflightGolden = flag.Bool("update-upgrade-preflight-golden", false, "rewrite testdata/upgrade-preflight.golden.json")

// TestUpgradePreflightJSONIsAStableFormForPipelinesA246L1 pins the JSON form
// of the upgrade preflight a pipeline reads (A246-L1): its format name, every
// field, every list present even when empty, and the same verdict the text
// prints. A field renamed or removed fails here; a pipeline would read it
// differently.
func TestUpgradePreflightJSONIsAStableFormForPipelinesA246L1(t *testing.T) {
	now := time.Date(2026, 11, 12, 6, 0, 0, 0, time.UTC)
	notReady := EvaluateUpgradePreflight(store.UpgradePlan{
		SchemaVersion: 446, BinaryVersion: 448,
		Pending: []store.UpgradeMigration{
			{Version: 447, Name: "0447_secret_scoped_sync_approved_mode.sql", Transactional: true},
			{Version: 448, Name: "0448_drop_retired_snapshots.sql", Destructive: true, Transactional: true},
		},
		InvalidIndexes: []string{"secret_scoped_syncs_mode_idx"},
	}, UpgradeBackup{Configured: true, Verified: true, TakenAt: "2026-11-10T06:00:00Z", Fresh: false}, now)
	ready := EvaluateUpgradePreflight(store.UpgradePlan{SchemaVersion: 448, BinaryVersion: 448},
		UpgradeBackup{Detail: "no backup directory is configured (TRSTCTL_BACKUP_DIRECTORY), so a backup taken elsewhere is not visible here"}, now)
	var out bytes.Buffer
	for _, verdict := range []UpgradePreflight{notReady, ready} {
		if err := verdict.WriteJSON(&out); err != nil {
			t.Fatal(err)
		}
	}
	golden := filepath.Join("testdata", "upgrade-preflight.golden.json")
	if *updateUpgradePreflightGolden {
		if err := os.WriteFile(golden, out.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden) // #nosec G304 -- the package's own golden file (CWE-22)
	if err != nil {
		t.Fatalf("read the golden (go test -run %s -update-upgrade-preflight-golden): %v", t.Name(), err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("the preflight's JSON form changed; a pipeline reads it. Got:\n%s", out.Bytes())
	}
	// Each document stands alone and carries the verdict.
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	for _, wantReady := range []bool{false, true} {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			t.Fatal(err)
		}
		if doc["format"] != UpgradePreflightFormat || doc["ready"] != wantReady {
			t.Fatalf("format %v ready %v, want %s %v", doc["format"], doc["ready"], UpgradePreflightFormat, wantReady)
		}
		for _, list := range []string{"pending", "checksum_mismatches", "newer_than_binary", "invalid_indexes", "blockers", "warnings"} {
			if _, ok := doc[list].([]any); !ok {
				t.Fatalf("%s is not a list in %v", list, doc)
			}
		}
	}
	if notReady.Ready || len(notReady.Blockers) != 1 || notReady.Blockers[0].Code != "backup_required" || notReady.Rollback.Method != "restore_backup" {
		t.Fatalf("the destructive upgrade's verdict = %+v", notReady)
	}
}
