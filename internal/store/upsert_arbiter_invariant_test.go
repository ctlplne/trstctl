// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"regexp"
	"testing"

	"trstctl.com/trstctl/tools/trstctllint/upsertarbiter"
)

// OPP-C01: the projection family's generic race guard. DP2-043 (declarations)
// and DP2-046 (runs) were the same defect: an Apply*Tx projection upserts into a
// table that carries a second unique index, and a simultaneous replay of the
// same event raises 23505 on the non-arbiter index instead of converging. This
// test walks every Apply*Tx projection in the package (pure AST, no database)
// and requires each such upsert to serialize on an advisory lock or handle
// unique_violation — or to be a reviewed, pinned baseline entry. A new
// projection with the DP2-046 shape fails here and in `make lint`.
func TestEveryApplyTxUpsertIsRaceGuardedOrBaselined(t *testing.T) {
	sites, err := upsertarbiter.ScanDir(".")
	if err != nil {
		t.Fatal(err)
	}
	projection := regexp.MustCompile(`^(?:apply|Apply)\w+Tx$`)
	seen, guardedCount := 0, 0
	stillFlagged := map[string]map[string]bool{}
	for _, s := range sites {
		if !projection.MatchString(s.Func) {
			continue
		}
		seen++
		if s.Guarded {
			guardedCount++
			continue
		}
		if stillFlagged[s.File] == nil {
			stillFlagged[s.File] = map[string]bool{}
		}
		stillFlagged[s.File][s.Func] = true
		if !s.Baselined {
			t.Errorf("%s: projection %s upserts %s on (%v) while the table also has unique (%v) with no advisory lock or unique_violation handling — the DP2-046 race; serialize it (pg_advisory_xact_lock keyed on the arbiter) or retry on 23505", s.File, s.Func, s.Table, s.Arbiter, s.Uncovered)
		}
	}
	for file, funcs := range upsertarbiter.ReviewedBaseline() {
		for _, fn := range funcs {
			if projection.MatchString(fn) && !stillFlagged[file][fn] {
				t.Errorf("baseline entry %s %s is no longer an unguarded dual-unique projection upsert — remove it so the ratchet only tightens", file, fn)
			}
		}
	}
	if seen == 0 {
		t.Fatal("found no Apply*Tx projection upserts on dual-unique tables — scanner or schema drift")
	}
	t.Logf("projection upserts on dual-unique tables: %d (guarded %d, baselined %d)", seen, guardedCount, seen-guardedCount)
}
