// SPDX-License-Identifier: BUSL-1.1

package connector

import "testing"

// AUD-33: every accepted E1 family has exactly one closed classification. The
// invariant iterates the SOURCE denominator, not the relay implementation list;
// otherwise deleting an executor from the latter would also delete the red row
// meant to reveal that omission.
func TestE1ScopeEveryAcceptedFamilyHasOneTruthfulDisposition(t *testing.T) {
	counts := map[ParityDisposition]int{}
	for _, family := range E1Families() {
		status := ParityStatusFor(family)
		counts[status.Disposition]++
		switch status.Disposition {
		case ParityDispositionMigrated:
			if !status.RelayMigrated || status.CPRetained || len(status.Missing) != 0 {
				t.Errorf("family %s: migrated disposition disagrees with gates: %+v", family, status)
			}
		case ParityDispositionArchitectureException:
			if status.RelayMigrated || !status.CPRetained || status.ScopeNote == "" {
				t.Errorf("family %s: architecture exception is not explicit: %+v", family, status)
			}
		case ParityDispositionUnimplemented:
			if status.RelayMigrated || status.CPRetained || len(status.Missing) == 0 || status.ScopeNote == "" {
				t.Errorf("family %s: unimplemented disposition has no concrete gap: %+v", family, status)
			}
		default:
			t.Errorf("family %s has unknown disposition %q", family, status.Disposition)
		}
		if status.CPRetained {
			if CanRollback(family) || CanReadback(family) {
				t.Errorf("family %s is marked cp_retained but its API CAN express rollback/readback — a capable family must migrate, not be parked", family)
			}
			if status.ScopeNote == "" {
				t.Errorf("family %s: cp_retained without a scope note — 'not migrated' with no reason reads as 'coming soon'", family)
			}
			row, ok := SupportRowFor(family)
			if !ok {
				t.Errorf("family %s: retained with no support-matrix row — the matrix is what carries this truth", family)
			} else if len(row.KnownLimits) == 0 {
				t.Errorf("family %s: retained but its support row names no known limits", family)
			}
		}
	}

	// A59: GCP Certificate Manager migrated; ACM and Key Vault are retained
	// exceptions; Envoy, PostgreSQL and MySQL remain host-local work. A122
	// (owner decision 2026-10-26): cisco migrated once an ISE target became
	// re-bindable and readable.
	if counts[ParityDispositionMigrated] != 8 || counts[ParityDispositionArchitectureException] != 2 || counts[ParityDispositionUnimplemented] != 3 {
		t.Errorf("E1 disposition counts = %v, want migrated=8 architecture_exception=2 unimplemented=3", counts)
	}
}
