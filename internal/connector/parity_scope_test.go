// SPDX-License-Identifier: MPL-2.0

package connector

import "testing"

// TestE1ScopeClosure_EveryVantageFamilyMigratedOrRetained pins the E1 closure
// invariant (owner scope decision, 2026-08-08): every relay-vantage family is
// either relay-migrated or control-plane-retained BY DESIGN — no family may sit
// in an unlabelled limbo that reads as "coming soon". It also pins that the
// two states never overlap, and that retention is grounded in the capability
// censuses rather than asserted: a retained family is exactly one that cannot
// express rollback or readback, and a family that CAN pass the gates may never
// be parked as retained.
func TestE1ScopeClosure_EveryVantageFamilyMigratedOrRetained(t *testing.T) {
	for _, family := range RelayVantageFamilies() {
		status := ParityStatusFor(family)
		if status.RelayMigrated == status.CPRetained {
			t.Errorf("family %s: relay_migrated=%v cp_retained=%v — must be exactly one (no limbo, no overlap)",
				family, status.RelayMigrated, status.CPRetained)
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

	migrated := RelayMigratedConnectors()
	if len(migrated) != 4 {
		t.Errorf("migrated families = %v, want the four gate-capable families (a10, f5, kemp, netscaler)", migrated)
	}
}
