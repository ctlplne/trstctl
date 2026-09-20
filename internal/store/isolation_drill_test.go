// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
)

// The on-demand isolation drill must PASS against a correctly migrated schema —
// every tenant table ENABLEs and FORCEs RLS — and must leave nothing behind.
func TestIsolationDrillPassesAndCleansUp(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	report, err := s.RunIsolationDrill(ctx)
	if err != nil {
		t.Fatalf("RunIsolationDrill: %v", err)
	}
	if !report.Passed {
		t.Fatalf("isolation drill did not pass against a healthy schema: %+v", report.Checks)
	}
	// The three named checks must all be present and green: read denial, write
	// refusal, and verified cleanup.
	want := map[string]bool{"cross_tenant_read_denied": false, "cross_tenant_write_refused": false, "cleanup": false}
	for _, c := range report.Checks {
		if _, ok := want[c.Name]; ok {
			want[c.Name] = c.Passed
		}
	}
	for name, passed := range want {
		if !passed {
			t.Errorf("check %q missing or not passed: %+v", name, report.Checks)
		}
	}

	// Zero residue under the reserved probe prefix after the drill.
	if residue, err := s.DoctorProbeResidue(ctx, "00000000-d0c7"); err != nil || residue != 0 {
		t.Fatalf("probe residue after drill = %d (err %v), want 0", residue, err)
	}
}
