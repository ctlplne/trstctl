// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// Per-batch health gates that mean something (epic H3).
//
// The gate used to be assigned by round-robin over the run's gate list —
// gates[(index-1)%len(gates)] — so batch 1 wore the first gate's label, batch 2
// the second, and it wrapped. A batch's health gate therefore said nothing
// whatever about that batch.
//
// That is worse than showing nothing. During an incident it reads as per-batch
// evidence, and the operator deciding whether to continue a fleet reissue is
// exactly the person who would act on it.

func TestABatchGateReflectsThatBatchAndNotAList(t *testing.T) {
	t.Parallel()
	// Three batches, one gate name in the run. Under the old round-robin every
	// batch would take a label from the list regardless of its own state.
	batches := buildFleetBatches(
		[]string{"a", "b", "c", "d", "e", "f"},
		[]string{"ra", "rb", "rc", "rd", "re", "rf"},
		2,
	)
	if len(batches) != 3 {
		t.Fatalf("batches = %d, want 3", len(batches))
	}
	for i, b := range batches {
		if b.HealthGate != servedstatus.FleetGateNotEvaluated {
			t.Errorf("batch %d starts with gate %q; a planned batch has been verified by nobody, "+
				"and any other value claims evidence that does not exist", i+1, b.HealthGate)
		}
	}
}

// The verdict rules that make a green run trustworthy: failure dominates, and
// absence beats success.
func TestTheBatchVerdictRefusesToRoundUp(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		outcome store.FleetVerificationOutcome
		want    string
	}{
		{"all verified", store.FleetVerificationOutcome{Verified: 5}, servedstatus.FleetGatePassed},
		{"one failed", store.FleetVerificationOutcome{Verified: 4, Failed: 1}, servedstatus.FleetGateFailed},
		{
			// The case that matters most. 99% verified is not a pass — it is a
			// run with an endpoint nobody looked at, and during an incident that
			// is precisely the endpoint worth knowing about.
			"one unverified", store.FleetVerificationOutcome{Verified: 99, Unverified: 1},
			servedstatus.FleetGateNotEvaluated,
		},
		{"nothing observed", store.FleetVerificationOutcome{}, servedstatus.FleetGateNotEvaluated},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := fleetDeploymentVerdict(tc.outcome); got != tc.want {
				t.Errorf("verdict = %q, want %q", got, tc.want)
			}
		})
	}
}

// A batch that has not run keeps its unevaluated gate: "not looked at" and
// "looked at and found nothing" must not collapse into one string.
func TestPlannedAndHaltedBatchesAreLeftAlone(t *testing.T) {
	t.Parallel()
	batches := []store.FleetReissuanceBatch{
		{Index: 1, Status: servedstatus.FleetBatchPlanned, HealthGate: servedstatus.FleetGateNotEvaluated,
			ReplacementIdentityIDs: []string{"r1"}},
		{Index: 2, Status: servedstatus.FleetBatchHalted, HealthGate: servedstatus.FleetGateNotEvaluated,
			ReplacementIdentityIDs: []string{"r2"}},
	}
	// A nil store stands in for "cannot read": the evaluator must not invent a
	// verdict in either case.
	got := evaluateFleetBatchGates(context.Background(), nil, "t1", batches)
	for _, b := range got {
		if b.HealthGate != servedstatus.FleetGateNotEvaluated {
			t.Errorf("batch %d became %q; a batch that never ran has nothing to verify, and a "+
				"halted one changed nothing at all", b.Index, b.HealthGate)
		}
	}
}
