// SPDX-License-Identifier: MPL-2.0

package api

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// The fleet gate verdict: failure dominates, absence beats success (epic D6).
//
// These two rules are what an operator relies on when reading a run mid-
// incident. Green must mean nothing in the run is known-broken AND nothing in
// it is merely unlooked-at. Either rule alone would let a run display a pass it
// has not earned, which is the failure mode this gate previously avoided by
// refusing to compute a verdict at all.
func TestFleetDeploymentVerdictNeverPassesOnIncompleteEvidence(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   store.FleetVerificationOutcome
		want string
	}{
		{"nothing observed at all", store.FleetVerificationOutcome{}, servedstatus.FleetGateNotEvaluated},
		{"every replacement verified", store.FleetVerificationOutcome{Verified: 3}, servedstatus.FleetGatePassed},
		{"one failed among many verified", store.FleetVerificationOutcome{Verified: 9, Failed: 1}, servedstatus.FleetGateFailed},
		{"one unverified among many verified", store.FleetVerificationOutcome{Verified: 9, Unverified: 1}, servedstatus.FleetGateNotEvaluated},
		{"failure beats an absence", store.FleetVerificationOutcome{Failed: 1, Unverified: 5}, servedstatus.FleetGateFailed},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := fleetDeploymentVerdict(tc.in); got != tc.want {
				t.Errorf("fleetDeploymentVerdict(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A gate an operator asserted is never overwritten by a computed one.
//
// The operator may have inspected something this control plane cannot see,
// which makes them the better authority; replacing their answer with a derived
// one would discard the more informed of the two.
func TestAnOperatorAssertedGateSurvivesEvaluation(t *testing.T) {
	t.Parallel()
	gates := []store.FleetReissuanceHealthGate{
		{Name: "replacement deployment", Status: servedstatus.FleetGatePassed},
		{Name: "graph enumeration", Status: servedstatus.FleetGateNotEvaluated},
	}
	asserted := operatorAssertedGates(gates)
	// Verification says otherwise; the operator's attestation stands.
	out := evaluateFleetDeploymentGate(gates, asserted, store.FleetVerificationOutcome{Failed: 2})
	if out[0].Status != servedstatus.FleetGatePassed {
		t.Errorf("an operator-asserted gate was overwritten with %q", out[0].Status)
	}
}

// An unasserted gate IS computed — otherwise D6 would have changed nothing.
func TestAnUnassertedGateIsComputedFromReceipts(t *testing.T) {
	t.Parallel()
	gates := []store.FleetReissuanceHealthGate{
		{Name: "replacement deployment", Status: servedstatus.FleetGateNotEvaluated},
	}
	out := evaluateFleetDeploymentGate(gates, operatorAssertedGates(gates), store.FleetVerificationOutcome{Failed: 1})
	if out[0].Status != servedstatus.FleetGateFailed {
		t.Fatalf("gate = %q, want failed — a run whose replacement is not being served must "+
			"not display all-green", out[0].Status)
	}
}

// The canary halts the fleet, and halted is not failed (epic D6).
//
// A fleet re-issuance touches every certificate an issuer signed. Without a
// gate, a bad replacement propagates to the whole estate at the speed of the
// outbox. The first batch is the canary; if its replacements are not being
// served, the rest stops.
func TestAFailedCanaryHaltsTheRemainingBatches(t *testing.T) {
	t.Parallel()
	batches := []store.FleetReissuanceBatch{
		{Index: 1, Status: servedstatus.FleetBatchPlanned},
		{Index: 2, Status: servedstatus.FleetBatchPlanned},
		{Index: 3, Status: servedstatus.FleetBatchPlanned},
	}
	out := applyCanaryHalt(batches)

	// The canary itself is untouched: it ran, and its own status says what
	// happened to it.
	if out[0].Status != servedstatus.FleetBatchPlanned {
		t.Errorf("the canary batch was rewritten to %q; it ran, and its own status records that",
			out[0].Status)
	}
	for _, b := range out[1:] {
		if b.Status != servedstatus.FleetBatchHalted {
			t.Errorf("batch %d = %q, want halted", b.Index, b.Status)
		}
		if b.Status == servedstatus.FleetBatchFailed {
			t.Errorf("batch %d was reported as FAILED; it was never attempted, so nothing in it "+
				"is broken and sending an operator to investigate it during an incident wastes "+
				"the attention they have least of", b.Index)
		}
	}
}

// A batch that already went out is never rewritten to halted.
//
// A canary that fails after later batches have deployed is a worse situation
// than a clean halt, and relabelling them would erase the fact that they ARE
// deployed and need attention — which is the single most important thing to
// know at that moment.
func TestAlreadyExecutedBatchesAreNotRelabelledAsHalted(t *testing.T) {
	t.Parallel()
	batches := []store.FleetReissuanceBatch{
		{Index: 1, Status: servedstatus.FleetBatchPlanned},
		{Index: 2, Status: servedstatus.FleetBatchExecuted},
		{Index: 3, Status: servedstatus.FleetBatchFailed},
		{Index: 4, Status: servedstatus.FleetBatchPlanned},
	}
	out := applyCanaryHalt(batches)

	if out[1].Status != servedstatus.FleetBatchExecuted {
		t.Errorf("an executed batch was relabelled %q; it is deployed and needs attention, and "+
			"hiding that is worse than the halt itself", out[1].Status)
	}
	if out[2].Status != servedstatus.FleetBatchFailed {
		t.Errorf("a failed batch was relabelled %q", out[2].Status)
	}
	if out[3].Status != servedstatus.FleetBatchHalted {
		t.Errorf("an unstarted batch after the canary = %q, want halted", out[3].Status)
	}
}

// The halt reason tells an operator that nothing in the halted batches changed
// and how the run resumes.
func TestTheHaltReasonSaysNothingWasChanged(t *testing.T) {
	t.Parallel()
	reason := canaryHaltReason(4)
	if reason == "" {
		t.Fatal("a halted run produced no reason")
	}
	for _, want := range []string{"canary", "halted", "Nothing in them was changed", "Resume"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason = %q; it must contain %q so an operator knows what is and is not "+
				"broken and how the run continues", reason, want)
		}
	}
	if canaryHaltReason(0) != "" {
		t.Error("a run with nothing halted produced a halt reason")
	}
}
