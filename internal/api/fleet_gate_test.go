// SPDX-License-Identifier: BUSL-1.1

package api

import (
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
