// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// Graph enumeration (A20): the live store is the completeness oracle. One
// identity still holding a certificate signed by the compromised CA outside
// the run fails the gate; an oracle that could not read keeps it unevaluated.
func TestFleetGraphEnumerationVerdict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   fleetEnumerationOutcome
		want string
	}{
		{"oracle could not read", fleetEnumerationOutcome{}, servedstatus.FleetGateNotEvaluated},
		{"every live leaf is in the run", fleetEnumerationOutcome{Evaluated: true, Live: 3}, servedstatus.FleetGatePassed},
		{"nothing live under the compromised CA any more", fleetEnumerationOutcome{Evaluated: true}, servedstatus.FleetGatePassed},
		{"one live leaf the plan missed", fleetEnumerationOutcome{Evaluated: true, Live: 4, Missing: []string{"id-9"}}, servedstatus.FleetGateFailed},
	}
	for _, tc := range cases {
		if got := fleetGraphEnumerationVerdict(tc.in); got != tc.want {
			t.Errorf("%s: verdict = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Revocation publication (A21): R1 observations for the compromised issuer.
// A stale or unreachable endpoint fails the gate; a fresh artifact older than
// the run's revocations cannot carry them, so the gate stays unevaluated.
func TestFleetRevocationPublicationVerdict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   fleetRevocationPublicationOutcome
		want string
	}{
		{"no observation for the issuer", fleetRevocationPublicationOutcome{}, servedstatus.FleetGateNotEvaluated},
		{"fresh and current", fleetRevocationPublicationOutcome{Evaluated: true, Fresh: 2, Current: true}, servedstatus.FleetGatePassed},
		{"fresh but predates the revocations", fleetRevocationPublicationOutcome{Evaluated: true, Fresh: 2}, servedstatus.FleetGateNotEvaluated},
		{"one stale among fresh", fleetRevocationPublicationOutcome{Evaluated: true, Fresh: 2, Stale: 1, Current: true}, servedstatus.FleetGateFailed},
		{"unreachable endpoint", fleetRevocationPublicationOutcome{Evaluated: true, Unreachable: 1}, servedstatus.FleetGateFailed},
	}
	for _, tc := range cases {
		if got := fleetRevocationPublicationVerdict(tc.in); got != tc.want {
			t.Errorf("%s: verdict = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestFleetRevocationPublicationFromRowsFiltersIssuerAndWatermark(t *testing.T) {
	t.Parallel()
	watermark := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	before, after := watermark.Add(-time.Hour), watermark.Add(time.Minute)
	rows := []store.RevocationEndpointHealth{
		{IssuerFingerprint: "AA", Status: "fresh", ThisUpdate: &after},
		{IssuerFingerprint: "bb", Status: "stale", ThisUpdate: &after}, // another issuer
		{IssuerFingerprint: "aa", Status: "expiring", ThisUpdate: &before},
	}
	got := fleetRevocationPublicationFromRows(rows, "aa", true, watermark)
	if !got.Evaluated || got.Fresh != 1 || got.Expiring != 1 || got.Stale != 0 || !got.Current {
		t.Fatalf("outcome = %+v", got)
	}
	if got := fleetRevocationPublicationFromRows(rows[2:], "aa", true, watermark); got.Current {
		t.Fatalf("an artifact published before the revocations must not count as current: %+v", got)
	}
	if got := fleetRevocationPublicationFromRows(rows, "aa", false, watermark); got.Current {
		t.Fatalf("a run that revoked nothing has nothing to be current about: %+v", got)
	}
	if got := fleetRevocationPublicationFromRows(rows, "cc", true, watermark); got.Evaluated {
		t.Fatalf("observations of other issuers must not evaluate the gate: %+v", got)
	}
}

// A computed gate is appended when the run never carried it, overwritten when
// it did, and left alone when an operator asserted it.
func TestEvaluateFleetComputedGate(t *testing.T) {
	t.Parallel()
	gates := []store.FleetReissuanceHealthGate{{Name: "replacement deployment", Status: servedstatus.FleetGatePassed}}
	gates = evaluateFleetComputedGate(gates, operatorAssertedGates(gates), fleetGraphEnumerationGateName, servedstatus.FleetGateFailed)
	if len(gates) != 2 || gates[1].Name != fleetGraphEnumerationGateName || gates[1].Status != servedstatus.FleetGateFailed {
		t.Fatalf("appended gate = %+v", gates)
	}
	asserted := operatorAssertedGates([]store.FleetReissuanceHealthGate{{Name: "Graph Enumeration", Status: servedstatus.FleetGatePassed}})
	kept := evaluateFleetComputedGate([]store.FleetReissuanceHealthGate{{Name: "Graph Enumeration", Status: servedstatus.FleetGatePassed}}, asserted, fleetGraphEnumerationGateName, servedstatus.FleetGateFailed)
	if kept[0].Status != servedstatus.FleetGatePassed {
		t.Fatalf("an operator-asserted gate was overwritten: %+v", kept)
	}
	recomputed := evaluateFleetComputedGate([]store.FleetReissuanceHealthGate{{Name: fleetRevocationPublicationGateName, Status: servedstatus.FleetGateNotEvaluated}}, map[string]bool{}, fleetRevocationPublicationGateName, servedstatus.FleetGatePassed)
	if len(recomputed) != 1 || recomputed[0].Status != servedstatus.FleetGatePassed {
		t.Fatalf("an unasserted gate was not recomputed: %+v", recomputed)
	}
}
