// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"testing"
	"time"
)

// TestIdleClosedCircuitsArePruned is the regression guard for the unbounded
// circuit-breaker map. o.circuits is keyed by (tenant, destination) and nothing
// ever deleted from it, so it grew with every pair the deployment had ever used
// — and the claim path iterates it IN FULL, so the sweep got slower the longer
// the process ran.
//
// Forgetting a CLOSED circuit is information-free: the claim path creates one on
// demand and a missing key already means closed. Open and half-open circuits
// carry real state and must survive.
func TestIdleClosedCircuitsArePruned(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	stale := now.Add(-2 * circuitIdleRetention)

	o := &Outbox{circuits: map[circuitKey]*outboxCircuit{
		{tenantID: "t1", destination: "d-idle"}:     {state: CircuitClosed, updatedAt: stale},
		{tenantID: "t2", destination: "d-idle"}:     {state: CircuitClosed, updatedAt: stale},
		{tenantID: "t3", destination: "d-recent"}:   {state: CircuitClosed, updatedAt: now},
		{tenantID: "t4", destination: "d-failing"}:  {state: CircuitClosed, updatedAt: stale, failures: 2},
		{tenantID: "t5", destination: "d-open"}:     {state: CircuitOpen, updatedAt: stale, openUntil: now.Add(time.Minute)},
		{tenantID: "t6", destination: "d-halfopen"}: {state: CircuitHalfOpen, updatedAt: stale},
		{tenantID: "t7", destination: "d-nil"}:      nil,
	}}

	o.pruneIdleCircuitsLocked(now)

	for _, gone := range []circuitKey{
		{tenantID: "t1", destination: "d-idle"},
		{tenantID: "t2", destination: "d-idle"},
		{tenantID: "t7", destination: "d-nil"},
	} {
		if _, still := o.circuits[gone]; still {
			t.Errorf("idle closed circuit %v was retained; the map grows without bound", gone)
		}
	}

	// State-bearing and recent circuits must survive — pruning them would drop a
	// live breaker and let a failing destination be retried immediately.
	for _, kept := range []circuitKey{
		{tenantID: "t3", destination: "d-recent"},
		{tenantID: "t4", destination: "d-failing"},
		{tenantID: "t5", destination: "d-open"},
		{tenantID: "t6", destination: "d-halfopen"},
	} {
		if _, still := o.circuits[kept]; !still {
			t.Errorf("circuit %v was pruned but carries state; a tripped breaker would be forgotten", kept)
		}
	}
}
