// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"errors"
	"testing"
	"time"
)

func TestCircuitTransitionsCarryDestinationFamilyAndEffectLaneSeparately(t *testing.T) {
	const family = "managedkey.command"
	const lane = "managedkey.command:provider:key-ref"
	now := time.Now().UTC()
	var transitions []CircuitTransition
	o := &Outbox{
		circuits:                make(map[circuitKey]*outboxCircuit),
		circuitFailureThreshold: 1,
		circuitOpenDuration:     time.Second,
		circuitObserver: func(transition CircuitTransition) {
			transitions = append(transitions, transition)
		},
	}
	message := Message{TenantID: "tenant-a", Destination: family, EffectLane: lane}
	o.recordCircuitFailure(message, errors.New("receiver unavailable"), now)
	o.reserveHalfOpenProbes(now.Add(2*time.Second), DestinationScope{})
	o.recordCircuitSuccess(message, now.Add(3*time.Second))
	if len(transitions) != 3 {
		t.Fatalf("circuit transitions = %d, want 3", len(transitions))
	}
	for _, transition := range transitions {
		if transition.Destination != family || transition.Lane != lane {
			t.Fatalf("transition route = %q/%q, want %q/%q", transition.Destination, transition.Lane, family, lane)
		}
	}
	states := o.CircuitStates()
	if len(states) != 1 || states[0].Destination != lane {
		t.Fatalf("tenant circuit route = %+v, want the effect lane", states)
	}
}
