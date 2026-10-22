// SPDX-License-Identifier: BUSL-1.1

package agentupgrade_test

import (
	"strings"
	"testing"

	fleet "trstctl.com/trstctl/internal/agentupgrade"
)

// A71: an agent that came up on the target build but failed its functional
// self-check halts the ring with its own reason, and is never counted silent.
func TestAFailedFunctionalCheckHaltsByName(t *testing.T) {
	outcome := fleet.RingOutcome{Ring: fleet.Rings[0], Dispatched: 3, Verified: 2, CheckFailed: 1}
	if outcome.Silent() != 0 {
		t.Fatalf("silent = %d, want 0: a failed check is an answer", outcome.Silent())
	}
	d := fleet.Advance(fleet.StateRunning, outcome)
	if d.NextState != fleet.StateHalted || !strings.Contains(d.Reason, "failed the functional self-check") {
		t.Fatalf("decision = %+v", d)
	}
	d = fleet.Advance(fleet.StateRunning, fleet.RingOutcome{Ring: fleet.Rings[0], Dispatched: 3, Verified: 3})
	if d.NextState != fleet.StateRunning || d.NextRing != fleet.Rings[1] {
		t.Fatalf("all passed = %+v", d)
	}
}
