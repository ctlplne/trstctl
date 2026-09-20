// SPDX-License-Identifier: BUSL-1.1

package agentupgrade

import (
	"strings"
	"testing"
)

// The acceptance criterion: a canary failure halts the rollout automatically.
func TestACanaryFailureHaltsTheRollout(t *testing.T) {
	t.Parallel()
	d := Advance(StateRunning, RingOutcome{Ring: RingCanary, Dispatched: 5, Verified: 4, Failed: 1})
	if d.NextState != StateHalted {
		t.Fatalf("state = %q after a canary failure, want halted.\n\n"+
			"The rollout would carry a build one agent has already reported unhealthy to the "+
			"whole fleet.", d.NextState)
	}
	if d.NextRing != "" {
		t.Fatalf("next ring = %q; a halted campaign must dispatch nothing", d.NextRing)
	}
	if !strings.Contains(d.Reason, "unhealthy") {
		t.Errorf("reason does not say what failed: %q. \"Halted\" alone sends somebody to read "+
			"logs", d.Reason)
	}
}

// One failure is enough. A percentage tolerance on a deliberately small canary
// means the ring can never halt anything.
func TestOneFailureIsEnoughToHaltNoMatterTheRingSize(t *testing.T) {
	t.Parallel()
	for _, dispatched := range []int{3, 50, 5000} {
		d := Advance(StateRunning, RingOutcome{
			Ring: RingCanary, Dispatched: dispatched, Verified: dispatched - 1, Failed: 1})
		if d.NextState != StateHalted {
			t.Fatalf("a single failure in a ring of %d did not halt. A percentage tolerance on a "+
				"canary that is deliberately small means the ring can never stop anything — which "+
				"is the entire reason the ring exists", dispatched)
		}
	}
}

// Silence is not success. An agent that took an upgrade and stopped answering
// is the most likely shape of a bad build.
func TestSilentAgentsHaltTheRollout(t *testing.T) {
	t.Parallel()
	d := Advance(StateRunning, RingOutcome{Ring: RingCanary, Dispatched: 5, Verified: 3, Failed: 0})
	if d.NextState != StateHalted {
		t.Fatalf("state = %q with 2 of 5 agents silent, want halted.\n\n"+
			"Counting silence as success is how a rollout proceeds over a fleet it has already "+
			"broken — the agents that went quiet are the ones the upgrade killed.", d.NextState)
	}
	if !strings.Contains(d.Reason, "Silence is not success") {
		t.Errorf("reason = %q; it must say why silence counts against the ring", d.Reason)
	}
}

// Verification means a health receipt, not an acknowledgement of the job.
func TestVerificationIsAHealthReceiptNotAnAcknowledgement(t *testing.T) {
	t.Parallel()
	// All five acknowledged, none verified healthy: that is five silent agents.
	d := Advance(StateRunning, RingOutcome{Ring: RingCanary, Dispatched: 5})
	if d.NextState != StateHalted {
		t.Fatal("a ring where every agent took the upgrade and none reported healthy was treated " +
			"as a success. An agent that applied the upgrade and then failed to serve is exactly " +
			"what the canary exists to catch")
	}
}

// A halted campaign must never advance on its own.
func TestAHaltedCampaignNeverAdvancesOnItsOwn(t *testing.T) {
	t.Parallel()
	d := Advance(StateHalted, RingOutcome{Ring: RingCanary, Dispatched: 5, Verified: 5})
	if d.NextState != StateHalted || d.NextRing != "" {
		t.Fatalf("a halted campaign advanced to %+v on a later clean report.\n\n"+
			"The whole value of an automatic halt is that it does not un-halt itself — a flapping "+
			"agent would otherwise resume a rollout nobody re-approved.", d)
	}
}

// Resume restarts at the ring that halted, never past it.
func TestResumeRestartsAtTheRingThatHaltedNotPastIt(t *testing.T) {
	t.Parallel()
	d, err := Resume(StateHalted, RingCanary)
	if err != nil {
		t.Fatal(err)
	}
	if d.NextRing != RingCanary {
		t.Fatalf("resumed at %q, want canary.\n\n"+
			"Skipping past the ring that halted leaves the agents whose failure stopped the "+
			"rollout on the broken build, while the campaign reports success.", d.NextRing)
	}
	if d.NextState != StateRunning {
		t.Fatalf("state = %q, want running", d.NextState)
	}
	if _, err := Resume(StateRunning, RingCanary); err == nil {
		t.Fatal("a running campaign was resumable; only a halted or paused one should be")
	}
	if _, err := Resume(StateHalted, ""); err == nil {
		t.Fatal("a campaign that does not record which ring halted it was resumed anyway — it " +
			"would restart from the beginning or from nowhere")
	}
}

// Pause must actually gate execution, not just grey out a button.
func TestPauseGatesDispatchRatherThanJustTheButton(t *testing.T) {
	t.Parallel()
	if CanDispatch(StatePaused) {
		t.Fatal("a paused campaign may still dispatch upgrade jobs.\n\n" +
			"A pause that greys out a button while jobs keep flowing is worse than no pause: the " +
			"operator believes they stopped the rollout.")
	}
	if CanDispatch(StateHalted) {
		t.Fatal("a halted campaign may still dispatch upgrade jobs")
	}
	if CanDispatch(StateComplete) {
		t.Fatal("a complete campaign may still dispatch")
	}
	for _, s := range []string{StatePending, StateRunning} {
		if !CanDispatch(s) {
			t.Errorf("%s cannot dispatch; the campaign could never start", s)
		}
	}
}

// A clean ring advances to the next, and the last one completes.
func TestACleanRingAdvancesAndTheLastCompletes(t *testing.T) {
	t.Parallel()
	d := Advance(StateRunning, RingOutcome{Ring: RingCanary, Dispatched: 3, Verified: 3})
	if d.NextRing != RingEarly {
		t.Fatalf("next = %q, want early", d.NextRing)
	}
	d = Advance(StateRunning, RingOutcome{Ring: RingBroad, Dispatched: 90, Verified: 90})
	if d.NextState != StateComplete || d.NextRing != "" {
		t.Fatalf("the last ring did not complete the campaign: %+v", d)
	}
}

// Halted and paused are different states: one is a machine's finding, the other
// a person's decision.
func TestHaltedIsDistinctFromPaused(t *testing.T) {
	t.Parallel()
	if StateHalted == StatePaused {
		t.Fatal("halted and paused are the same value. One is an automatic finding that a build " +
			"is bad and the other is an operator stopping deliberately; an operator resuming a " +
			"pause they made must not silently resume a halt they never saw")
	}
}

// A staged rollout needs more than one ring, or it is a fleet-wide push with
// extra vocabulary.
func TestARolloutHasMoreThanOneRing(t *testing.T) {
	t.Parallel()
	if len(Rings) < 2 {
		t.Fatalf("Rings has %d entries; a rollout with one ring is not staged", len(Rings))
	}
	if Rings[0] != RingCanary {
		t.Fatalf("first ring = %q, want canary — the small one has to go first or it is not a "+
			"canary", Rings[0])
	}
}
