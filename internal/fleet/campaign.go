// SPDX-License-Identifier: MPL-2.0

// Package fleet holds staged agent-upgrade campaigns (epic A5).
//
// The decisions live here as pure functions over state rather than inside a
// worker, because the property that matters is a REFUSAL — a campaign whose
// canary ring failed must not advance — and a refusal enforced only by whichever
// worker happens to run is a refusal that holds until somebody adds a second
// caller.
package fleet

import "fmt"

// Ring names one stage of a rollout. Canary first, always.
//
// The point of a canary is that it is small enough that its failure is cheap
// and large enough that a broken build shows up. A rollout with one ring is not
// staged; it is a fleet-wide push with extra vocabulary.
type Ring string

const (
	RingCanary Ring = "canary"
	RingEarly  Ring = "early"
	RingBroad  Ring = "broad"
)

// Rings is the rollout order. One list so the worker, the API enum and the
// console cannot disagree about what comes next.
var Rings = []Ring{RingCanary, RingEarly, RingBroad}

// Campaign states.
const (
	// StatePending: created, nothing dispatched.
	StatePending = "pending"
	// StateRunning: a ring is in flight.
	StateRunning = "running"
	// StateHalted: a ring's verification failed. AUTOMATIC, and it is the whole
	// acceptance criterion. Distinct from paused because nobody chose it.
	StateHalted = "halted"
	// StatePaused: an operator stopped it deliberately.
	StatePaused = "paused"
	// StateComplete: every ring verified.
	StateComplete = "complete"
)

// RingOutcome is what a ring's post-upgrade verification receipts said.
type RingOutcome struct {
	Ring Ring
	// Dispatched is how many agents were told to upgrade.
	Dispatched int
	// Verified is how many returned a receipt proving they are healthy on the
	// new version. NOT how many acknowledged the job: an agent that took the
	// upgrade and then failed to serve is the exact failure a canary exists to
	// catch, and counting acknowledgements would score it as a success.
	Verified int
	// Failed is how many returned a receipt saying they are not healthy.
	Failed int
}

// Silent reports agents that neither verified nor failed.
//
// A silent agent is NOT a success. An agent that took an upgrade and stopped
// answering is the most likely shape of a bad build, and counting silence as
// anything but unresolved is how a rollout proceeds over a fleet it has already
// broken.
func (r RingOutcome) Silent() int {
	n := r.Dispatched - r.Verified - r.Failed
	if n < 0 {
		return 0
	}
	return n
}

// Decision is what the campaign should do next.
type Decision struct {
	// NextState is the campaign state after this ring's result.
	NextState string
	// NextRing is the ring to dispatch, empty when nothing should be.
	NextRing Ring
	// Reason is the sentence an operator reads. For a halt it must say what
	// failed, because "halted" alone sends somebody to read logs.
	Reason string
}

// Advance decides what happens after a ring reports.
//
// The rules, in full:
//   - ANY failed receipt halts. Not a threshold, not a percentage: the canary
//     ring is deliberately small, so one failure in it is a meaningful signal,
//     and a "5% tolerance" on a three-agent canary means the ring can never
//     halt anything.
//   - SILENCE halts too. An agent that took the upgrade and went quiet is the
//     most likely shape of a bad build.
//   - a halted campaign never advances. Resuming is an explicit operator act
//     (see Resume), because the whole value of an automatic halt is that it
//     does not un-halt on its own.
func Advance(state string, outcome RingOutcome) Decision {
	if state == StateHalted || state == StatePaused {
		return Decision{NextState: state, Reason: "Campaign is " + state + " and does not advance on its own."}
	}
	if outcome.Failed > 0 {
		return Decision{
			NextState: StateHalted,
			Reason: fmt.Sprintf(
				"Halted: %d of %d agents in the %s ring reported an unhealthy upgrade. The rollout "+
					"stopped here rather than carrying a bad build to the rest of the fleet.",
				outcome.Failed, outcome.Dispatched, outcome.Ring),
		}
	}
	if silent := outcome.Silent(); silent > 0 {
		return Decision{
			NextState: StateHalted,
			Reason: fmt.Sprintf(
				"Halted: %d of %d agents in the %s ring never reported after upgrading. Silence is "+
					"not success — an agent that took an upgrade and stopped answering is the most "+
					"likely shape of a bad build.",
				silent, outcome.Dispatched, outcome.Ring),
		}
	}
	next, ok := nextRing(outcome.Ring)
	if !ok {
		return Decision{
			NextState: StateComplete,
			Reason:    "Every ring verified. The fleet is on the new version.",
		}
	}
	return Decision{
		NextState: StateRunning, NextRing: next,
		Reason: fmt.Sprintf("The %s ring verified; dispatching the %s ring.", outcome.Ring, next),
	}
}

func nextRing(current Ring) (Ring, bool) {
	for i, r := range Rings {
		if r == current && i+1 < len(Rings) {
			return Rings[i+1], true
		}
	}
	return "", false
}

// Resume restarts a halted or paused campaign at the ring that stopped it.
//
// It restarts at the FAILED ring, not the next one. Resuming past the ring that
// halted would skip exactly the agents whose failure stopped the rollout, and
// the campaign would report success over a fleet still running the broken
// build.
func Resume(state string, haltedAt Ring) (Decision, error) {
	switch state {
	case StateHalted, StatePaused:
	default:
		return Decision{}, fmt.Errorf("fleet: only a halted or paused campaign can be resumed, not one that is %s", state)
	}
	if haltedAt == "" {
		return Decision{}, fmt.Errorf("fleet: cannot resume a campaign that does not record which ring stopped it")
	}
	return Decision{
		NextState: StateRunning, NextRing: haltedAt,
		Reason: fmt.Sprintf(
			"Resumed at the %s ring — the one that halted it. Skipping ahead would leave the "+
				"agents whose failure stopped the rollout on the broken build while the campaign "+
				"reported success.", haltedAt),
	}, nil
}

// CanDispatch reports whether a campaign in this state may send upgrade jobs.
//
// Used by the worker before every dispatch. The console's pause button is only
// as real as this check: a pause that merely greys out a button while jobs keep
// flowing is worse than no pause, because an operator believes they stopped it.
func CanDispatch(state string) bool {
	return state == StatePending || state == StateRunning
}
