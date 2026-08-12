// SPDX-License-Identifier: MPL-2.0

// Package migration is the generic wave engine behind CA rollover (epic H2).
//
// Generic on purpose: it knows about ordering, cohorts and gates, and nothing
// about what is being migrated. That is what lets a licensed campaign under ee/
// drive the same sequencing without this package growing a dependency on it —
// the engine stays MPL core, and anything algorithm-specific stays behind the
// AN-9 boundary where the contract puts it.
//
// The only "wave" in the codebase before this was a free-text label on a
// lifecycle row. It sorted a report and did nothing else: an operator could
// write Wave 2 on a hundred identities and the system would still re-issue all
// of them at once, because nothing read the field.
//
// A real wave engine exists for one reason — ORDERING IS A SAFETY PROPERTY, and
// getting it wrong during a CA migration is how an estate goes dark. The failure
// is specific and worth naming: issue a leaf signed by the new root before that
// root's anchor has landed in the relying party's trust store, and every
// handshake to that endpoint fails. Not degrades — fails, for everyone, until
// somebody notices and distributes the anchor by hand.
//
// So the phase order here is not a workflow convenience. It is the invariant:
//
//	distribute trust → VERIFY trust landed → issue successor leaves →
//	VERIFY live → advance to the next wave
//
// Both verify steps are gates, not steps, and the distinction is the whole
// design. A step is something you do; a gate is something that must be TRUE
// before you may proceed, established by evidence someone else produced. The
// engine will not enter the issuing phase on a cohort whose trust distribution
// has not been observed landing, and it does not accept "we sent it" as
// evidence that it arrived — that is the delivered-vs-verified distinction D3
// exists to keep apart, applied to the one place where confusing them takes an
// estate offline.
package migration

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Phase is where a wave is in the sequence.
//
// A closed, ORDERED set. The order is the safety property, so it is expressed
// as data (ordinal) rather than as a switch statement someone can extend in the
// wrong place.
type Phase string

const (
	// PhasePlanned: the wave exists as a membership set and has not started.
	PhasePlanned Phase = "planned"
	// PhaseDistributingTrust: the new anchor is being pushed to the cohort.
	PhaseDistributingTrust Phase = "distributing_trust"
	// PhaseVerifyingTrust: waiting for evidence the anchor LANDED. This is a
	// gate, not a step — "we queued the distribution" is not evidence.
	PhaseVerifyingTrust Phase = "verifying_trust"
	// PhaseIssuing: successor leaves under the new authority. Reachable only
	// once trust is verified on the cohort.
	PhaseIssuing Phase = "issuing"
	// PhaseVerifyingLive: waiting for evidence the endpoints actually serve the
	// successors (D2's handshake receipts).
	PhaseVerifyingLive Phase = "verifying_live"
	// PhaseRevokingPredecessor is incident-only. Every successor in the cohort
	// has passed its signed live listener gate; the next cohort remains blocked
	// until the exact predecessor revocations are event-projected.
	PhaseRevokingPredecessor Phase = "revoking_predecessor"
	// PhaseComplete: this wave is done and the next may start.
	PhaseComplete Phase = "complete"
	// PhaseHalted: a gate failed. The wave stopped where it was.
	//
	// HALTED IS NOT FAILED, and the vocabulary keeps them apart deliberately:
	// a halted wave may have changed nothing at all, and sending an operator to
	// investigate machines that are serving perfectly well wastes the attention
	// an incident most needs.
	PhaseHalted Phase = "halted"
	// PhaseRolledBack: the wave's changes were reversed.
	PhaseRolledBack Phase = "rolled_back"
)

// phaseOrder gives each phase its position in the sequence.
//
// Terminal phases share the sentinel -1: they are not points on the line, and
// giving them ordinals would let a comparison accidentally treat "halted" as
// further along than "issuing".
var phaseOrder = map[Phase]int{
	PhasePlanned:             0,
	PhaseDistributingTrust:   1,
	PhaseVerifyingTrust:      2,
	PhaseIssuing:             3,
	PhaseVerifyingLive:       4,
	PhaseRevokingPredecessor: 5,
	PhaseComplete:            6,
	PhaseHalted:              -1,
	PhaseRolledBack:          -1,
}

// Terminal reports whether a phase ends the wave.
func (p Phase) Terminal() bool { return p == PhaseHalted || p == PhaseRolledBack || p == PhaseComplete }

// Gate is the evidence a wave needs to leave a verifying phase.
//
// Counts rather than a boolean, because "how much of the cohort is confirmed"
// is the question an operator is actually asking, and a boolean would force the
// engine to pick a threshold and hide it.
type Gate struct {
	// Observed is how many cohort members have been checked at all.
	Observed int
	// Confirmed is how many were checked and PASSED.
	Confirmed int
	// Failed is how many were checked and did not pass.
	Failed int
	// Total is the cohort size. Members neither confirmed nor failed are
	// UNOBSERVED, and the difference matters: nobody looked is not the same as
	// looked and found nothing wrong.
	Total int
}

// Unobserved is the cohort nobody has checked yet.
func (g Gate) Unobserved() int {
	n := g.Total - g.Confirmed - g.Failed
	if n < 0 {
		return 0
	}
	return n
}

// ErrGateNotMet explains why a wave may not advance.
type ErrGateNotMet struct {
	Phase  Phase
	Gate   Gate
	Reason string
}

func (e *ErrGateNotMet) Error() string { return e.Reason }

// Wave is one ordered cohort of a migration.
type Wave struct {
	ID      string
	Ordinal int
	// Members are the identities this wave migrates.
	Members []string
	Phase   Phase
	// TrustGate is evidence the new anchor landed on this cohort.
	TrustGate Gate
	// LiveGate is evidence the cohort's endpoints serve the successors.
	LiveGate Gate
	// HaltReason is set when Phase is Halted, in operator-facing words.
	HaltReason string
	StartedAt  time.Time
	UpdatedAt  time.Time
}

// Plan is a whole migration: ordered waves plus the policy they advance under.
type Plan struct {
	ID    string
	Waves []Wave
	// RequireFullTrust demands EVERY member's trust be confirmed before issuing.
	//
	// Default true, and the default is the safe one. A partial-trust threshold
	// is legitimate for a large estate where a handful of hosts are always
	// unreachable, but it has to be a decision someone made rather than one the
	// engine made for them, because the members it skips are exactly the ones
	// that will break.
	RequireFullTrust bool
	// MinTrustPercent is the threshold used when RequireFullTrust is false.
	MinTrustPercent int
	// DualTrustOverlap is how long both anchors stay distributed after a wave
	// completes.
	//
	// Non-zero is what makes rollback possible at all. Remove the old anchor the
	// moment the new one lands and a rollback has nowhere to go: the successors
	// are already serving, the predecessors are no longer trusted, and the only
	// route back is a second full distribution under incident pressure.
	DualTrustOverlap time.Duration
}

// ErrOutOfOrder is returned when a caller tries to skip the sequence.
var ErrOutOfOrder = errors.New("migration: phases must advance in order")

// NextPhase returns the phase that follows p, or an error at a terminal phase.
func NextPhase(p Phase) (Phase, error) {
	switch p {
	case PhasePlanned:
		return PhaseDistributingTrust, nil
	case PhaseDistributingTrust:
		return PhaseVerifyingTrust, nil
	case PhaseVerifyingTrust:
		return PhaseIssuing, nil
	case PhaseIssuing:
		return PhaseVerifyingLive, nil
	case PhaseVerifyingLive:
		return PhaseComplete, nil
	default:
		return p, fmt.Errorf("%w: %q is terminal", ErrOutOfOrder, p)
	}
}

// Advance moves a wave to its next phase if the gate for its CURRENT phase is
// met, and refuses otherwise.
//
// This function is the engine. Everything else is bookkeeping around the two
// refusals it makes:
//
//   - Leaving VerifyingTrust requires confirmed trust. This is the one that
//     prevents the estate going dark, because the next phase issues leaves the
//     cohort cannot validate without it.
//   - Leaving VerifyingLive requires confirmed serving. This one prevents a
//     migration marching through an estate leaving broken endpoints behind it,
//     each wave reporting success because the deploy was accepted.
func Advance(p Plan, w Wave) (Wave, error) {
	if w.Phase.Terminal() {
		return w, fmt.Errorf("%w: wave %s is %s", ErrOutOfOrder, w.ID, w.Phase)
	}
	switch w.Phase {
	case PhaseVerifyingTrust:
		if err := checkGate(p, w.TrustGate, PhaseVerifyingTrust,
			"the new trust anchor has not been confirmed on this cohort, so issuing successor "+
				"certificates now would produce leaves these hosts cannot validate"); err != nil {
			return w, err
		}
	case PhaseVerifyingLive:
		if err := checkGate(p, w.LiveGate, PhaseVerifyingLive,
			"this cohort's endpoints have not been confirmed serving their successors, so "+
				"advancing would carry a broken wave into the next one"); err != nil {
			return w, err
		}
	}
	next, err := NextPhase(w.Phase)
	if err != nil {
		return w, err
	}
	w.Phase = next
	return w, nil
}

// checkGate applies the plan's policy to one gate.
func checkGate(p Plan, g Gate, phase Phase, why string) error {
	if g.Failed > 0 {
		return &ErrGateNotMet{Phase: phase, Gate: g,
			Reason: fmt.Sprintf("%d of %d cohort members failed verification: %s", g.Failed, g.Total, why)}
	}
	if g.Total == 0 {
		// An empty cohort passes vacuously. Refusing would strand a wave whose
		// membership legitimately resolved to nothing.
		return nil
	}
	if p.RequireFullTrust || p.MinTrustPercent <= 0 {
		if g.Confirmed < g.Total {
			return &ErrGateNotMet{Phase: phase, Gate: g,
				Reason: fmt.Sprintf("%d of %d cohort members are confirmed and %d have not been "+
					"observed at all: %s", g.Confirmed, g.Total, g.Unobserved(), why)}
		}
		return nil
	}
	pct := g.Confirmed * 100 / g.Total
	if pct < p.MinTrustPercent {
		return &ErrGateNotMet{Phase: phase, Gate: g,
			Reason: fmt.Sprintf("%d%% of the cohort is confirmed, below the %d%% this plan "+
				"requires: %s", pct, p.MinTrustPercent, why)}
	}
	return nil
}

// Halt stops a wave and every wave after it.
//
// Later waves are marked halted rather than failed, and never overwrite a wave
// that already ran: a run whose gate fails after later waves executed is a worse
// situation than a clean halt, and rewriting their phase would erase the fact
// that they were deployed and need attention.
func Halt(waves []Wave, from int, reason string) []Wave {
	for i := range waves {
		if i < from || waves[i].Phase == PhaseComplete || waves[i].Phase == PhaseRolledBack {
			continue
		}
		waves[i].Phase = PhaseHalted
		if waves[i].HaltReason == "" {
			waves[i].HaltReason = reason
		}
	}
	return waves
}

// RollbackOrder returns the waves to reverse, NEWEST FIRST.
//
// Reverse order is not a detail. Waves were sequenced so that trust preceded
// leaves; undoing them front-to-back would remove an anchor that a later,
// still-live wave is depending on, breaking endpoints that were working. A
// rollback that damages the part of the estate that succeeded is worse than no
// rollback.
func RollbackOrder(waves []Wave) []Wave {
	out := make([]Wave, 0, len(waves))
	for _, w := range waves {
		// Only waves that CHANGED something need reversing. A planned or halted
		// wave never ran, so "rolling it back" would be a no-op dressed as work.
		if phaseOrder[w.Phase] >= phaseOrder[PhaseIssuing] || w.Phase == PhaseComplete {
			out = append(out, w)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Ordinal > out[j].Ordinal })
	return out
}

// HaltReasonFor is the operator-facing sentence for a halted migration.
func HaltReasonFor(phase Phase, g Gate) string {
	switch phase {
	case PhaseVerifyingTrust:
		return fmt.Sprintf("trust distribution was not confirmed on this cohort (%d of %d "+
			"confirmed, %d failed, %d unobserved). The remaining waves were halted before "+
			"anything was issued, so nothing in them changed.",
			g.Confirmed, g.Total, g.Failed, g.Unobserved())
	case PhaseVerifyingLive:
		return fmt.Sprintf("this cohort's endpoints were not confirmed serving their successors "+
			"(%d of %d confirmed, %d failed, %d unobserved). The remaining waves were halted; "+
			"this wave's own changes were applied and may need rollback.",
			g.Confirmed, g.Total, g.Failed, g.Unobserved())
	default:
		return "the migration was halted."
	}
}

// ValidatePlan rejects a plan the engine cannot run safely.
func ValidatePlan(p Plan) error {
	if len(p.Waves) == 0 {
		return errors.New("migration: a plan needs at least one wave")
	}
	seenOrdinal := map[int]bool{}
	seenMember := map[string]string{}
	for _, w := range p.Waves {
		if seenOrdinal[w.Ordinal] {
			return fmt.Errorf("migration: two waves share ordinal %d, so their order is undefined "+
				"and the trust-before-leaf sequence cannot be guaranteed", w.Ordinal)
		}
		seenOrdinal[w.Ordinal] = true
		for _, m := range w.Members {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			if prev, dup := seenMember[m]; dup {
				// A member in two waves would be migrated twice, and the second
				// wave would re-issue over a successor the first already
				// verified — silently discarding evidence.
				return fmt.Errorf("migration: %s appears in waves %s and %s; a member migrated "+
					"twice has its first wave's verification silently replaced", m, prev, w.ID)
			}
			seenMember[m] = w.ID
		}
	}
	if !p.RequireFullTrust && (p.MinTrustPercent <= 0 || p.MinTrustPercent > 100) {
		return fmt.Errorf("migration: a plan that does not require full trust must set a "+
			"threshold between 1 and 100; got %d", p.MinTrustPercent)
	}
	return nil
}
