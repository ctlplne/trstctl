// SPDX-License-Identifier: BUSL-1.1

package migration_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/migration"
)

// The wave engine's one safety property (epic H2).
//
// Issue a leaf signed by the new root before that root's anchor has landed in
// the relying party's trust store, and every handshake to that endpoint fails.
// Not degrades — fails, for everyone, until somebody distributes the anchor by
// hand. That is what the ordering exists to prevent, so it is what these tests
// are about.

func fullTrustPlan() migration.Plan {
	return migration.Plan{ID: "p1", RequireFullTrust: true}
}

// THE test. An unverified cohort must not reach the issuing phase.
func TestAWaveCannotIssueBeforeTrustIsConfirmed(t *testing.T) {
	t.Parallel()
	w := migration.Wave{
		ID: "w1", Ordinal: 1, Phase: migration.PhaseVerifyingTrust,
		Members:   []string{"a", "b", "c"},
		TrustGate: migration.Gate{Total: 3, Confirmed: 2}, // one host unobserved
	}
	got, err := migration.Advance(fullTrustPlan(), w)
	if err == nil {
		t.Fatal("a wave advanced to issuing with an unconfirmed cohort; the successor leaves " +
			"would be signed by a root the remaining hosts do not trust, and every handshake " +
			"to them would fail")
	}
	if got.Phase != migration.PhaseVerifyingTrust {
		t.Errorf("the wave moved to %s despite the refusal", got.Phase)
	}
	var gateErr *migration.ErrGateNotMet
	if !errors.As(err, &gateErr) {
		t.Fatalf("error is %T, want a gate error carrying the counts an operator needs", err)
	}
	if gateErr.Gate.Unobserved() != 1 {
		t.Errorf("unobserved = %d, want 1; 'nobody looked' is the number that matters here",
			gateErr.Gate.Unobserved())
	}
}

// A fully confirmed cohort proceeds — so the test above cannot pass by the
// engine simply refusing everything.
func TestAConfirmedCohortAdvancesToIssuing(t *testing.T) {
	t.Parallel()
	w := migration.Wave{
		ID: "w1", Phase: migration.PhaseVerifyingTrust,
		Members:   []string{"a", "b"},
		TrustGate: migration.Gate{Total: 2, Confirmed: 2},
	}
	got, err := migration.Advance(fullTrustPlan(), w)
	if err != nil {
		t.Fatalf("a fully confirmed cohort was refused: %v", err)
	}
	if got.Phase != migration.PhaseIssuing {
		t.Fatalf("phase = %s, want issuing", got.Phase)
	}
}

// A single failure blocks regardless of threshold: a member that was checked
// and FAILED is not the same as one nobody reached.
func TestOneFailedMemberBlocksEvenUnderAPercentageThreshold(t *testing.T) {
	t.Parallel()
	p := migration.Plan{ID: "p1", RequireFullTrust: false, MinTrustPercent: 50}
	w := migration.Wave{
		Phase: migration.PhaseVerifyingTrust, Members: []string{"a", "b", "c", "d"},
		TrustGate: migration.Gate{Total: 4, Confirmed: 3, Failed: 1}, // 75% — over threshold
	}
	if _, err := migration.Advance(p, w); err == nil {
		t.Fatal("a cohort with a member that FAILED verification advanced because the percentage " +
			"was met; a known-broken host is different from an unreached one and must not be " +
			"averaged away")
	}
}

// The live gate is the second refusal: a wave whose endpoints are not serving
// must not carry a broken cohort into the next wave.
func TestAWaveWhoseEndpointsAreNotServingCannotComplete(t *testing.T) {
	t.Parallel()
	w := migration.Wave{
		Phase: migration.PhaseVerifyingLive, Members: []string{"a", "b"},
		LiveGate: migration.Gate{Total: 2, Confirmed: 1},
	}
	if _, err := migration.Advance(fullTrustPlan(), w); err == nil {
		t.Fatal("a wave completed with an endpoint not confirmed serving; the migration would " +
			"march through the estate leaving broken endpoints behind it, each wave reporting " +
			"success because the deploy was accepted")
	}
}

// Phases advance one at a time. Skipping is what the ordering exists to stop.
func TestPhasesCannotBeSkipped(t *testing.T) {
	t.Parallel()
	want := []migration.Phase{
		migration.PhaseDistributingTrust, migration.PhaseVerifyingTrust,
		migration.PhaseIssuing, migration.PhaseVerifyingLive, migration.PhaseComplete,
	}
	got := migration.PhasePlanned
	for i, expect := range want {
		next, err := migration.NextPhase(got)
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if next != expect {
			t.Fatalf("step %d: next after %s = %s, want %s; the sequence IS the safety property",
				i, got, next, expect)
		}
		got = next
	}
	if _, err := migration.NextPhase(migration.PhaseComplete); err == nil {
		t.Error("a complete wave advanced further")
	}
}

// Halting stops later waves without rewriting ones that already ran.
func TestHaltingDoesNotEraseWavesThatAlreadyExecuted(t *testing.T) {
	t.Parallel()
	waves := []migration.Wave{
		{ID: "w1", Ordinal: 1, Phase: migration.PhaseComplete},
		{ID: "w2", Ordinal: 2, Phase: migration.PhaseIssuing},
		{ID: "w3", Ordinal: 3, Phase: migration.PhasePlanned},
	}
	waves = migration.Halt(waves, 1, "trust gate failed")

	if waves[0].Phase != migration.PhaseComplete {
		t.Errorf("wave 1 became %s; a completed wave rewritten as halted erases the fact that it "+
			"was deployed and may need attention", waves[0].Phase)
	}
	if waves[1].Phase != migration.PhaseHalted || waves[2].Phase != migration.PhaseHalted {
		t.Errorf("later waves = %s/%s, want halted", waves[1].Phase, waves[2].Phase)
	}
	if waves[2].HaltReason == "" {
		t.Error("a halted wave carries no reason, so an operator cannot tell why it stopped")
	}
}

// Rollback runs NEWEST FIRST, and only over waves that changed something.
func TestRollbackReversesNewestFirstAndSkipsWavesThatNeverRan(t *testing.T) {
	t.Parallel()
	waves := []migration.Wave{
		{ID: "w1", Ordinal: 1, Phase: migration.PhaseComplete},
		{ID: "w2", Ordinal: 2, Phase: migration.PhaseVerifyingLive},
		{ID: "w3", Ordinal: 3, Phase: migration.PhasePlanned}, // never ran
		{ID: "w4", Ordinal: 4, Phase: migration.PhaseHalted},  // never ran
	}
	order := migration.RollbackOrder(waves)
	if len(order) != 2 {
		t.Fatalf("rollback covers %d waves, want 2; a wave that never ran has nothing to reverse "+
			"and 'rolling it back' would be a no-op dressed as work", len(order))
	}
	if order[0].ID != "w2" || order[1].ID != "w1" {
		t.Fatalf("rollback order = %s,%s; want newest first — undoing front-to-back would remove "+
			"an anchor a later still-live wave depends on, breaking endpoints that were working",
			order[0].ID, order[1].ID)
	}
}

// A member in two waves would have its first wave's verification silently
// replaced by the second's re-issue.
func TestAMemberCannotAppearInTwoWaves(t *testing.T) {
	t.Parallel()
	p := migration.Plan{
		ID: "p1", RequireFullTrust: true,
		Waves: []migration.Wave{
			{ID: "w1", Ordinal: 1, Members: []string{"a", "b"}},
			{ID: "w2", Ordinal: 2, Members: []string{"b", "c"}},
		},
	}
	if err := migration.ValidatePlan(p); err == nil {
		t.Fatal("a plan with a member in two waves validated; it would be migrated twice and the " +
			"first wave's verification silently discarded")
	}
}

// Duplicate ordinals make the order undefined, which defeats the whole engine.
func TestDuplicateOrdinalsAreRefused(t *testing.T) {
	t.Parallel()
	p := migration.Plan{
		ID: "p1", RequireFullTrust: true,
		Waves: []migration.Wave{
			{ID: "w1", Ordinal: 1, Members: []string{"a"}},
			{ID: "w2", Ordinal: 1, Members: []string{"b"}},
		},
	}
	if err := migration.ValidatePlan(p); err == nil {
		t.Fatal("two waves shared an ordinal; their relative order is undefined and the " +
			"trust-before-leaf sequence cannot be guaranteed")
	}
}

// A partial-trust plan must state its threshold rather than inheriting one.
func TestAPartialTrustPlanMustNameItsThreshold(t *testing.T) {
	t.Parallel()
	p := migration.Plan{
		ID: "p1", RequireFullTrust: false, MinTrustPercent: 0,
		Waves: []migration.Wave{{ID: "w1", Ordinal: 1, Members: []string{"a"}}},
	}
	if err := migration.ValidatePlan(p); err == nil {
		t.Fatal("a plan opted out of full trust without naming a threshold; the members it would " +
			"skip are exactly the ones that break, so that has to be someone's decision")
	}
}
