// SPDX-License-Identifier: MPL-2.0

package migration_test

import (
	"testing"

	"trstctl.com/trstctl/internal/migration"
)

// Assess before migrate (epic H2).
//
// The value is entirely in the unknowns, and in keeping them distinct from
// findings. A member with no OBSERVED trust store is not a member confirmed to
// have an empty one — only the second is safe to migrate, and collapsing the two
// is how an assessment reassures someone into an outage.

func TestAnUnobservedMemberIsAnUnknownNotAPass(t *testing.T) {
	t.Parallel()
	p := migration.Plan{
		ID: "p1", RequireFullTrust: true,
		Waves: []migration.Wave{{ID: "w1", Ordinal: 1, Members: []string{"known", "never-scanned"}}},
	}
	facts := map[string]migration.MemberFacts{
		"known": {Member: "known", TrustStoresObserved: 2, HasDeploymentTarget: true, HasVerifyAddress: true},
		// "never-scanned" is absent entirely — nobody has looked at it.
	}
	a := migration.Assess(p, facts)

	if a.Members != 2 {
		t.Fatalf("members = %d, want 2", a.Members)
	}
	if a.Migratable != 1 {
		t.Errorf("migratable = %d, want 1; an unscanned member counted as ready is the one that "+
			"breaks", a.Migratable)
	}
	found := false
	for _, u := range a.Unknowns {
		if u.Member == "never-scanned" && u.Kind == migration.UnknownNoTrustStore {
			found = true
		}
	}
	if !found {
		t.Error("a member nobody has scanned produced no unknown; the assessment would read as " +
			"though its trust store had been checked and found fine")
	}
	if len(a.Waves) != 1 || len(a.Waves[0].Blocked) != 1 {
		t.Errorf("wave blocked list = %+v, want the unscanned member", a.Waves)
	}
}

// A member with no listener can never satisfy the live gate — the wave would
// wait on it forever, which is a different failure from breaking.
func TestAMemberWithNoListenerIsFlaggedBeforeItStallsAWave(t *testing.T) {
	t.Parallel()
	p := migration.Plan{
		ID: "p1", RequireFullTrust: true,
		Waves: []migration.Wave{{ID: "w1", Ordinal: 1, Members: []string{"m"}}},
	}
	a := migration.Assess(p, map[string]migration.MemberFacts{
		"m": {Member: "m", TrustStoresObserved: 1, HasDeploymentTarget: true, HasVerifyAddress: false},
	})
	found := false
	for _, u := range a.Unknowns {
		if u.Kind == migration.UnknownNoVerificationAddress {
			found = true
		}
	}
	if !found {
		t.Fatal("a member with no listener address was not flagged; the live gate could never " +
			"confirm it and the wave would sit unobserved forever")
	}
}

// A member nothing can deliver to would be issued a certificate that never
// arrives.
func TestAMemberWithNoDeploymentTargetIsFlagged(t *testing.T) {
	t.Parallel()
	p := migration.Plan{
		ID: "p1", RequireFullTrust: true,
		Waves: []migration.Wave{{ID: "w1", Ordinal: 1, Members: []string{"m"}}},
	}
	a := migration.Assess(p, map[string]migration.MemberFacts{
		"m": {Member: "m", TrustStoresObserved: 1, HasDeploymentTarget: false, HasVerifyAddress: true},
	})
	found := false
	for _, u := range a.Unknowns {
		if u.Kind == migration.UnknownNoDeploymentTarget {
			found = true
		}
	}
	if !found {
		t.Fatal("a member with no deployment target was not flagged; it would be issued a " +
			"successor that is never delivered")
	}
}

// Assessment mutates nothing — it is the whole promise of the mode.
func TestAssessDoesNotMutateThePlan(t *testing.T) {
	t.Parallel()
	p := migration.Plan{
		ID: "p1", RequireFullTrust: true,
		Waves: []migration.Wave{
			{ID: "w2", Ordinal: 2, Phase: migration.PhasePlanned, Members: []string{"b"}},
			{ID: "w1", Ordinal: 1, Phase: migration.PhasePlanned, Members: []string{"a"}},
		},
	}
	_ = migration.Assess(p, map[string]migration.MemberFacts{})

	// The caller's plan keeps its own order and phases: Assess sorts a COPY.
	if p.Waves[0].ID != "w2" || p.Waves[1].ID != "w1" {
		t.Error("Assess reordered the caller's plan in place")
	}
	for _, w := range p.Waves {
		if w.Phase != migration.PhasePlanned {
			t.Errorf("wave %s phase became %s; a read-only assessment moved a wave", w.ID, w.Phase)
		}
	}
}

// The assessment reports waves in execution order, whatever order they arrived.
func TestAssessedWavesAreInExecutionOrder(t *testing.T) {
	t.Parallel()
	p := migration.Plan{
		ID: "p1", RequireFullTrust: true,
		Waves: []migration.Wave{
			{ID: "w3", Ordinal: 3, Members: []string{"c"}},
			{ID: "w1", Ordinal: 1, Members: []string{"a"}},
			{ID: "w2", Ordinal: 2, Members: []string{"b"}},
		},
	}
	a := migration.Assess(p, map[string]migration.MemberFacts{})
	for i, want := range []string{"w1", "w2", "w3"} {
		if a.Waves[i].ID != want {
			t.Fatalf("wave %d = %s, want %s; an operator reviewing what would run needs it in the "+
				"order it would run", i, a.Waves[i].ID, want)
		}
	}
}
