// SPDX-License-Identifier: BUSL-1.1

package migration_test

import (
	"strings"
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
	if !strings.Contains(a.Guidance, "blocks the start") || !strings.Contains(a.Guidance, "check again") || strings.Contains(a.Guidance, "accept that") {
		t.Errorf("unknown-member guidance must explain the fail-closed start gate and recheck, got %q", a.Guidance)
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

// P3-L4: assessing a planned switch lists, member by member, the certificate
// the switch would revoke and the CA that would revoke it. One no trstctl CA
// can revoke is a blocking unknown, because the start refuses it; a plain
// assessment lists no predecessors.
func TestAssessSwitchListsWhatItWouldRevokeP3L4(t *testing.T) {
	t.Parallel()
	p := migration.Plan{
		ID: "switch", RequireFullTrust: true,
		Waves: []migration.Wave{{ID: "canary", Ordinal: 1, Members: []string{"issued", "imported", "unread"}}},
	}
	ready := func(m string, pf *migration.PredecessorFacts) migration.MemberFacts {
		return migration.MemberFacts{Member: m, TrustStoresObserved: 1, HasDeploymentTarget: true, HasVerifyAddress: true, Predecessor: pf}
	}
	facts := map[string]migration.MemberFacts{
		"issued": ready("issued", &migration.PredecessorFacts{CertificateID: "cert-1", Serial: "0a1b", Fingerprint: "ff00",
			CAID: "ca-1", CAName: "Platform issuing CA"}),
		"imported": ready("imported", &migration.PredecessorFacts{CertificateID: "cert-2", Serial: "0c2d",
			Problem: "its current certificate does not resolve to exactly one trstctl CA that can revoke it"}),
		"unread": ready("unread", nil),
	}
	a := migration.AssessSwitch(p, facts)
	if !a.RevokePredecessors || len(a.Predecessors) != 3 {
		t.Fatalf("switch assessment = %+v", a)
	}
	want := migration.Predecessor{Member: "issued", CertificateID: "cert-1", Serial: "0a1b", Fingerprint: "ff00",
		CAID: "ca-1", CAName: "Platform issuing CA", Revocable: true}
	if a.Predecessors[0] != want {
		t.Fatalf("revocable row = %+v, want %+v", a.Predecessors[0], want)
	}
	if row := a.Predecessors[1]; row.Revocable || row.Serial != "0c2d" || !strings.Contains(row.Problem, "exactly one trstctl CA") {
		t.Fatalf("an imported certificate's row = %+v", row)
	}
	if row := a.Predecessors[2]; row.Revocable || row.Problem == "" {
		t.Fatalf("an unread certificate's row = %+v", row)
	}
	if a.Migratable != 1 || len(a.Waves[0].Blocked) != 2 {
		t.Fatalf("migratable %d, blocked %v; want 1 and the two that cannot be revoked", a.Migratable, a.Waves[0].Blocked)
	}
	kinds := 0
	for _, u := range a.Unknowns {
		if u.Kind == migration.UnknownPredecessorNotRevocable {
			kinds++
		}
	}
	if kinds != 2 || !strings.Contains(a.Guidance, "planned switch") {
		t.Fatalf("%d predecessor unknowns, guidance %q", kinds, a.Guidance)
	}

	plain := migration.Assess(p, facts)
	if plain.RevokePredecessors || plain.Predecessors != nil || plain.Migratable != 3 {
		t.Fatalf("a plain assessment = %+v", plain)
	}
}
