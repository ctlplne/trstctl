// SPDX-License-Identifier: BUSL-1.1

package migration

import (
	"fmt"
	"sort"
)

// Assess before migrate (epic H2).
//
// A read-only pass that answers "what would this migration touch, and what do I
// not know about it" — WITHOUT mutating anything. It exists because the honest
// answer to the second half is usually "more than you think", and finding that
// out during the migration is finding it out too late.
//
// The unknowns are the point. A dependency the engine can enumerate is one it
// can sequence; a dependency it cannot see is one that breaks in wave three
// while everyone is watching wave one. So this reports both, and reports them
// as different things: a member with no observed trust store is not a member
// with a confirmed empty trust store, and only one of those is safe to migrate.

// Unknown is something the assessment could not determine.
//
// Distinct from a finding: a finding is a fact about the estate, an unknown is a
// fact about the ASSESSMENT — a gap in what has been observed. Merging them
// would let "we did not look" render as "there is nothing there".
type Unknown struct {
	Member string `json:"member"`
	// Kind is a closed-set reason, so a console can group and count them.
	Kind string `json:"kind"`
	// Detail says what an operator would have to do to resolve it.
	Detail string `json:"detail"`
}

// Closed set of unknown kinds.
const (
	// UnknownNoTrustStore: nothing has been observed carrying any anchor for
	// this member's host. Migrating it is a coin flip.
	UnknownNoTrustStore = "no_trust_store_observed"
	// UnknownNoVerificationAddress: the member has no configured listener, so
	// the live gate can never confirm it — it would sit unobserved forever.
	UnknownNoVerificationAddress = "no_verification_address"
	// UnknownNoDeploymentTarget: nothing knows how to deliver to this member.
	UnknownNoDeploymentTarget = "no_deployment_target"
	// UnknownPredecessorNotRevocable: a planned switch (P3) revokes each
	// member's current certificate through the trstctl CA that issued it, and
	// this member's cannot be resolved to one, so the start would refuse it
	// (P3-L4).
	UnknownPredecessorNotRevocable = "predecessor_not_revocable"
)

// Predecessor is one row of a planned switch's preview (P3-L4): the
// certificate a switch would revoke (superseded) for the member once its
// successor is verified live, and the CA that would revoke it.
type Predecessor struct {
	Member        string `json:"member"`
	CertificateID string `json:"certificate_id,omitempty"`
	Serial        string `json:"serial,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	CAID          string `json:"ca_id,omitempty"`
	// ExternalCAID names the vendor CA that would revoke a predecessor no
	// trstctl CA issued (P3-L2); CAID is then empty.
	ExternalCAID string `json:"external_ca_id,omitempty"`
	CAName       string `json:"ca_name,omitempty"`
	// Revocable is false when a switch could not revoke it; Problem says why.
	Revocable bool   `json:"revocable"`
	Problem   string `json:"problem,omitempty"`
}

// Assessment is the read-only answer.
type Assessment struct {
	PlanID string `json:"plan_id"`
	// Waves mirrors the plan's shape so an operator reviews what would run.
	Waves []AssessedWave `json:"waves"`
	// Unknowns are gathered across every wave, because the question "what do I
	// not know" is asked of the migration, not of one cohort.
	Unknowns []Unknown `json:"unknowns"`
	// Members is the total across all waves.
	Members int `json:"members"`
	// Migratable is Members minus those with a blocking unknown. It is
	// deliberately NOT presented as a readiness percentage: a migration that is
	// "94% ready" still takes down the other 6%, and a percentage invites
	// someone to round it up.
	Migratable int    `json:"migratable"`
	Guidance   string `json:"guidance"`
	// RevokePredecessors says this assessed a planned switch (P3-L4), and
	// Predecessors then lists, member by member, what it would revoke.
	RevokePredecessors bool          `json:"revoke_predecessors"`
	Predecessors       []Predecessor `json:"predecessors,omitempty"`
}

// AssessedWave is one wave's read-only summary.
type AssessedWave struct {
	ID       string   `json:"id"`
	Ordinal  int      `json:"ordinal"`
	Members  []string `json:"members"`
	Blocked  []string `json:"blocked"`
	Guidance string   `json:"guidance,omitempty"`
}

const switchGuidance = " This assesses a planned switch: once a member's successor is verified " +
	"live, the certificate listed for it is revoked (superseded) through the CA named beside it, " +
	"and a certificate no trstctl CA can revoke blocks the start."

const assessGuidance = "This is a read-only assessment: nothing was distributed, issued, or " +
	"deployed. Unknowns are gaps in what has been OBSERVED, not findings about the estate — a " +
	"member with no observed trust store is not a member confirmed to have an empty one. " +
	"Any unknown blocks the start of a migration. Observe the missing trust store, " +
	"deployment target, or verification listener, then check again."

// MemberFacts is what the caller already knows about one member, gathered from
// the graph (H1), the deployment targets, and the verification config (D2).
//
// Passed in rather than fetched here so this package stays free of store and
// HTTP dependencies — the sequencing logic is the valuable part and it should be
// testable without a database.
type MemberFacts struct {
	Member string
	// TrustStoresObserved is how many trust stores have been seen on this
	// member's host. Zero means unobserved, which is the unknown.
	TrustStoresObserved int
	HasDeploymentTarget bool
	HasVerifyAddress    bool
	// Predecessor is what a planned switch would revoke for this member; nil
	// when the switch is not being assessed, or its certificate was not read.
	Predecessor *PredecessorFacts
}

// PredecessorFacts is a member's current certificate and the trstctl CA that
// issued it, as a planned switch would bind them.
type PredecessorFacts struct {
	CertificateID string
	Serial        string
	Fingerprint   string
	CAID          string
	ExternalCAID  string
	CAName        string
	// Problem says why a switch could not revoke it; empty when it can.
	Problem string
}

// Assess enumerates what a plan would touch and what is unknown about it.
func Assess(p Plan, facts map[string]MemberFacts) Assessment {
	return assess(p, facts, false)
}

// AssessSwitch is Assess for a planned CA switch (P3-L4): it also lists the
// certificate each member's switch would revoke and the CA that would revoke
// it, and one no trstctl CA can revoke is an unknown that blocks the start.
func AssessSwitch(p Plan, facts map[string]MemberFacts) Assessment {
	return assess(p, facts, true)
}

func assess(p Plan, facts map[string]MemberFacts, switching bool) Assessment {
	out := Assessment{PlanID: p.ID, Guidance: assessGuidance, RevokePredecessors: switching}
	if switching {
		out.Guidance += switchGuidance
		out.Predecessors = []Predecessor{}
	}
	waves := append([]Wave(nil), p.Waves...)
	sort.SliceStable(waves, func(i, j int) bool { return waves[i].Ordinal < waves[j].Ordinal })

	for _, w := range waves {
		aw := AssessedWave{ID: w.ID, Ordinal: w.Ordinal, Members: append([]string(nil), w.Members...)}
		for _, m := range w.Members {
			out.Members++
			f, known := facts[m]
			blocked := false
			if !known || f.TrustStoresObserved == 0 {
				out.Unknowns = append(out.Unknowns, Unknown{
					Member: m, Kind: UnknownNoTrustStore,
					Detail: "no trust store has been observed on this member's host, so there is " +
						"no way to confirm the new anchor landed before its leaves are issued",
				})
				blocked = true
			}
			if known && !f.HasDeploymentTarget {
				out.Unknowns = append(out.Unknowns, Unknown{
					Member: m, Kind: UnknownNoDeploymentTarget,
					Detail: "no deployment target is configured, so a successor certificate could " +
						"be issued but never delivered",
				})
				blocked = true
			}
			if known && !f.HasVerifyAddress {
				out.Unknowns = append(out.Unknowns, Unknown{
					Member: m, Kind: UnknownNoVerificationAddress,
					Detail: "no listener address is configured, so the live gate can never confirm " +
						"this member and the wave would wait on it forever",
				})
				blocked = true
			}
			if switching {
				row := Predecessor{Member: m, Problem: "the member's current certificate was not read"}
				if pf := f.Predecessor; known && pf != nil {
					row = Predecessor{Member: m, CertificateID: pf.CertificateID, Serial: pf.Serial,
						Fingerprint: pf.Fingerprint, CAID: pf.CAID, ExternalCAID: pf.ExternalCAID, CAName: pf.CAName, Problem: pf.Problem}
				}
				row.Revocable = row.Problem == ""
				out.Predecessors = append(out.Predecessors, row)
				if !row.Revocable {
					out.Unknowns = append(out.Unknowns, Unknown{
						Member: m, Kind: UnknownPredecessorNotRevocable,
						Detail: "a switch revokes each member's current certificate through the trstctl CA " +
							"that issued it, and this one cannot be: " + row.Problem,
					})
					blocked = true
				}
			}
			if blocked {
				aw.Blocked = append(aw.Blocked, m)
				continue
			}
			out.Migratable++
		}
		if len(aw.Blocked) > 0 {
			aw.Guidance = fmt.Sprintf("%d of %d members in this wave have unresolved unknowns and "+
				"would either block its gates or migrate blind.", len(aw.Blocked), len(aw.Members))
		}
		out.Waves = append(out.Waves, aw)
	}
	if out.Waves == nil {
		out.Waves = []AssessedWave{}
	}
	if out.Unknowns == nil {
		out.Unknowns = []Unknown{}
	}
	return out
}
