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
)

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
}

// AssessedWave is one wave's read-only summary.
type AssessedWave struct {
	ID       string   `json:"id"`
	Ordinal  int      `json:"ordinal"`
	Members  []string `json:"members"`
	Blocked  []string `json:"blocked"`
	Guidance string   `json:"guidance,omitempty"`
}

const assessGuidance = "This is a read-only assessment: nothing was distributed, issued, or " +
	"deployed. Unknowns are gaps in what has been OBSERVED, not findings about the estate — a " +
	"member with no observed trust store is not a member confirmed to have an empty one, and only " +
	"the second is safe to migrate. Resolve the unknowns, or accept that those members are the " +
	"ones most likely to break, before starting."

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
}

// Assess enumerates what a plan would touch and what is unknown about it.
func Assess(p Plan, facts map[string]MemberFacts) Assessment {
	out := Assessment{PlanID: p.ID, Guidance: assessGuidance}
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
