// SPDX-License-Identifier: BUSL-1.1

package migration

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Canary-first cohort planning (P3-L1). A migration run lists its cohorts
// explicitly; the planner builds them read-only from a selector (issuer,
// profile, owner or connector), so an estate is not typed in by hand. The
// first cohort is the canary: small, so a failed live check pauses the run
// before most of the estate is touched. The plan is a proposal to review,
// assess and start, never an effect.

// Bounds on a cohort plan.
const (
	DefaultCanarySize = 1
	MaxCanarySize     = 10
	DefaultCohortSize = 25
	MaxCohortSize     = 500
	// MaxCohortPlanMembers caps the members one plan places; a selector that
	// matches more says the plan was truncated.
	MaxCohortPlanMembers = 1000
)

// CohortCandidate is one identity a plan may place.
type CohortCandidate struct {
	IdentityID string
	Name       string
	// AgentID is the host agent bound to the identity's deployment target;
	// empty when the target names none (an appliance's relay is the
	// operator's choice).
	AgentID string
}

// PlannedMember is one placed identity.
type PlannedMember struct {
	IdentityID string `json:"identity_id"`
	Name       string `json:"name"`
	AgentID    string `json:"agent_id,omitempty"`
}

// PlannedCohort is one proposed wave: "canary" first, then "cohort-2" on.
type PlannedCohort struct {
	ID      string          `json:"id"`
	Ordinal int             `json:"ordinal"`
	Members []PlannedMember `json:"members"`
}

// PlanCohorts orders candidates by name, then identity id, and cuts a canary
// of canarySize, then cohorts of cohortSize. A duplicate identity is placed
// once.
func PlanCohorts(candidates []CohortCandidate, canarySize, cohortSize int) ([]PlannedCohort, error) {
	if canarySize < 1 || canarySize > MaxCanarySize {
		return nil, fmt.Errorf("migration: canary_size must be between 1 and %d", MaxCanarySize)
	}
	if cohortSize < 1 || cohortSize > MaxCohortSize {
		return nil, fmt.Errorf("migration: cohort_size must be between 1 and %d", MaxCohortSize)
	}
	if len(candidates) > MaxCohortPlanMembers {
		return nil, fmt.Errorf("migration: a cohort plan places at most %d members", MaxCohortPlanMembers)
	}
	seen := make(map[string]bool, len(candidates))
	ordered := make([]CohortCandidate, 0, len(candidates))
	for _, c := range candidates {
		c.IdentityID = strings.TrimSpace(c.IdentityID)
		if c.IdentityID == "" {
			return nil, errors.New("migration: a cohort candidate needs an identity id")
		}
		if seen[c.IdentityID] {
			continue
		}
		seen[c.IdentityID] = true
		ordered = append(ordered, c)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Name != ordered[j].Name {
			return ordered[i].Name < ordered[j].Name
		}
		return ordered[i].IdentityID < ordered[j].IdentityID
	})
	cohorts := []PlannedCohort{}
	for start, size := 0, canarySize; start < len(ordered); start, size = start+size, cohortSize {
		end := min(start+size, len(ordered))
		cohort := PlannedCohort{ID: "canary", Ordinal: len(cohorts) + 1}
		if cohort.Ordinal > 1 {
			cohort.ID = fmt.Sprintf("cohort-%d", cohort.Ordinal)
		}
		for _, c := range ordered[start:end] {
			cohort.Members = append(cohort.Members, PlannedMember(c))
		}
		cohorts = append(cohorts, cohort)
	}
	return cohorts, nil
}
