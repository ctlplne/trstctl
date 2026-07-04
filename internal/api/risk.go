// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/risk"
)

// riskListResponse is the scored, sorted, filtered credential list.
type riskListResponse struct {
	Credentials []risk.CredentialRisk `json:"credentials"`
}

type contextualRiskResponse struct {
	Capability  string                    `json:"capability"`
	GeneratedAt time.Time                 `json:"generated_at"`
	Coverage    []string                  `json:"coverage"`
	Summary     contextualRiskSummary     `json:"summary"`
	Priorities  []risk.ContextualPriority `json:"priorities"`
}

type contextualRiskSummary struct {
	TotalAnalyzed     int `json:"total_analyzed"`
	Priorities        int `json:"priorities"`
	Critical          int `json:"critical"`
	High              int `json:"high"`
	Medium            int `json:"medium"`
	Low               int `json:"low"`
	HighBlastRadius   int `json:"high_blast_radius"`
	WeakCryptoContext int `json:"weak_crypto_context"`
	Orphaned          int `json:"orphaned"`
	NearExpiry        int `json:"near_expiry"`
	Recommendations   int `json:"recommendations"`
}

// privilegeByName maps the API's privilege filter values to classes.
var privilegeByName = map[string]risk.PrivilegeClass{
	"low":      risk.PrivilegeLow,
	"standard": risk.PrivilegeStandard,
	"high":     risk.PrivilegeHigh,
	"critical": risk.PrivilegeCritical,
}

// listRiskScores scores every credential in the tenant's inventory and returns
// them ranked, with optional sort and filters — the API answer to "what should I
// rotate first" (F19).
func (a *API) listRiskScores(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}

	q := r.URL.Query()

	var filter risk.Filter
	if s := q.Get("min_score"); s != "" {
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "min_score must be a number"))
			return
		}
		filter.MinScore = v
	}
	if p := q.Get("privilege"); p != "" {
		cls, ok := privilegeByName[p]
		if !ok {
			a.writeError(w, errStatus(http.StatusBadRequest, "privilege must be one of low, standard, high, critical"))
			return
		}
		filter.MinPrivilege = &cls
	}
	if o := q.Get("owner"); o != "" {
		switch o {
		case "active":
			active := true
			filter.OwnerActive = &active
		case "inactive", "orphaned":
			inactive := false
			filter.OwnerActive = &inactive
		default:
			a.writeError(w, errStatus(http.StatusBadRequest, "owner must be active or inactive"))
			return
		}
	}

	sortKey := q.Get("sort")
	switch sortKey {
	case "", "score", "expiry":
	default:
		a.writeError(w, errStatus(http.StatusBadRequest, "sort must be score or expiry"))
		return
	}

	scores, err := risk.ScoreInventory(r.Context(), a.store, tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	scores = filter.Apply(scores)
	if sortKey == "expiry" {
		risk.SortByExpiry(scores)
	} else {
		risk.SortByScore(scores)
	}

	if scores == nil {
		scores = []risk.CredentialRisk{}
	}
	a.writeJSON(w, http.StatusOK, riskListResponse{Credentials: scores})
}

// listContextualRiskPriorities serves CAP-POST-05: blast-radius-aware
// prioritization over the tenant's credential risk inventory.
func (a *API) listContextualRiskPriorities(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}

	priorities, err := risk.ContextualPriorities(r.Context(), a.store, tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if priorities == nil {
		priorities = []risk.ContextualPriority{}
	}
	a.writeJSON(w, http.StatusOK, contextualRiskResponse{
		Capability:  "CAP-POST-05",
		GeneratedAt: time.Now().UTC(),
		Coverage: []string{
			"credential_risk_scores",
			"graph_blast_radius",
			"resource_reachability",
			"cbom_crypto_context",
			"owner_and_rotation_context",
		},
		Summary:    summarizeContextualRisk(priorities),
		Priorities: priorities,
	})
}

func summarizeContextualRisk(priorities []risk.ContextualPriority) contextualRiskSummary {
	s := contextualRiskSummary{TotalAnalyzed: len(priorities), Priorities: len(priorities)}
	for _, p := range priorities {
		switch p.Severity {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		default:
			s.Low++
		}
		if p.BlastRadius >= 4 {
			s.HighBlastRadius++
		}
		if p.WeakCryptoContext > 0 {
			s.WeakCryptoContext++
		}
		if !p.OwnerActive {
			s.Orphaned++
		}
		for _, reason := range p.PriorityReasons {
			if reason == "near_expiry" {
				s.NearExpiry++
				break
			}
		}
		if p.RecommendedAction != "" {
			s.Recommendations++
		}
	}
	return s
}
