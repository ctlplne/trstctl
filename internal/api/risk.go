package api

import (
	"net/http"
	"strconv"

	"certctl.io/certctl/internal/risk"
)

// riskListResponse is the scored, sorted, filtered credential list.
type riskListResponse struct {
	Credentials []risk.CredentialRisk `json:"credentials"`
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
