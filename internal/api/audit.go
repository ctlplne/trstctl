package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/audit"
)

// auditQueryFromRequest builds an audit query from the request's tenant
// (authoritative, from the principal) and its query parameters.
func (a *API) auditQueryFromRequest(r *http.Request, tenantID string) (audit.Query, error) {
	q := audit.Query{TenantID: tenantID, Contains: r.URL.Query().Get("q")}
	if t := r.URL.Query().Get("type"); t != "" {
		for _, name := range strings.Split(t, ",") {
			if name = strings.TrimSpace(name); name != "" {
				q.Types = append(q.Types, name)
			}
		}
	}
	if s := r.URL.Query().Get("since"); s != "" {
		ts, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return audit.Query{}, errStatus(http.StatusBadRequest, "since must be RFC3339")
		}
		q.Since = ts
	}
	if s := r.URL.Query().Get("until"); s != "" {
		ts, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return audit.Query{}, errStatus(http.StatusBadRequest, "until must be RFC3339")
		}
		q.Until = ts
	}
	if s := r.URL.Query().Get("as_of"); s != "" {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return audit.Query{}, errStatus(http.StatusBadRequest, "as_of must be a sequence number")
		}
		q.AsOfSequence = n
	}
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return audit.Query{}, errStatus(http.StatusBadRequest, "limit must be a positive integer")
		}
		q.Limit = n
	}
	return q, nil
}

func (a *API) searchAudit(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.audit == nil {
		a.writeProblem(w, problem.New(http.StatusInternalServerError, "audit log is not configured"))
		return
	}
	q, err := a.auditQueryFromRequest(r, tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	records, err := a.audit.Search(r.Context(), q)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"events": records, "count": len(records)})
}

func (a *API) exportAudit(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.audit == nil {
		a.writeProblem(w, problem.New(http.StatusInternalServerError, "audit log is not configured"))
		return
	}
	q, err := a.auditQueryFromRequest(r, tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	bundle, err := a.audit.Export(r.Context(), q)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"format": "jws", "bundle": bundle})
}
