// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
)

// A274: the sign-ins bypass detection read for providers' managed accounts,
// metadata only, and what explained each. An unexplained one also raised a
// compromised-credential finding.

// PAMSignIn is one recorded sign-in.
type PAMSignIn struct {
	ProviderID  string                `json:"provider_id"`
	Fingerprint string                `json:"fingerprint"`
	Account     string                `json:"account"`
	At          time.Time             `json:"at"`
	Earliest    *time.Time            `json:"earliest,omitempty"`
	Source      string                `json:"source,omitempty"`
	Method      string                `json:"method,omitempty"`
	KeyID       string                `json:"key_id,omitempty"`
	Ref         string                `json:"ref,omitempty"`
	Collector   string                `json:"collector,omitempty"`
	LastSeenAt  time.Time             `json:"last_seen_at"`
	ExplainedBy *PAMSignInExplanation `json:"explained_by,omitempty"`
}

// PAMSignInExplanation is what explained a sign-in: a session, a check-out,
// a rotation or a health check, and its reference.
type PAMSignInExplanation struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref,omitempty"`
}

// PAMSignInService lists recorded sign-ins; the served broker implements it.
type PAMSignInService interface {
	ListPAMSignIns(ctx context.Context, tenantID, providerID string, unexplainedOnly bool, limit int) ([]PAMSignIn, error)
}

func (a *API) pamSignInRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/access/signins", opID: "listPAMSignIns", summary: "List the sign-ins bypass detection read for managed accounts, newest first, with what explained each (an unexplained one also raised a compromised-credential finding)",
			handler: a.listPAMSignIns, query: []param{{name: "provider_id", typ: "string", desc: "only this provider's sign-ins"},
				{name: "unexplained", typ: "boolean", desc: "only the sign-ins nothing explained"}, {name: "limit", typ: "integer", desc: "at most this many (1-500)"}},
			resSchema: "PAMSignInList", successCode: "200", perm: authz.AccessRead},
	}
}

func (a *API) listPAMSignIns(w http.ResponseWriter, r *http.Request) {
	svc, ok := a.pam.(PAMSignInService)
	if a.pam == nil || !ok {
		a.writePAMError(w, ErrPAMUnavailable)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	q := r.URL.Query()
	limit := 100
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 500 {
			a.writeError(w, errStatus(http.StatusBadRequest, "limit must be 1-500"))
			return
		}
		limit = n
	}
	unexplained := false
	if raw := strings.TrimSpace(q.Get("unexplained")); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "unexplained must be true or false"))
			return
		}
		unexplained = b
	}
	items, err := svc.ListPAMSignIns(r.Context(), tenantID, strings.TrimSpace(q.Get("provider_id")), unexplained, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
