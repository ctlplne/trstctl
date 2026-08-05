// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/issuancerequest"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type issuanceRequestBody struct {
	Subject       string `json:"subject"`
	Profile       string `json:"profile"`
	CSRPEM        string `json:"csr_pem"`
	Justification string `json:"justification"`
	// Origin and TicketRef let a ticket-driven intake say where it came from.
	// An unrecorded origin stays empty rather than defaulting to "api": as with
	// owner provenance, absence must not be dressed up as an answer.
	Origin    string `json:"origin"`
	TicketRef string `json:"ticket_ref"`
}

type issuanceDecisionBody struct {
	Reason     string `json:"reason"`
	IdentityID string `json:"identity_id"`
}

type issuanceRequestResponse struct {
	ID             string `json:"id"`
	TenantID       string `json:"tenant_id"`
	Subject        string `json:"subject"`
	Profile        string `json:"profile,omitempty"`
	Requester      string `json:"requester"`
	Justification  string `json:"justification,omitempty"`
	Origin         string `json:"origin,omitempty"`
	TicketRef      string `json:"ticket_ref,omitempty"`
	Status         string `json:"status"`
	DecidedBy      string `json:"decided_by,omitempty"`
	DecisionReason string `json:"decision_reason,omitempty"`
	DecidedAt      string `json:"decided_at,omitempty"`
	IdentityID     string `json:"identity_id,omitempty"`
	ExpiresAt      string `json:"expires_at"`
	CreatedAt      string `json:"created_at"`
}

type issuanceRequestList struct {
	Items []issuanceRequestResponse `json:"items"`
	// Open is counted separately from the total. A single number cannot tell an
	// operator whether the queue needs attention or is just long with history.
	Open     int    `json:"open"`
	Guidance string `json:"guidance"`
}

const issuanceRequestGuidance = "A request has a real lifecycle: requested, then approved, denied, " +
	"expired, or cancelled — and approved is not the end, because issuance can still fail. Denial " +
	"and expiry are deliberately different: a denial is somebody's decision with a reason, an expiry " +
	"is nobody's. A requester can withdraw their own request and can never decide it; self-approval " +
	"would leave an approval record that looks legitimate while nobody independent ever looked."

// The CSR is public material. This response deliberately does NOT echo it back:
// it is large, it is already in the request the caller sent, and a list endpoint
// that returns every CSR makes an inventory of pending key material's public
// halves available to anyone who can list.
func toIssuanceRequestResponse(r store.IssuanceRequest) issuanceRequestResponse {
	out := issuanceRequestResponse{
		ID: r.ID, TenantID: r.TenantID, Subject: r.Subject, Profile: r.Profile,
		Requester: r.Requester, Justification: r.Justification, Origin: r.Origin,
		TicketRef: r.TicketRef, Status: r.Status, DecidedBy: r.DecidedBy,
		DecisionReason: r.DecisionReason, IdentityID: r.IdentityID,
		ExpiresAt: r.ExpiresAt.UTC().Format(time.RFC3339),
		CreatedAt: r.CreatedAt.UTC().Format(time.RFC3339),
	}
	if r.DecidedAt != nil {
		out.DecidedAt = r.DecidedAt.UTC().Format(time.RFC3339)
	}
	return out
}

// principalSubject reads the authenticated caller. Empty means unauthenticated,
// and every caller here treats that as fatal rather than as an anonymous
// requester: a request with no requester makes the self-approval check compare
// an empty string to an empty string and pass.
func principalSubject(ctx context.Context) string {
	principal, ok := ctx.Value(principalCtxKey).(authz.Principal)
	if !ok {
		return ""
	}
	return principal.Subject
}

func (a *API) createIssuanceRequest(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var body issuanceRequestBody
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if strings.TrimSpace(body.Subject) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "subject is required")
		}
		requester := principalSubject(ctx)
		if requester == "" {
			return 0, nil, errStatus(http.StatusUnauthorized,
				"an issuance request must name its requester; without one the self-approval check has nothing to compare")
		}
		out, err := a.orch.OpenIssuanceRequest(ctx, tenantID, projections.IssuanceRequestOpened{
			Subject: strings.TrimSpace(body.Subject), Profile: strings.TrimSpace(body.Profile),
			CSRPEM: strings.TrimSpace(body.CSRPEM), Requester: requester,
			Justification: strings.TrimSpace(body.Justification),
			Origin:        strings.TrimSpace(body.Origin), TicketRef: strings.TrimSpace(body.TicketRef),
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toIssuanceRequestResponse(out), nil
	})
}

func (a *API) listIssuanceRequests(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && !validIssuanceState(status) {
		a.writeError(w, errStatus(http.StatusBadRequest,
			"status must be one of: "+strings.Join(issuancerequest.States, ", ")))
		return
	}
	rows, err := a.store.ListIssuanceRequests(r.Context(), tenantID, status, 200)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := issuanceRequestList{Items: []issuanceRequestResponse{}, Guidance: issuanceRequestGuidance}
	for _, row := range rows {
		if row.Status == issuancerequest.StateRequested {
			out.Open++
		}
		out.Items = append(out.Items, toIssuanceRequestResponse(row))
	}
	a.writeJSON(w, http.StatusOK, out)
}

func validIssuanceState(s string) bool {
	for _, v := range issuancerequest.States {
		if v == s {
			return true
		}
	}
	return false
}

// decideIssuanceRequest handles approve / deny / cancel through one path, so the
// transition rules cannot be enforced in one handler and forgotten in another.
func (a *API) decideIssuanceRequest(to string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idempotencyKey := r.Header.Get("Idempotency-Key")
		a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
			var body issuanceDecisionBody
			if r.ContentLength > 0 {
				if err := decodeJSON(r, &body); err != nil {
					return 0, nil, errWithStatus(http.StatusBadRequest, err)
				}
			}
			if to == issuancerequest.StateDenied && strings.TrimSpace(body.Reason) == "" {
				// A denial with no reason is the thing that makes people stop
				// using a request queue: the requester learns only that somebody
				// said no, and re-asks.
				return 0, nil, errStatus(http.StatusBadRequest,
					"a denial needs a reason; without one the requester learns only that somebody said no and will simply ask again")
			}
			out, err := a.orch.DecideIssuanceRequest(ctx, tenantID, r.PathValue("id"), to,
				principalSubject(ctx), strings.TrimSpace(body.Reason), strings.TrimSpace(body.IdentityID))
			if err != nil {
				return 0, nil, err
			}
			return http.StatusOK, toIssuanceRequestResponse(out), nil
		})
	}
}
