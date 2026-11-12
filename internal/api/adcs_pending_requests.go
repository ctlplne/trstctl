// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// N1-L2: the requests an AD CS issuer's CA holds for a manager's approval,
// listed from the relay's latest read of the CA database, so an operator picks
// the request to decide instead of reading its id from the CA.

// ADCSPendingRequestService lists an issuer's pending requests. The server
// implements it beside ADCSDecisionService.
type ADCSPendingRequestService interface {
	ListADCSPendingRequests(ctx context.Context, tenantID, issuerID string) (ADCSPendingRequests, error)
}

// ADCSPendingRequests is an issuer's CA's pending requests from the relay's
// latest read, newest first.
type ADCSPendingRequests struct {
	IssuerID  string               `json:"issuer_id"`
	CAConfig  string               `json:"ca_config"`
	ReadAt    *time.Time           `json:"read_at,omitempty"`
	Truncated bool                 `json:"truncated"`
	Items     []ADCSPendingRequest `json:"items"`
}

// ADCSPendingRequest is one pending request, and whether a trstctl issuance
// is held on it.
type ADCSPendingRequest struct {
	RequestID    int    `json:"request_id"`
	Template     string `json:"template,omitempty"`
	CommonName   string `json:"common_name,omitempty"`
	Requester    string `json:"requester,omitempty"`
	HeldIssuance bool   `json:"held_issuance"`
}

func (a *API) listADCSPendingRequests(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	svc, ok := a.adcsDecisions.(ADCSPendingRequestService)
	if a.adcsDecisions == nil || !ok {
		a.writeError(w, adcsDecisionAPIError(ErrADCSDecisionUnavailable))
		return
	}
	issuerID := strings.TrimSpace(r.PathValue("id"))
	if issuerID == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "name an external CA"))
		return
	}
	listed, err := svc.ListADCSPendingRequests(r.Context(), tenantID, issuerID)
	if err != nil {
		a.writeError(w, adcsDecisionAPIError(err))
		return
	}
	if listed.Items == nil {
		listed.Items = []ADCSPendingRequest{}
	}
	a.writeJSON(w, http.StatusOK, listed)
}
