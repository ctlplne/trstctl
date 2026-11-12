// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
)

// N1-L1: an issuance an external CA holds for a manager's approval (AD CS's
// "taken under submission") is listed with the CA's request id, and resumed
// by it once approved: trstctl reads the request back, and the CA's issued
// certificate is recorded under the issuance its caller waits on.

// ErrExternalCAHeldIssueNotFound means the authority holds no such request for
// this tenant.
var ErrExternalCAHeldIssueNotFound = errors.New("held external CA issuance not found")

// ErrExternalCAStillHeld means the CA still holds the request for approval.
var ErrExternalCAStillHeld = errors.New("the CA still holds the request for approval")

// ErrExternalCAHeldUnsupported means the authority cannot read a held request
// back.
var ErrExternalCAHeldUnsupported = errors.New("this authority cannot read a held request back")

// ExternalCAHeldIssue is an issuance an external CA holds, or held, for
// approval: held, issued once the CA issued it, or denied.
type ExternalCAHeldIssue struct {
	CARequestID int        `json:"ca_request_id"`
	DNSNames    []string   `json:"dns_names"`
	Status      string     `json:"status"`
	Serial      string     `json:"serial,omitempty"`
	HeldAt      time.Time  `json:"held_at"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

// ExternalCAHeldIssueResume is a held issuance after its request was read back
// from the CA, with the certificate once the CA issued it.
type ExternalCAHeldIssueResume struct {
	ExternalCAHeldIssue
	CertificatePEM string     `json:"certificate_pem,omitempty"`
	NotAfter       *time.Time `json:"not_after,omitempty"`
}

// ExternalCAHeldIssueService lists and resumes held issuances. The served
// external-CA registry implements it beside ExternalCAService.
type ExternalCAHeldIssueService interface {
	ListExternalCAHeldIssues(ctx context.Context, tenantID, id string) ([]ExternalCAHeldIssue, error)
	ResumeExternalCAHeldIssue(ctx context.Context, tenantID, id string, requestID int) (ExternalCAHeldIssueResume, error)
}

func (a *API) heldIssueService() (ExternalCAHeldIssueService, error) {
	if a.externalCAs == nil {
		return nil, ErrExternalCAUnavailable
	}
	svc, ok := a.externalCAs.(ExternalCAHeldIssueService)
	if !ok {
		return nil, ErrExternalCAUnavailable
	}
	return svc, nil
}

func (a *API) listExternalCAHeldIssues(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	svc, err := a.heldIssueService()
	if err != nil {
		a.writeError(w, err)
		return
	}
	items, err := svc.ListExternalCAHeldIssues(r.Context(), tenantID, strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

func (a *API) resumeExternalCAHeldIssue(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	requestID, err := strconv.Atoi(strings.TrimSpace(r.PathValue("request_id")))
	if err != nil || requestID <= 0 {
		a.writeError(w, errStatus(http.StatusBadRequest, "request_id must be the CA's positive request id"))
		return
	}
	// Reading the request back cannot issue a second certificate and the
	// recording is idempotent, so the call may wait on the CA outside the
	// tenant transaction.
	a.mutateDurable(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.heldIssueService()
		if err != nil {
			return 0, nil, err
		}
		resumed, err := svc.ResumeExternalCAHeldIssue(ctx, tenantID, id, requestID)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, resumed, nil
	})
}

func (a *API) writeExternalCAHeldError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, ErrExternalCAHeldIssueNotFound):
		a.writeProblem(w, problem.New(http.StatusNotFound, "held external CA issuance not found"))
	case errors.Is(err, ErrExternalCAStillHeld):
		a.writeProblem(w, problem.New(http.StatusConflict, "the CA still holds the request for approval; resume it once a CA manager approves it"))
	case errors.Is(err, ErrExternalCAHeldUnsupported):
		a.writeProblem(w, problem.New(http.StatusConflict, "this authority cannot read a held request back"))
	default:
		return false
	}
	return true
}
