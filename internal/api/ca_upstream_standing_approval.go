// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// ErrCAUpstreamStandingApprovalNotFound reports an approval that is not at
// the named authority.
var ErrCAUpstreamStandingApprovalNotFound = errors.New("api: no such upstream standing approval")

// CAUpstreamStandingApproval is a standing approval for one SPIRE server's
// upstream CA requests at one CA authority (OD-8). A key ceremony grants it
// once; then that caller's CA CSRs are signed without a ceremony each, as long
// as each names the approved trust domain and stays within the approved spec
// and lifetime, until the approval expires or is revoked. Every signing is
// counted and in the audit trail.
type CAUpstreamStandingApproval struct {
	ID          string `json:"id"`
	CAID        string `json:"ca_id"`
	Principal   string `json:"principal"`
	TrustDomain string `json:"trust_domain"`
	// Spec is the CA spec every signed CA must match; its ttl_seconds is the
	// longest lifetime a signed CA may have.
	Spec         CASpec     `json:"spec"`
	CeremonyID   string     `json:"ceremony_id"`
	GrantedBy    string     `json:"granted_by"`
	GrantedAt    time.Time  `json:"granted_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	Status       string     `json:"status"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokedBy    string     `json:"revoked_by,omitempty"`
	RevokeReason string     `json:"revoke_reason,omitempty"`
	Signings     int64      `json:"signings"`
	LastSignedAt *time.Time `json:"last_signed_at,omitempty"`
}

// CAUpstreamStandingApprovalGrantRequest grants an approval a
// grant_upstream_standing_approval ceremony approved: the same principal,
// trust domain, validity and spec the ceremony named.
type CAUpstreamStandingApprovalGrantRequest struct {
	CeremonyID      string `json:"ceremony_id"`
	Principal       string `json:"principal"`
	TrustDomain     string `json:"trust_domain"`
	ValidForSeconds int64  `json:"valid_for_seconds"`
	Spec            CASpec `json:"spec"`
}

type caUpstreamStandingApprovalRevokeJSON struct {
	Reason string `json:"reason"`
}

// CAUpstreamStandingApprovals is the served standing-approval surface; a CA
// hierarchy service that does not serve it answers 503.
type CAUpstreamStandingApprovals interface {
	ListUpstreamStandingApprovals(ctx context.Context, tenantID, caID string) ([]CAUpstreamStandingApproval, error)
	GrantUpstreamStandingApproval(ctx context.Context, tenantID, caID string, req CAUpstreamStandingApprovalGrantRequest) (CAUpstreamStandingApproval, error)
	RevokeUpstreamStandingApproval(ctx context.Context, tenantID, caID, approvalID, reason string) (CAUpstreamStandingApproval, error)
}

func (a *API) standingApprovals() (CAUpstreamStandingApprovals, bool) {
	svc, ok := a.caHierarchy.(CAUpstreamStandingApprovals)
	return svc, ok
}

func (a *API) listCAUpstreamStandingApprovals(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	svc, ok := a.standingApprovals()
	if !ok {
		a.writeError(w, ErrCAHierarchyUnavailable)
		return
	}
	items, err := svc.ListUpstreamStandingApprovals(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	if items == nil {
		items = []CAUpstreamStandingApproval{}
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

//trstctl:mutation
func (a *API) grantCAUpstreamStandingApproval(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		svc, ok := a.standingApprovals()
		if !ok {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CAUpstreamStandingApprovalGrantRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		granted, err := svc.GrantUpstreamStandingApproval(ctx, tenantID, id, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, granted, nil
	})
}

//trstctl:mutation
func (a *API) revokeCAUpstreamStandingApproval(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id, approvalID := r.PathValue("id"), r.PathValue("approval_id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		svc, ok := a.standingApprovals()
		if !ok {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req caUpstreamStandingApprovalRevokeJSON
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" || len(reason) > 1024 {
			return 0, nil, errStatus(http.StatusBadRequest, "reason is required (at most 1024 characters)")
		}
		revoked, err := svc.RevokeUpstreamStandingApproval(ctx, tenantID, id, approvalID, reason)
		if errors.Is(err, ErrCAUpstreamStandingApprovalNotFound) {
			return 0, nil, errStatus(http.StatusNotFound, "no such standing approval at this authority")
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, revoked, nil
	})
}
