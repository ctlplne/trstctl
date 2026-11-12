// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// AccessBundleStandingApproval approves, in advance, the privileged session
// requests an access bundle's runs make for one delegated account as one
// role, until it expires or is revoked (OD-9). It is never on by default.
// Sessions it approves are recorded and revocable like any other, and
// revoking it ends the live ones.
type AccessBundleStandingApproval struct {
	ID         string    `json:"id"`
	BundleID   string    `json:"bundle_id"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	Role       string    `json:"role"`
	Reason     string    `json:"reason"`
	GrantedBy  string    `json:"granted_by"`
	GrantedAt  time.Time `json:"granted_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	// Status is active, expired or revoked.
	Status       string     `json:"status"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokedBy    string     `json:"revoked_by,omitempty"`
	RevokeReason string     `json:"revoke_reason,omitempty"`
	// Approvals counts the session requests it approved.
	Approvals      int64      `json:"approvals"`
	LastApprovedAt *time.Time `json:"last_approved_at,omitempty"`
}

// AccessBundleStandingApprovalRevoked is a revoked approval and the live
// sessions its revocation ended.
type AccessBundleStandingApprovalRevoked struct {
	Approval      AccessBundleStandingApproval `json:"approval"`
	EndedSessions []PAMSession                 `json:"ended_sessions"`
}

type accessBundleStandingApprovalRequest struct {
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	Role       string    `json:"role"`
	Reason     string    `json:"reason"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type accessBundleStandingApprovalRevokeRequest struct {
	Reason string `json:"reason"`
}

// accessStandingApprovalMinLife is the shortest a standing approval may last:
// a session it approves must end before it does.
const accessStandingApprovalMinLife = 5 * time.Minute

// standingApprovalRevokePages bounds one revocation's session sweep; a
// retry with the same key ends the rest.
const standingApprovalRevokePages = 10

func accessStandingApprovalView(a store.AccessBundleStandingApproval, now time.Time) AccessBundleStandingApproval {
	status := "active"
	switch {
	case a.RevokedAt != nil:
		status = "revoked"
	case !a.ExpiresAt.After(now):
		status = "expired"
	}
	return AccessBundleStandingApproval{
		ID: a.ID, BundleID: a.BundleID, TargetType: a.TargetType, TargetID: a.TargetID, Role: a.Role, Reason: a.Reason,
		GrantedBy: a.GrantedBy, GrantedAt: a.GrantedAt.UTC(), ExpiresAt: a.ExpiresAt.UTC(), Status: status,
		RevokedAt: a.RevokedAt, RevokedBy: a.RevokedBy, RevokeReason: a.RevokeReason,
		Approvals: a.Approvals, LastApprovedAt: a.LastApprovedAt,
	}
}

// liveAccessBundle reads a bundle that is not deleted.
func (a *API) liveAccessBundle(ctx context.Context, tenantID, id string) (store.AccessBundle, error) {
	bundle, err := a.store.GetAccessBundle(ctx, tenantID, id)
	if err != nil {
		return store.AccessBundle{}, accessBundleNotFound(err)
	}
	if bundle.DeletedAt != nil {
		return store.AccessBundle{}, errStatus(http.StatusNotFound, "access bundle not found")
	}
	return bundle, nil
}

func (a *API) listAccessBundleStandingApprovals(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	bundle, err := a.liveAccessBundle(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	rows, err := a.store.ListAccessBundleStandingApprovals(r.Context(), tenantID, bundle.ID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	now := time.Now()
	items := make([]AccessBundleStandingApproval, 0, len(rows))
	for _, row := range rows {
		items = append(items, accessStandingApprovalView(row, now))
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

// grantAccessBundleStandingApproval approves in advance one bundle's runs'
// session requests for one of its delegated accounts as one role. It needs
// access:approve as well as access:write, since it stands in for reviewers;
// a run cannot grant one, and neither can a principal the bundle is granted
// to, so nobody approves their own sessions in advance.
//
//trstctl:mutation
func (a *API) grantAccessBundleStandingApproval(w http.ResponseWriter, r *http.Request) {
	bundleID := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		principal, err := requestAuthzPrincipal(ctx)
		if err != nil {
			return 0, nil, err
		}
		if principal.RunID != "" {
			return 0, nil, errStatus(http.StatusForbidden, "an access bundle run cannot grant a standing approval")
		}
		if !principal.Can(authz.AccessApprove, authz.Scope{TenantID: tenantID}) {
			return 0, nil, errStatus(http.StatusForbidden, "a standing approval stands in for reviewers: it needs access:approve as well as access:write")
		}
		var req accessBundleStandingApprovalRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		bundle, err := a.liveAccessBundle(ctx, tenantID, bundleID)
		if err != nil {
			return 0, nil, err
		}
		delegated := slices.ContainsFunc(bundle.AccessTargets, func(t store.AccessBundleTarget) bool {
			return t.TargetType == req.TargetType && t.TargetID == req.TargetID && slices.Contains(t.Roles, req.Role)
		})
		if !delegated {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, fmt.Sprintf("%s/%s as %s is not among the accounts this bundle delegates", req.TargetType, req.TargetID, req.Role))
		}
		reason, err := plainText(req.Reason, 500, "reason")
		if err != nil {
			return 0, nil, err
		}
		if reason == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "reason is required")
		}
		now := time.Now().UTC()
		expires := req.ExpiresAt.UTC().Truncate(time.Microsecond)
		if expires.Before(now.Add(accessStandingApprovalMinLife)) || expires.After(now.Add(projections.MaxAccessBundleStandingApprovalValidity)) {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "expires_at must be between five minutes and 90 days from now")
		}
		grants, err := a.store.LiveAccessBundleGrants(ctx, tenantID, principal.Subject, now)
		if err != nil {
			return 0, nil, err
		}
		if slices.ContainsFunc(grants, func(g store.AccessBundleGrant) bool { return g.BundleID == bundle.ID }) {
			return 0, nil, errStatus(http.StatusForbidden, "this bundle is granted to you: a standing approval for it must come from someone it is not granted to")
		}
		id := googleuuid.NewString()
		if err := a.orch.GrantAccessBundleStandingApproval(ctx, tenantID, projections.AccessBundleStandingApprovalGranted{
			ID: id, BundleID: bundle.ID, TargetType: req.TargetType, TargetID: req.TargetID, Role: req.Role,
			Reason: reason, ExpiresAt: expires, GrantedBy: principal.Subject,
		}); err != nil {
			return 0, nil, err
		}
		granted, err := a.store.GetAccessBundleStandingApproval(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, accessStandingApprovalView(granted, time.Now()), nil
	})
}

// revokeAccessBundleStandingApproval revokes an approval at once and ends
// the live sessions it approved, each as an operator's revocation is, under
// a key derived from the call's own so a retry ends nothing twice. A
// request it approved that was not opened yet is refused when opened.
//
//trstctl:mutation
func (a *API) revokeAccessBundleStandingApproval(w http.ResponseWriter, r *http.Request) {
	bundleID, approvalID := r.PathValue("id"), r.PathValue("approval_id")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		var req accessBundleStandingApprovalRevokeRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		reason, err := plainText(req.Reason, 500, "reason")
		if err != nil {
			return 0, nil, err
		}
		if reason == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "reason is required")
		}
		approval, err := a.store.GetAccessBundleStandingApproval(ctx, tenantID, approvalID)
		if errors.Is(err, store.ErrAccessBundleStandingApprovalNotFound) || (err == nil && approval.BundleID != bundleID) {
			return 0, nil, errStatus(http.StatusNotFound, "no such standing approval for this bundle")
		}
		if err != nil {
			return 0, nil, err
		}
		if approval.RevokedAt == nil {
			if err := a.orch.RevokeAccessBundleStandingApproval(ctx, tenantID, projections.AccessBundleStandingApprovalRevoked{
				ID: approval.ID, BundleID: approval.BundleID, RevokedBy: subject, Reason: reason,
			}); err != nil {
				return 0, nil, err
			}
		}
		ended, err := a.endStandingApprovalSessions(ctx, tenantID, approval.ID, subject, reason, idempotencyKey)
		if err != nil {
			return 0, nil, err
		}
		revoked, err := a.store.GetAccessBundleStandingApproval(ctx, tenantID, approval.ID)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, AccessBundleStandingApprovalRevoked{Approval: accessStandingApprovalView(revoked, time.Now()), EndedSessions: ended}, nil
	})
}

func (a *API) endStandingApprovalSessions(ctx context.Context, tenantID, approvalID, actor, reason, idempotencyKey string) ([]PAMSession, error) {
	ended := []PAMSession{}
	if a.pam == nil {
		return ended, nil
	}
	approver := "standing-approval:" + approvalID
	for range standingApprovalRevokePages {
		live, err := a.store.ListLivePAMSessionsApprovedBy(ctx, tenantID, approver, 100)
		if err != nil || len(live) == 0 {
			return ended, err
		}
		for _, rec := range live {
			key := crypto.SHA256Hex([]byte(idempotencyKey + "\x00" + rec.ID))
			session, err := a.pam.RevokePAMSession(ctx, tenantID, rec.ID, actor, "standing approval revoked: "+strings.TrimSpace(reason), key)
			if errors.Is(err, ErrPAMTerminal) {
				continue // it ended on its own meanwhile
			}
			if err != nil {
				return ended, fmt.Errorf("end session %s: %w", rec.ID, err)
			}
			ended = append(ended, session)
		}
	}
	return ended, errors.New("api: the standing approval has more live sessions than one call ends; retry with the same key")
}
