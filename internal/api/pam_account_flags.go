// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
)

// A276: brokered accounts whose owner is gone, or that sat unused past the
// deployment's window, are flagged with a proposed action — reassign the
// owner, or rotate the account's credential and disable it — that needs
// approval, then is applied and read back.

// PAMAccountFlag is a brokered account's latest flag.
type PAMAccountFlag struct {
	TargetType        string     `json:"target_type"`
	TargetID          string     `json:"target_id"`
	Reasons           []string   `json:"reasons"`
	Detail            string     `json:"detail,omitempty"`
	OwnerID           string     `json:"owner_id,omitempty"`
	LastUsedAt        *time.Time `json:"last_used_at,omitempty"`
	FlaggedAt         time.Time  `json:"flagged_at"`
	Status            string     `json:"status"`
	ClearedAt         *time.Time `json:"cleared_at,omitempty"`
	Action            string     `json:"action,omitempty"`
	ActionOwnerID     string     `json:"action_owner_id,omitempty"`
	ActionRotationID  string     `json:"action_rotation_id,omitempty"`
	ActionReason      string     `json:"action_reason,omitempty"`
	ApprovalRequestID string     `json:"approval_request_id,omitempty"`
	ActionedBy        string     `json:"actioned_by,omitempty"`
	ActionedAt        *time.Time `json:"actioned_at,omitempty"`
}

// PAMAccountActionRequest proposes, or applies once approved, an action on
// a flagged account.
type PAMAccountActionRequest struct {
	RequestID string `json:"request_id"`
	Action    string `json:"action"`
	OwnerID   string `json:"owner_id,omitempty"`
	// RotationOldRef names the account its consumers use now, for a
	// rotate_disable of an account its provider rotates between two (A240).
	RotationOldRef    string `json:"rotation_old_ref,omitempty"`
	Reason            string `json:"reason"`
	ApprovalRequestID string `json:"approval_request_id,omitempty"`
	IntentDigest      string `json:"intent_digest,omitempty"`
}

// PAMAccountActionReview is a proposed action's approval request.
type PAMAccountActionReview struct {
	RequestID         string    `json:"request_id"`
	ApprovalRequestID string    `json:"approval_request_id"`
	IntentDigest      string    `json:"intent_digest"`
	Status            string    `json:"status"`
	ApprovalCount     int       `json:"approval_count"`
	RequiredApprovals int       `json:"required_approvals"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// PAMAccountActionPlan is what applying an approved action does: the
// account's vaulted credential to rotate first, when it has one.
type PAMAccountActionPlan struct {
	RotateProvider, RotateKey, RotateOldRef string
}

// PAMAccountFlagService flags brokered accounts and applies approved
// actions; the served broker implements it.
type PAMAccountFlagService interface {
	ListPAMAccountFlags(ctx context.Context, tenantID, status string) ([]PAMAccountFlag, error)
	ScanPAMAccountFlags(ctx context.Context, tenantID string) ([]PAMAccountFlag, error)
	RequestPAMAccountAction(ctx context.Context, tenantID, requester, targetType, id string, req PAMAccountActionRequest) (PAMAccountActionReview, error)
	PlanPAMAccountAction(ctx context.Context, tenantID, requester, targetType, id string, req PAMAccountActionRequest) (PAMAccountActionPlan, error)
	ApplyPAMAccountAction(ctx context.Context, tenantID, requester, targetType, id string, req PAMAccountActionRequest, rotationID string) (PAMAccountFlag, error)
}

func (a *API) pamAccountFlagRoutes() []route {
	flagPath := []param{pathString("target_type", "the brokered account's target type"), pathString("id", "the brokered account's target id")}
	return []route{
		{method: "GET", path: "/api/v1/access/account-flags", opID: "listPAMAccountFlags",
			summary: "List brokered accounts flagged as orphaned (owner gone) or unused past the window, with what an approved action did",
			handler: a.listPAMAccountFlags, query: []param{{name: "status", typ: "string", desc: "open, cleared or actioned"}},
			resSchema: "PAMAccountFlagList", successCode: "200", perm: authz.AccessRead},
		{method: "POST", path: "/api/v1/access/account-flags/scan", opID: "scanPAMAccountFlags",
			summary: "Flag the tenant's brokered accounts now: orphaned when the owner is gone, unused past pam.unused_after; clear flags that no longer hold",
			handler: a.scanPAMAccountFlags, resSchema: "PAMAccountFlagList", successCode: "200", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "POST", path: "/api/v1/access/account-flags/{target_type}/{id}/actions", opID: "requestPAMAccountAction",
			summary: "Propose an action on a flagged account — reassign its owner, or rotate its credential and disable it — for approval",
			handler: a.requestPAMAccountAction, pathParams: flagPath, reqSchema: "PAMAccountActionRequest", resSchema: "PAMAccountActionReview",
			successCode: "202", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "POST", path: "/api/v1/access/account-flags/{target_type}/{id}/actions/apply", opID: "applyPAMAccountAction",
			summary: "Apply an approved action on a flagged account once, and read the flag back",
			handler: a.applyPAMAccountAction, pathParams: flagPath, reqSchema: "PAMAccountActionRequest", resSchema: "PAMAccountFlag",
			successCode: "200", mutation: true, perm: authz.AccessTargetsWrite},
	}
}

func (a *API) pamAccountFlags(w http.ResponseWriter) (PAMAccountFlagService, bool) {
	svc, ok := a.pam.(PAMAccountFlagService)
	if a.pam == nil || !ok {
		a.writePAMError(w, ErrPAMUnavailable)
		return nil, false
	}
	return svc, true
}

func (a *API) listPAMAccountFlags(w http.ResponseWriter, r *http.Request) {
	svc, ok := a.pamAccountFlags(w)
	if !ok {
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && status != "open" && status != "cleared" && status != "actioned" {
		a.writeError(w, errStatus(http.StatusBadRequest, "status must be open, cleared or actioned"))
		return
	}
	items, err := svc.ListPAMAccountFlags(r.Context(), tenantID, status)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

//trstctl:mutation
func (a *API) scanPAMAccountFlags(w http.ResponseWriter, r *http.Request) {
	svc, ok := a.pamAccountFlags(w)
	if !ok {
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		items, err := svc.ScanPAMAccountFlags(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"items": items}, nil
	})
}

//trstctl:mutation
func (a *API) requestPAMAccountAction(w http.ResponseWriter, r *http.Request) {
	svc, ok := a.pamAccountFlags(w)
	if !ok {
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req PAMAccountActionRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		review, err := svc.RequestPAMAccountAction(ctx, tenantID, principalSubject(ctx), r.PathValue("target_type"), r.PathValue("id"), req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, review, nil
	})
}

//trstctl:mutation
func (a *API) applyPAMAccountAction(w http.ResponseWriter, r *http.Request) {
	svc, ok := a.pamAccountFlags(w)
	if !ok {
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req PAMAccountActionRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		actor := principalSubject(ctx)
		targetType, id := r.PathValue("target_type"), r.PathValue("id")
		plan, err := svc.PlanPAMAccountAction(ctx, tenantID, actor, targetType, id, req)
		if err != nil {
			return 0, nil, err
		}
		rotationID := ""
		if req.Action == "rotate_disable" && plan.RotateProvider != "" && plan.RotateKey != "" {
			// The approved action rotates the account's vaulted credential
			// first, as a durable rotation command keyed by the approval, so
			// a retried apply finds the same command.
			rotation := secretRotationRequest{Provider: plan.RotateProvider, Key: plan.RotateKey, OldRef: plan.RotateOldRef, AcknowledgeSinglePhase: true}
			key := "pam-account-flag:" + req.ApprovalRequestID
			_, binding, err := a.applicationSecretRequestBinding(tenantID, key, actor, http.MethodPost,
				"/api/v1/access/account-flags/"+targetType+"/"+id+"/actions/apply", "static-rotate", staticRotationSurface, rotation.Key, rotation)
			if err != nil {
				return 0, nil, err
			}
			cmd, err := a.queueStaticSecretRotation(ctx, tenantID, key, binding, "", rotation)
			if err != nil {
				return 0, nil, applicationSecretMutationError(err)
			}
			rotationID = cmd.ID
		}
		flag, err := svc.ApplyPAMAccountAction(ctx, tenantID, actor, targetType, id, req, rotationID)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, flag, nil
	})
}
