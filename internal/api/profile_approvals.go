// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/approval"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Profile create/edit under dual control (a profile whose spec carries
// requires_approval) answers 202 with an approval id and parks the spec until a
// distinct reviewer approves it. These routes are the served review surface for
// those parked requests (DP2-057): before them the orchestrator could record
// the approval but no route reached it, so a governed profile could never be
// created or edited through the API.

type profileEditApprovalDecision struct {
	Approver string `json:"approver"`
	Decision string `json:"decision"`
	At       string `json:"at"`
}

type profileEditApprovalRecord struct {
	ID                string                        `json:"id"`
	Kind              string                        `json:"kind"`
	Resource          string                        `json:"resource"`
	ProfileName       string                        `json:"profile_name"`
	Requester         string                        `json:"requester"`
	RequiredApprovals int                           `json:"required_approvals"`
	Approvals         []profileEditApprovalDecision `json:"approvals"`
	State             string                        `json:"state"`
	ProfileID         string                        `json:"profile_id,omitempty"`
	CreatedAt         string                        `json:"created_at"`
	ExpiresAt         string                        `json:"expires_at"`
}

type profileEditApprovalList struct {
	Items []profileEditApprovalRecord `json:"items"`
}

type profileEditApprovalDecisionRequest struct {
	Reason string `json:"reason"`
}

func toProfileEditApprovalRecord(r store.ProfileEditApproval, now time.Time) profileEditApprovalRecord {
	rec := profileEditApprovalRecord{
		ID: r.ID, Kind: string(approval.KindProfileEdit), Resource: "profile:" + r.Name,
		ProfileName:       r.Name,
		Requester:         r.Requester,
		RequiredApprovals: r.RequiredApprovals,
		Approvals:         make([]profileEditApprovalDecision, 0, len(r.Approvals)),
		State:             orchestrator.ProfileEditApprovalState(r, now),
		ProfileID:         r.ProfileID,
		CreatedAt:         r.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt:         r.ExpiresAt.UTC().Format(time.RFC3339),
	}
	for _, a := range r.Approvals {
		rec.Approvals = append(rec.Approvals, profileEditApprovalDecision{Approver: a.Approver, Decision: a.Decision, At: a.At.UTC().Format(time.RFC3339)})
	}
	return rec
}

// profileEditApprovalError maps the orchestrator's typed refusals to problems:
// unknown ids are tenant-safe 404s, an expired window is a 409 the requester
// resolves by resubmitting, and a self-approval is the documented 403.
func profileEditApprovalError(err error) error {
	switch {
	case errors.Is(err, orchestrator.ErrProfileEditApprovalUnknown):
		return errStatus(http.StatusNotFound, "no such profile approval request")
	case errors.Is(err, orchestrator.ErrProfileEditApprovalExpired):
		return errStatus(http.StatusConflict, "the profile approval request expired; resubmit the profile change to open a new request")
	case errors.Is(err, orchestrator.ErrProfileEditSelfApproval):
		return errStatus(http.StatusForbidden, "dual control: the requester cannot approve their own profile edit")
	default:
		return err
	}
}

func (a *API) profileEditApprovalRoutes() []route {
	approvalIDPath := []param{pathUUID("id")}
	return []route{
		{method: "GET", path: "/api/v1/profiles/approvals", opID: "listProfileEditApprovals", summary: "List parked profile create/edit approval requests (dual control)", handler: a.listProfileEditApprovals, resSchema: "ProfileEditApprovalList", successCode: "200", perm: authz.ProfilesRead},
		{method: "GET", path: "/api/v1/profiles/approvals/{id}", opID: "getProfileEditApproval", summary: "Get one parked profile create/edit approval request", handler: a.getProfileEditApproval, pathParams: approvalIDPath, resSchema: "ProfileEditApprovalRecord", successCode: "200", perm: authz.ProfilesRead},
		{method: "POST", path: "/api/v1/profiles/approvals/{id}/approvals", opID: "approveProfileEdit", summary: "Approve a parked profile create/edit as a distinct reviewer; quorum applies the queued spec", handler: a.approveProfileEdit, pathParams: approvalIDPath, reqSchema: "ProfileEditApprovalDecisionRequest", reqOptional: true, resSchema: "ProfileEditApprovalRecord", successCode: "200", mutation: true, perm: authz.ProfilesWrite},
	}
}

func (a *API) listProfileEditApprovals(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeError(w, errStatus(http.StatusUnauthorized, "missing or invalid tenant"))
		return
	}
	items, err := a.orch.ListProfileEditApprovals(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	now := time.Now().UTC()
	out := profileEditApprovalList{Items: make([]profileEditApprovalRecord, 0, len(items))}
	for _, it := range items {
		out.Items = append(out.Items, toProfileEditApprovalRecord(it, now))
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) getProfileEditApproval(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeError(w, errStatus(http.StatusUnauthorized, "missing or invalid tenant"))
		return
	}
	parked, err := a.orch.GetProfileEditApproval(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, profileEditApprovalError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, toProfileEditApprovalRecord(parked, time.Now().UTC()))
}

//trstctl:mutation
func (a *API) approveProfileEdit(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	requestID := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if r.ContentLength != 0 {
			var body profileEditApprovalDecisionRequest
			if err := decodeJSON(r, &body); err != nil {
				return 0, nil, errWithStatus(http.StatusBadRequest, err)
			}
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if strings.TrimSpace(principal.Subject) == "" {
			return 0, nil, errStatus(http.StatusUnauthorized, "missing authenticated principal")
		}
		parked, err := a.orch.ApproveProfileEdit(ctx, tenantID, requestID, principal.Subject)
		if err != nil {
			return 0, nil, profileEditApprovalError(err)
		}
		return http.StatusOK, toProfileEditApprovalRecord(parked, time.Now().UTC()), nil
	})
}
