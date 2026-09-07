// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/approval"
	"trstctl.com/trstctl/internal/authz"
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

func toProfileEditApprovalRecord(req approval.Request) profileEditApprovalRecord {
	rec := profileEditApprovalRecord{
		ID: req.ID, Kind: string(req.Kind), Resource: req.Resource,
		ProfileName:       strings.TrimPrefix(req.Resource, "profile:"),
		Requester:         req.Requester,
		RequiredApprovals: req.RequiredApprovals,
		Approvals:         make([]profileEditApprovalDecision, 0, len(req.Approvals)),
		State:             string(req.State),
		ProfileID:         req.CredentialID,
		CreatedAt:         req.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt:         req.ExpiresAt.UTC().Format(time.RFC3339),
	}
	for _, a := range req.Approvals {
		rec.Approvals = append(rec.Approvals, profileEditApprovalDecision{Approver: a.Approver, Decision: a.Decision, At: a.At.UTC().Format(time.RFC3339)})
	}
	return rec
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
	items := a.orch.ListProfileEditApprovals(tenantID)
	out := profileEditApprovalList{Items: make([]profileEditApprovalRecord, 0, len(items))}
	for _, it := range items {
		out.Items = append(out.Items, toProfileEditApprovalRecord(it))
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) getProfileEditApproval(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeError(w, errStatus(http.StatusUnauthorized, "missing or invalid tenant"))
		return
	}
	req, _, found := a.orch.GetProfileEditApproval(tenantID, r.PathValue("id"))
	if !found {
		a.writeError(w, errStatus(http.StatusNotFound, "no such profile approval request"))
		return
	}
	a.writeJSON(w, http.StatusOK, toProfileEditApprovalRecord(req))
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
		if _, _, found := a.orch.GetProfileEditApproval(tenantID, requestID); !found {
			return 0, nil, errStatus(http.StatusNotFound, "no such profile approval request")
		}
		req, err := a.orch.ApproveProfileEdit(ctx, tenantID, requestID, principal.Subject)
		if err != nil {
			if strings.Contains(err.Error(), "dual control") {
				return 0, nil, errStatus(http.StatusForbidden, "dual control: the requester cannot approve their own profile edit")
			}
			return 0, nil, err
		}
		return http.StatusOK, toProfileEditApprovalRecord(req), nil
	})
}
