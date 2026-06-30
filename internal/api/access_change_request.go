package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type accessChangeRequestResponse struct {
	ID                string                         `json:"id"`
	TenantID          string                         `json:"tenant_id"`
	RequestedAction   string                         `json:"requested_action"`
	RequesterSubject  string                         `json:"requester_subject"`
	NHIID             string                         `json:"nhi_id"`
	NHIKind           string                         `json:"nhi_kind"`
	DisplayName       string                         `json:"display_name"`
	OwnerRef          string                         `json:"owner_ref,omitempty"`
	Resource          string                         `json:"resource"`
	Entitlement       string                         `json:"entitlement"`
	ChangeRef         string                         `json:"change_ref"`
	ChangeSystem      string                         `json:"change_system"`
	ChangeURL         string                         `json:"change_url,omitempty"`
	Risk              string                         `json:"risk"`
	Reason            string                         `json:"reason"`
	EvidenceRefs      []string                       `json:"evidence_refs"`
	Status            string                         `json:"status"`
	RequiredApprovals int                            `json:"required_approvals"`
	ApprovalCount     int                            `json:"approval_count"`
	CreatedAt         time.Time                      `json:"created_at"`
	UpdatedAt         time.Time                      `json:"updated_at"`
	CompletedAt       *time.Time                     `json:"completed_at,omitempty"`
	Decisions         []accessChangeDecisionResponse `json:"decisions,omitempty"`
}

type accessChangeDecisionResponse struct {
	RequestID            string    `json:"request_id"`
	ApproverSubject      string    `json:"approver_subject"`
	Decision             string    `json:"decision"`
	Reason               string    `json:"reason,omitempty"`
	DecisionEvidenceRefs []string  `json:"decision_evidence_refs"`
	DecidedAt            time.Time `json:"decided_at"`
}

//trstctl:mutation
func (a *API) createAccessChangeRequest(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "access change requests are not configured")
		}
		var raw json.RawMessage
		if err := decodeJSON(r, &raw); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
			return 0, nil, errStatus(http.StatusBadRequest, "request body must be a JSON object")
		}
		if containsInlineSecret(obj) {
			return 0, nil, errStatus(http.StatusBadRequest, "access change requests accept PR/change/evidence references, not inline credential or token values")
		}
		var req orchestrator.AccessChangeRequestCreateRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "invalid access change request")
		}
		created, err := a.orch.CreateAccessChangeRequest(ctx, tenantID, req)
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		return http.StatusCreated, toAccessChangeRequestResponse(created, true), nil
	})
}

func (a *API) listAccessChangeRequests(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	rows, err := a.store.ListAccessChangeRequestsPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]accessChangeRequestResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toAccessChangeRequestResponse(row, false))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) getAccessChangeRequest(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	req, err := a.store.GetAccessChangeRequest(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toAccessChangeRequestResponse(req, true))
}

//trstctl:mutation
func (a *API) decideAccessChangeRequest(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	requestID := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "access change requests are not configured")
		}
		var raw json.RawMessage
		if err := decodeJSON(r, &raw); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
			return 0, nil, errStatus(http.StatusBadRequest, "request body must be a JSON object")
		}
		if containsInlineSecret(obj) {
			return 0, nil, errStatus(http.StatusBadRequest, "access change decisions accept evidence references, not inline credential or token values")
		}
		var req orchestrator.AccessChangeDecisionRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "invalid access change decision")
		}
		updated, err := a.orch.DecideAccessChangeRequest(ctx, tenantID, requestID, req)
		if err != nil {
			if errors.Is(err, store.ErrAccessChangeRequestTerminal) || errors.Is(err, store.ErrAccessChangeDecisionDuplicate) {
				return 0, nil, errStatus(http.StatusConflict, err.Error())
			}
			if store.IsNotFound(err) {
				return 0, nil, errStatus(http.StatusNotFound, "access change request not found")
			}
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		return http.StatusOK, toAccessChangeRequestResponse(updated, true), nil
	})
}

func toAccessChangeRequestResponse(req store.AccessChangeRequest, includeDecisions bool) accessChangeRequestResponse {
	refs := req.EvidenceRefs
	if refs == nil {
		refs = []string{}
	}
	resp := accessChangeRequestResponse{
		ID: req.ID, TenantID: req.TenantID, RequestedAction: req.RequestedAction,
		RequesterSubject: req.RequesterSubject, NHIID: req.NHIID, NHIKind: req.NHIKind,
		DisplayName: req.DisplayName, OwnerRef: req.OwnerRef, Resource: req.Resource,
		Entitlement: req.Entitlement, ChangeRef: req.ChangeRef, ChangeSystem: req.ChangeSystem,
		ChangeURL: req.ChangeURL, Risk: req.Risk, Reason: req.Reason, EvidenceRefs: refs,
		Status: req.Status, RequiredApprovals: req.RequiredApprovals, ApprovalCount: req.ApprovalCount,
		CreatedAt: req.CreatedAt, UpdatedAt: req.UpdatedAt, CompletedAt: req.CompletedAt,
	}
	if includeDecisions {
		resp.Decisions = make([]accessChangeDecisionResponse, 0, len(req.Decisions))
		for _, decision := range req.Decisions {
			resp.Decisions = append(resp.Decisions, toAccessChangeDecisionResponse(decision))
		}
	}
	return resp
}

func toAccessChangeDecisionResponse(decision store.AccessChangeDecision) accessChangeDecisionResponse {
	refs := decision.DecisionEvidenceRefs
	if refs == nil {
		refs = []string{}
	}
	return accessChangeDecisionResponse{
		RequestID: decision.RequestID, ApproverSubject: decision.ApproverSubject,
		Decision: decision.Decision, Reason: decision.Reason,
		DecisionEvidenceRefs: refs, DecidedAt: decision.DecidedAt,
	}
}
