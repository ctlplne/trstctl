// SPDX-License-Identifier: BUSL-1.1

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

type nhiReviewCampaignResponse struct {
	ID              string                  `json:"id"`
	TenantID        string                  `json:"tenant_id"`
	Name            string                  `json:"name"`
	Scope           string                  `json:"scope"`
	ReviewerSubject string                  `json:"reviewer_subject"`
	RequestedBy     string                  `json:"requested_by"`
	Status          string                  `json:"status"`
	DueAt           *time.Time              `json:"due_at,omitempty"`
	ItemCount       int                     `json:"item_count"`
	PendingCount    int                     `json:"pending_count"`
	CertifiedCount  int                     `json:"certified_count"`
	RevokedCount    int                     `json:"revoked_count"`
	ExceptionCount  int                     `json:"exception_count"`
	CreatedAt       time.Time               `json:"created_at"`
	UpdatedAt       time.Time               `json:"updated_at"`
	CompletedAt     *time.Time              `json:"completed_at,omitempty"`
	Items           []nhiReviewItemResponse `json:"items,omitempty"`
}

type nhiReviewItemResponse struct {
	ItemID               string     `json:"item_id"`
	NHIID                string     `json:"nhi_id"`
	NHIKind              string     `json:"nhi_kind"`
	DisplayName          string     `json:"display_name"`
	OwnerRef             string     `json:"owner_ref,omitempty"`
	Resource             string     `json:"resource"`
	Entitlement          string     `json:"entitlement"`
	Risk                 string     `json:"risk"`
	EvidenceRefs         []string   `json:"evidence_refs"`
	Status               string     `json:"status"`
	DecisionBy           string     `json:"decision_by,omitempty"`
	DecisionReason       string     `json:"decision_reason,omitempty"`
	DecisionEvidenceRefs []string   `json:"decision_evidence_refs,omitempty"`
	DecidedAt            *time.Time `json:"decided_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

//trstctl:mutation
func (a *API) startNHIReviewCampaign(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "NHI access reviews are not configured")
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
			return 0, nil, errStatus(http.StatusBadRequest, "NHI access reviews accept evidence references, not inline credential or token values")
		}
		var req orchestrator.NHIReviewCampaignStartRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "invalid NHI access review campaign request")
		}
		campaign, err := a.orch.StartNHIReviewCampaign(ctx, tenantID, req)
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		return http.StatusCreated, toNHIReviewCampaignResponse(campaign, true), nil
	})
}

func (a *API) listNHIReviewCampaigns(w http.ResponseWriter, r *http.Request) {
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
	rows, err := a.store.ListNHIReviewCampaignsPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]nhiReviewCampaignResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toNHIReviewCampaignResponse(row, false))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) getNHIReviewCampaign(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	campaign, err := a.store.GetNHIReviewCampaign(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toNHIReviewCampaignResponse(campaign, true))
}

//trstctl:mutation
func (a *API) decideNHIReviewItem(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	campaignID := r.PathValue("id")
	itemID := r.PathValue("item_id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "NHI access reviews are not configured")
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
			return 0, nil, errStatus(http.StatusBadRequest, "NHI access reviews accept evidence references, not inline credential or token values")
		}
		var req orchestrator.NHIReviewDecisionRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "invalid NHI access review decision request")
		}
		campaign, err := a.orch.DecideNHIReviewItem(ctx, tenantID, campaignID, itemID, req)
		if err != nil {
			if errors.Is(err, store.ErrNHIReviewItemAlreadyDecided) {
				return 0, nil, errStatus(http.StatusConflict, err.Error())
			}
			if store.IsNotFound(err) {
				return 0, nil, errStatus(http.StatusNotFound, "NHI access review item not found")
			}
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		return http.StatusOK, toNHIReviewCampaignResponse(campaign, true), nil
	})
}

func toNHIReviewCampaignResponse(c store.NHIReviewCampaign, includeItems bool) nhiReviewCampaignResponse {
	resp := nhiReviewCampaignResponse{
		ID: c.ID, TenantID: c.TenantID, Name: c.Name, Scope: c.Scope,
		ReviewerSubject: c.ReviewerSubject, RequestedBy: c.RequestedBy, Status: c.Status,
		DueAt: c.DueAt, ItemCount: c.ItemCount, PendingCount: c.PendingCount,
		CertifiedCount: c.CertifiedCount, RevokedCount: c.RevokedCount,
		ExceptionCount: c.ExceptionCount, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
		CompletedAt: c.CompletedAt,
	}
	if includeItems {
		resp.Items = make([]nhiReviewItemResponse, 0, len(c.Items))
		for _, item := range c.Items {
			resp.Items = append(resp.Items, toNHIReviewItemResponse(item))
		}
	}
	return resp
}

func toNHIReviewItemResponse(item store.NHIReviewItem) nhiReviewItemResponse {
	refs := item.EvidenceRefs
	if refs == nil {
		refs = []string{}
	}
	decisionRefs := item.DecisionEvidenceRefs
	if decisionRefs == nil {
		decisionRefs = []string{}
	}
	return nhiReviewItemResponse{
		ItemID: item.ItemID, NHIID: item.NHIID, NHIKind: item.NHIKind, DisplayName: item.DisplayName,
		OwnerRef: item.OwnerRef, Resource: item.Resource, Entitlement: item.Entitlement,
		Risk: item.Risk, EvidenceRefs: refs, Status: item.Status, DecisionBy: item.DecisionBy,
		DecisionReason: item.DecisionReason, DecisionEvidenceRefs: decisionRefs,
		DecidedAt: item.DecidedAt, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}
