// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type ownershipAssignmentRequest struct {
	OwnerID      string   `json:"owner_id"`
	InventoryIDs []string `json:"inventory_ids"`
	Reason       string   `json:"reason"`
}

type ownershipAssignmentResponse struct {
	OwnerID    string    `json:"owner_id"`
	Assigned   []string  `json:"assigned"`
	AssignedBy string    `json:"assigned_by"`
	AssignedAt time.Time `json:"assigned_at"`
}

//trstctl:mutation
func (a *API) assignOwnership(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req ownershipAssignmentRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.OwnerID, req.Reason = strings.TrimSpace(req.OwnerID), strings.TrimSpace(req.Reason)
		if req.OwnerID == "" || req.Reason == "" || len(req.InventoryIDs) == 0 || len(req.InventoryIDs) > projections.MaxOwnershipAssignmentAssets {
			return 0, nil, errStatus(http.StatusBadRequest, "owner_id, reason, and 1-100 inventory_ids are required")
		}
		if _, err := a.store.GetOwner(ctx, tenantID, req.OwnerID); err != nil {
			if store.IsNotFound(err) {
				return 0, nil, errStatus(http.StatusUnprocessableEntity, "owner_id does not reference an owner in this tenant")
			}
			return 0, nil, err
		}
		inventory, err := a.nhiInventory(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		known := make(map[string]bool, len(inventory.Items))
		for _, item := range inventory.Items {
			known[item.ID] = true
		}
		for i := range req.InventoryIDs {
			req.InventoryIDs[i] = strings.TrimSpace(req.InventoryIDs[i])
			if !known[req.InventoryIDs[i]] {
				return 0, nil, errStatus(http.StatusUnprocessableEntity, "inventory_ids contains an unknown tenant inventory record")
			}
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		assignment, err := a.orch.AssignOwnership(ctx, tenantID, req.OwnerID, req.InventoryIDs, req.Reason, principal.Subject)
		if err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		return http.StatusOK, ownershipAssignmentResponse{
			OwnerID: assignment.OwnerID, Assigned: assignment.InventoryIDs,
			AssignedBy: assignment.AssignedBy, AssignedAt: assignment.AssignedAt,
		}, nil
	})
}
