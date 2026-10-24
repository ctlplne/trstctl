// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Stale NHI owner handoff (A101). The stale posture finds dormant, unused and
// orphaned NHIs; a handoff gives them to a new accountable owner in one step:
// the ownership assignment the inventory now honors for every source, the
// previous owner of each record kept in the response, and an ownership-channel
// notice telling the new owner to reattest what is still in use and retire the
// rest.

type nhiStaleHandoffRequest struct {
	OwnerID      string   `json:"owner_id"`
	InventoryIDs []string `json:"inventory_ids"`
	Reason       string   `json:"reason"`
}

type nhiStaleHandoffItem struct {
	InventoryID     string   `json:"inventory_id"`
	DisplayName     string   `json:"display_name"`
	Kind            string   `json:"kind"`
	FromOwnerID     string   `json:"from_owner_id,omitempty"`
	FromOwnerStatus string   `json:"from_owner_status"`
	FindingTypes    []string `json:"finding_types"`
}

type nhiStaleHandoffResponse struct {
	OwnerID      string                `json:"owner_id"`
	Items        []nhiStaleHandoffItem `json:"items"`
	AssignedBy   string                `json:"assigned_by"`
	AssignedAt   time.Time             `json:"assigned_at"`
	NoticeQueued bool                  `json:"notice_queued"`
}

//trstctl:mutation
func (a *API) handOffStaleNHIs(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req nhiStaleHandoffRequest
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
		posture, err := a.nhiStalePosture(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		stale := make(map[string]nhiStalePostureFinding, len(posture.Findings))
		for _, finding := range posture.Findings {
			stale[finding.InventoryID] = finding
		}
		items := make([]nhiStaleHandoffItem, 0, len(req.InventoryIDs))
		ids := make([]string, 0, len(req.InventoryIDs))
		for _, id := range req.InventoryIDs {
			id = strings.TrimSpace(id)
			finding, ok := stale[id]
			if !ok {
				return 0, nil, errStatus(http.StatusUnprocessableEntity, "inventory_ids contains a record that is not in the stale NHI posture: "+id)
			}
			if finding.OwnerID == req.OwnerID {
				return 0, nil, errStatus(http.StatusConflict, "the record already belongs to that owner: "+id)
			}
			ids = append(ids, id)
			items = append(items, nhiStaleHandoffItem{
				InventoryID: id, DisplayName: finding.DisplayName, Kind: finding.Kind,
				FromOwnerID: finding.OwnerID, FromOwnerStatus: finding.OwnerStatus, FindingTypes: finding.FindingTypes,
			})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].InventoryID < items[j].InventoryID })
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		assignment, err := a.orch.AssignOwnership(ctx, tenantID, req.OwnerID, ids, "handoff: "+req.Reason, principal.Subject)
		if err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		// One notice per handoff command: a retry of the same request converges.
		queued, err := a.orch.QueueOwnerHandoffNotice(ctx, tenantID, req.OwnerID, assignment.InventoryIDs, req.Reason,
			crypto.SHA256Hex([]byte(tenantID+"\x00"+idempotencyKey)))
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, nhiStaleHandoffResponse{
			OwnerID: assignment.OwnerID, Items: items, AssignedBy: assignment.AssignedBy,
			AssignedAt: assignment.AssignedAt, NoticeQueued: queued,
		}, nil
	})
}
