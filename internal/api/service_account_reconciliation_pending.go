// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"encoding/json"
	"errors"
	googleuuid "github.com/google/uuid"
	"net/http"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

type dependentReconcilePendingReview struct {
	dependentReconcileReviewView
	Approval     dependentReconcileApprovalView `json:"approval"`
	Reason       string                         `json:"reason"`
	QueuePending bool                           `json:"queue_pending,omitempty"`
	RotationID   string                         `json:"rotation_id,omitempty"`
}

// The requester can resume the exact review without acquiring the permission
// to approve it. This read never creates a grant, command or external job.
func (a *API) getPAMServiceReconciliationPendingReview(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	value, digest, err := a.loadServiceReconciliationReview(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	if value.Intent.Plan.Account.AccountID != r.PathValue("account_id") {
		a.writeError(w, errStatus(http.StatusNotFound, "reconciliation review not found"))
		return
	}
	if err := a.dependentRotationPermission(r.Context(), r, tenantID, value.Intent.Plan.SecretName); err != nil {
		a.writeError(w, err)
		return
	}
	actor, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	if value.Actor != actor {
		a.writeError(w, errStatus(http.StatusForbidden, "only the requester may resume this reconciliation review"))
		return
	}
	requestID := r.URL.Query().Get("approval_request_id")
	parsed, err := googleuuid.Parse(requestID)
	if err != nil || parsed == googleuuid.Nil || parsed.String() != requestID {
		a.writeError(w, errStatus(http.StatusBadRequest, "exact approval request ID required"))
		return
	}
	approval, err := a.store.GetOperationApproval(r.Context(), tenantID, requestID)
	if err != nil {
		a.writeError(w, approvalAPIError(err))
		return
	}
	if approval.Requester != actor {
		a.writeError(w, errStatus(http.StatusForbidden, "approval request belongs to another requester"))
		return
	}
	use, err := store.OperationApprovalUseFromRequest(approval)
	if err == nil {
		err = projections.ValidateServiceDependentRotationApproval(projections.ServiceDependentRotationQueued{Intent: value.Intent, Actor: actor, Approval: &use})
	}
	if err != nil {
		a.writeError(w, errStatus(http.StatusConflict, "approval no longer names this exact review"))
		return
	}
	view := dependentReconcilePendingReview{dependentReconcileReviewView: dependentReconcileReviewView{value.Intent, digest, value.At}, Approval: dependentReconcileApprovalView{approval.ID, approval.IntentDigest, approval.Status, approval.RequiredApprovals, approval.ApprovalCount, approval.ExpiresAt}, Reason: approval.Reason}
	if approval.Status == store.ApprovalStatusConsumed {
		parent, err := a.store.GetServiceDependentRotation(r.Context(), tenantID, value.Intent.Plan.ID)
		if errors.Is(err, store.ErrServiceDependentRotationNotFound) {
			fence, fenceErr := a.store.GetApprovedTargetFence(r.Context(), tenantID, store.ApprovedTargetServiceReconciliation, servicedependents.ReconcileCommandKey(tenantID, value.Intent.Plan.SecretName))
			var queued projections.ServiceDependentRotationQueued
			if fenceErr != nil || fence.EventID != value.Intent.Plan.ID || approval.ConsumedEventID != fence.EventID || fence.RequestBinding != digest || fence.Approval.RequestID != approval.ID || fence.Approval.IntentDigest != approval.IntentDigest || json.Unmarshal(fence.Payload, &queued) != nil || queued.Actor != actor {
				a.writeError(w, errStatus(http.StatusConflict, "consumed review has no matching first command"))
				return
			}
			event := serviceReconciliationFenceEvent(fence)
			semantic, semanticErr := projections.ServiceReconcileSemanticDigest(event, queued)
			if semanticErr != nil || semantic != fence.SemanticDigest {
				a.writeError(w, errStatus(http.StatusConflict, "first reconciliation command differs"))
				return
			}
			view.QueuePending = true
			a.writeJSON(w, http.StatusOK, view)
			return
		}
		if err != nil {
			a.writeError(w, err)
			return
		}
		command, err := a.store.GetSecretStaticRotationCommand(r.Context(), tenantID, parent.CommandID)
		if err == nil {
			_, err = a.dependentRotationParent(r.Context(), command)
		}
		if err != nil || approval.ConsumedEventID != parent.ID {
			a.writeError(w, errStatus(http.StatusConflict, "consumed review differs from its canonical operation"))
			return
		}
		view.RotationID = parent.ID
	}
	a.writeJSON(w, http.StatusOK, view)
}
