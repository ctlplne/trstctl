// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
)

// Cancelling a target's queued or running connector work (A48).
//
// Deploy, rollback, host renewal and containment commands for one deployment
// target share that target's lane. The cancel route drains the lane: a command
// nobody holds is withdrawn, a command an enrolled agent holds is recalled so
// the agent stops at its next check-in and a late result is retained rather
// than applied, and a command the control-plane worker is executing inside a
// connector call right now is reported and left alone, because stopping it
// mid-call would leave the appliance half-written. Every withdrawn or recalled
// command gets a cancelled receipt.

type connectorWorkCancellationResponse struct {
	TargetID string `json:"target_id"`
	// Withdrawn commands were never claimed; the target was not changed by them.
	Withdrawn []int64 `json:"withdrawn_job_ids"`
	// Recalled commands were leased by an agent that may already have acted.
	Recalled []int64 `json:"recalled_job_ids"`
	// Executing commands are inside a control-plane connector call and were not
	// cancelled; cancel again once they land, or roll back.
	Executing []int64                     `json:"executing_job_ids"`
	Receipts  []connectorDeliveryResponse `json:"receipts"`
}

//trstctl:mutation
func (a *API) cancelConnectorTargetWork(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	targetID := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		req, err := decodeConnectorTargetActionRequest(r)
		if err != nil {
			return 0, nil, err
		}
		if strings.TrimSpace(req.Reason) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "cancelling connector work needs a reason")
		}
		if a.orch == nil {
			return 0, nil, errors.New("connector orchestrator is unavailable")
		}
		target, err := a.store.GetDeploymentTarget(ctx, tenantID, targetID)
		if err != nil {
			return 0, nil, err
		}
		if strings.TrimSpace(req.IdentityID) != "" {
			if _, err := a.store.GetIdentity(ctx, tenantID, req.IdentityID); err != nil {
				return 0, nil, err
			}
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		cancelled, err := a.orch.CancelConnectorTargetWork(ctx, tenantID, orchestrator.CancelConnectorWorkRequest{
			TargetID: target.ID, IdentityID: strings.TrimSpace(req.IdentityID),
			Reason: strings.TrimSpace(req.Reason), RequestedBy: principal.Subject,
		})
		if err != nil {
			return 0, nil, err
		}
		out := connectorWorkCancellationResponse{
			TargetID: target.ID, Withdrawn: []int64{}, Recalled: []int64{}, Executing: []int64{},
			Receipts: []connectorDeliveryResponse{},
		}
		out.Withdrawn = append(out.Withdrawn, cancelled.Withdrawn...)
		out.Recalled = append(out.Recalled, cancelled.Recalled...)
		out.Executing = append(out.Executing, cancelled.Executing...)
		for _, receipt := range cancelled.Receipts {
			out.Receipts = append(out.Receipts, toConnectorDeliveryResponse(receipt))
		}
		return http.StatusOK, out, nil
	})
}
