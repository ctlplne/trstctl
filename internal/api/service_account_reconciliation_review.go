// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

type dependentReconcileReviewView struct {
	Intent    servicedependents.RotationIntent `json:"intent"`
	Digest    string                           `json:"intent_digest"`
	CreatedAt time.Time                        `json:"created_at"`
}

func (a *API) retainServiceReconciliationReview(ctx context.Context, tenantID, actor string, intent servicedependents.RotationIntent) error {
	value := projections.ServiceReconciliationReview{Intent: intent, Actor: actor, At: intent.Plan.CreatedAt}
	if err := projections.ValidateServiceReconciliationReview(value); err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	next := events.Event{ID: servicedependents.ReconciliationReviewSourceID(tenantID, intent.Plan.ID), TenantID: tenantID, Type: projections.EventServiceReconciliationReviewProposed, SchemaVersion: 1, Data: raw}
	if actor, ok := events.ActorFromContext(ctx); ok {
		next.Actor = &actor
	}
	canonical, err := a.log.Append(ctx, next)
	if err != nil {
		return err
	}
	if canonical.TenantID != tenantID || canonical.ID != next.ID || canonical.Type != next.Type || !bytes.Equal(canonical.Data, raw) {
		return store.ErrIdempotencyConflict
	}
	return projections.New(a.store).Apply(ctx, canonical)
}

func (a *API) loadServiceReconciliationReview(ctx context.Context, tenantID, id string) (projections.ServiceReconciliationReview, string, error) {
	var value projections.ServiceReconciliationReview
	if a.log == nil {
		return value, "", ErrPAMUnavailable
	}
	event, found, err := a.log.EventByID(ctx, servicedependents.ReconciliationReviewSourceID(tenantID, id))
	if err != nil {
		return value, "", err
	}
	if !found || event.TenantID != tenantID || event.Type != projections.EventServiceReconciliationReviewProposed {
		return value, "", errStatus(http.StatusNotFound, "reconciliation review not found")
	}
	if event.SchemaVersion != 1 || json.Unmarshal(event.Data, &value) != nil || value.Intent.Plan.ID != id || projections.ValidateServiceReconciliationReview(value) != nil {
		return value, "", errStatus(http.StatusConflict, "canonical reconciliation review differs")
	}
	digest, err := value.Intent.Digest()
	return value, digest, err
}
func (a *API) getPAMServiceReconciliationReview(w http.ResponseWriter, r *http.Request) {
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
	a.writeJSON(w, http.StatusOK, dependentReconcileReviewView{value.Intent, digest, value.At})
}
