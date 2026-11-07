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

	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	next := events.Event{ID: servicedependents.ReconciliationReviewSourceID(tenantID, intent.Plan.ID), TenantID: tenantID, Type: projections.EventServiceReconciliationReviewProposed, SchemaVersion: 1, Data: raw}
	if intent.Plan.Manifest != nil {
		next.SchemaVersion = projections.ServiceDependentManifestReviewSchemaVersion
	}
	if err := projections.ValidateServiceReconciliationReviewSource(next, value); err != nil {
		return err
	}
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
	if json.Unmarshal(event.Data, &value) != nil || value.Intent.Plan.ID != id || projections.ValidateServiceReconciliationReviewSource(event, value) != nil {
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

// An independent approver reads the exact pages attached to a real frozen
// reconciliation review. Approval permission is sufficient for this public
// effect metadata; the requester never lends the approver a vault credential.
func (a *API) getPAMServiceReconciliationReviewPage(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	id, err := manifestPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	number, err := manifestPageNumber(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	review, digest, err := a.loadServiceReconciliationReview(r.Context(), tenantID, id)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if review.Intent.Plan.Manifest == nil || number >= review.Intent.Plan.Manifest.PageCount {
		a.writeError(w, errStatus(http.StatusNotFound, "native reconciliation review page not found"))
		return
	}
	state, err := a.canonicalManifestHeader(r.Context(), tenantID, id)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if state.Seal == nil {
		a.writeError(w, manifestConflict())
		return
	}
	intent, err := servicedependents.NewRotationIntentFromManifest(state.Header, *state.Seal)
	if err != nil {
		a.writeError(w, err)
		return
	}
	exact, err := intent.Digest()
	if err != nil || exact != digest {
		a.writeError(w, manifestConflict())
		return
	}
	page, err := a.canonicalManifestPage(r.Context(), tenantID, state, number)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, page)
}
