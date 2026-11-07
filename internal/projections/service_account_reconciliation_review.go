// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"errors"
	"time"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/servicedependents"
)

const EventServiceReconciliationReviewProposed = "pam.service_dependents.reconcile_review_proposed"

// ServiceReconciliationReview retains what another operator can inspect before
// deciding. It carries public effect metadata and no credential or human reason.
type ServiceReconciliationReview struct {
	Intent servicedependents.RotationIntent `json:"intent"`
	Actor  string                           `json:"actor"`
	At     time.Time                        `json:"at"`
}

func ValidateServiceReconciliationReview(v ServiceReconciliationReview) error {
	if v.Intent.Plan.Version != servicedependents.RotationPlanVersion || v.Intent.Plan.Manifest != nil || v.Intent.Mode != servicedependents.Reconcile || v.Actor == "" || !v.At.Equal(v.Intent.Plan.CreatedAt) {
		return errors.New("dependent reconciliation: incomplete frozen review")
	}
	_, err := v.Intent.Digest()
	return err
}

func ValidateServiceReconciliationReviewSource(e events.Event, v ServiceReconciliationReview) error {
	version := schemaVersionOf(e)
	if e.Type != EventServiceReconciliationReviewProposed || e.ID != servicedependents.ReconciliationReviewSourceID(e.TenantID, v.Intent.Plan.ID) {
		return errors.New("dependent reconciliation: frozen review source identity differs")
	}
	if version == 1 {
		var historical privacyServiceReconciliationReviewV1
		if err := decodePublishedDependentSource(e.Data, &historical); err != nil {
			return err
		}
		return ValidateServiceReconciliationReview(v)
	}
	if version != ServiceDependentManifestReviewSchemaVersion || v.Intent.Plan.Version != servicedependents.RotationManifestPlanVersion || v.Intent.Plan.Manifest == nil || v.Intent.Mode != servicedependents.Reconcile || v.Actor == "" || !v.At.Equal(v.Intent.Plan.CreatedAt) {
		return errors.New("dependent reconciliation: sealed review version differs")
	}
	var exact ServiceReconciliationReview
	if err := decodePublishedDependentSource(e.Data, &exact); err != nil {
		return err
	}
	if err := validateApprovalActor(e, v.Actor); err != nil {
		return err
	}
	_, err := v.Intent.Digest()
	return err
}
