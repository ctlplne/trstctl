// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"errors"
	"time"
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
