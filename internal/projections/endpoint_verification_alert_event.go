// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"errors"
	"time"

	"trstctl.com/trstctl/internal/events"
)

const EndpointVerificationAlertEventSchemaVersion = 2

// EndpointVerificationObservedWithAlert retains the notification decision with
// the observation. Reconciliation must use this historical last-good snapshot,
// not whatever a later probe has put in the current endpoint row.
type EndpointVerificationObservedWithAlert struct {
	EndpointVerificationObserved
	AlertRequired   bool      `json:"alert_required"`
	AlertLastGoodAt time.Time `json:"alert_last_good_at,omitzero"`
}

func (v EndpointVerificationObservedWithAlert) ValidateAlert() error {
	if v.AlertRequired != (!v.Reached || v.Mismatch != "") {
		return errors.New("endpoint observation has an inconsistent alert decision")
	}
	if !v.AlertRequired && !v.AlertLastGoodAt.IsZero() {
		return errors.New("healthy endpoint observation carries an alert snapshot")
	}
	return nil
}

func decodeEndpointVerificationObserved(e events.Event) (EndpointVerificationObserved, error) {
	if e.SchemaVersion == EndpointVerificationAlertEventSchemaVersion {
		var observed EndpointVerificationObservedWithAlert
		if err := decode(e, &observed); err != nil {
			return EndpointVerificationObserved{}, err
		}
		return observed.EndpointVerificationObserved, observed.ValidateAlert()
	}
	var observed EndpointVerificationObserved
	err := decode(e, &observed)
	return observed, err
}
