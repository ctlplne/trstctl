// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"errors"
	"time"

	"trstctl.com/trstctl/internal/events"
)

const endpointVerificationAlertEventSchemaVersionV2 = 2
const EndpointVerificationAlertEventSchemaVersion = 3

// EndpointVerificationObservedWithAlert retains the notification decision with
// the observation. Reconciliation must use this historical last-good snapshot,
// not whatever a later probe has put in the current endpoint row.
type EndpointVerificationObservedWithAlert struct {
	EndpointVerificationObserved
	AlertRequired         bool      `json:"alert_required"`
	AlertLastGoodAt       time.Time `json:"alert_last_good_at,omitzero"`
	SupersededExpectation bool      `json:"superseded_expectation,omitempty"`
}

func (v EndpointVerificationObservedWithAlert) ValidateAlert() error {
	if v.AlertRequired != (!v.SupersededExpectation && (!v.Reached || v.Mismatch != "")) {
		return errors.New("endpoint observation has an inconsistent alert decision")
	}
	if v.SupersededExpectation && v.Vantage != "relay" {
		return errors.New("only a relay observation can carry a superseded expectation")
	}
	if !v.AlertRequired && !v.AlertLastGoodAt.IsZero() {
		return errors.New("endpoint observation without an alert carries an alert snapshot")
	}
	return nil
}

// Schema two has a closed historical shape. A schema-three decision can mark a
// signed relay observation as superseded after a newer local deployment.
type endpointVerificationObservedWithAlertV2 struct {
	EndpointVerificationObserved
	AlertRequired   bool      `json:"alert_required"`
	AlertLastGoodAt time.Time `json:"alert_last_good_at,omitzero"`
}

func decodeEndpointVerificationObservedWithDecision(e events.Event) (EndpointVerificationObserved, bool, error) {
	switch e.SchemaVersion {
	case EndpointVerificationAlertEventSchemaVersion:
		var observed EndpointVerificationObservedWithAlert
		if err := decode(e, &observed); err != nil {
			return EndpointVerificationObserved{}, false, err
		}
		return observed.EndpointVerificationObserved, observed.SupersededExpectation, observed.ValidateAlert()
	case endpointVerificationAlertEventSchemaVersionV2:
		var observed endpointVerificationObservedWithAlertV2
		if err := decode(e, &observed); err != nil {
			return EndpointVerificationObserved{}, false, err
		}
		if observed.AlertRequired != (!observed.Reached || observed.Mismatch != "") || (!observed.AlertRequired && !observed.AlertLastGoodAt.IsZero()) {
			return EndpointVerificationObserved{}, false, errors.New("endpoint observation has an inconsistent historical alert decision")
		}
		return observed.EndpointVerificationObserved, false, nil
	}
	var observed EndpointVerificationObserved
	err := decode(e, &observed)
	return observed, false, err
}

func decodeEndpointVerificationObserved(e events.Event) (EndpointVerificationObserved, error) {
	observed, _, err := decodeEndpointVerificationObservedWithDecision(e)
	return observed, err
}
