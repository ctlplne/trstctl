// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"errors"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/servicedependents"
)

const EventServiceDependentCursorAdvanced = "pam.service_dependents.cursor_advanced"
const ServiceDependentManifestSchemaVersion = 3
const ServiceDependentManifestStepSchemaVersion = 2
const ServiceDependentManifestReviewSchemaVersion = 2

type ServiceDependentCursorAdvanced = servicedependents.ManifestCursorAdvance

func ValidateServiceDependentCursorAdvanceSource(e events.Event, v ServiceDependentCursorAdvanced, intent servicedependents.RotationIntent) error {
	if e.Type != EventServiceDependentCursorAdvanced || schemaVersionOf(e) != 1 || e.ID != servicedependents.ManifestCursorAdvanceSourceID(e.TenantID, v.RotationID, v.PreviousSourceID) || !e.Time.Equal(v.At) {
		return errors.New("dependent cursor: exact immutable successor source required")
	}
	return v.Validate(intent)
}
