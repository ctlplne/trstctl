// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	adcsdiscovery "trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// RecordADCSInventoryObservedWithEventID appends one normalized, receipt-bound
// AD CS posture observation and lets the projector replace that domain's view.
// The event carries SIDs and template facts only: never the bind credential or
// nTSecurityDescriptor bytes.
func (o *Orchestrator) RecordADCSInventoryObservedWithEventID(
	ctx context.Context,
	tenantID, eventID string,
	observation adcsdiscovery.InventoryObserved,
) error {
	if strings.TrimSpace(eventID) == "" {
		return errors.New("orchestrator: AD CS observation event id is required")
	}
	payload, err := json.Marshal(observation)
	if err != nil {
		return err
	}
	_, err = o.emitPreparedExact(ctx, events.Event{
		ID: eventID, Type: projections.EventADCSInventoryObserved,
		TenantID: tenantID, SchemaVersion: adcsdiscovery.InventoryEventSchemaVersion, Data: payload,
	})
	return err
}
