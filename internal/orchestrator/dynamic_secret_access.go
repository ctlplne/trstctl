// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// RecordDynamicSecretLeaseAccess records what an active lease reaches, as its
// target reported it to the leader's access worker (G2). eventID is the
// worker's stable identity for the observation; an observation already
// recorded under it is kept, so two leaders in the same window converge.
func (o *Orchestrator) RecordDynamicSecretLeaseAccess(ctx context.Context, tenantID, eventID string, observed projections.DynamicSecretLeaseAccessObserved) error {
	if eventID == "" {
		return errors.New("orchestrator: lease access observation needs an event id")
	}
	if _, found, err := o.log.EventByID(ctx, eventID); err != nil || found {
		return err
	}
	payload, err := json.Marshal(observed)
	if err != nil {
		return err
	}
	_, err = o.emitPrepared(ctx, events.Event{
		ID: eventID, Type: projections.EventDynamicSecretLeaseAccessObserved, TenantID: tenantID, Data: payload,
	})
	return err
}
