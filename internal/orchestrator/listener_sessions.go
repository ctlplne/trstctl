// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// RecordListenerSessionsWithEventID records a host's count of its listener's
// sessions right after a verified deploy (A245-L2). The event id is derived
// from the job attempt, so a retried report converges on one event.
func (o *Orchestrator) RecordListenerSessionsWithEventID(ctx context.Context, tenantID, eventID string, obs projections.ListenerSessionsObserved) error {
	if strings.TrimSpace(eventID) == "" {
		return errors.New("orchestrator: listener session count event id is required")
	}
	if err := projections.ValidateListenerSessionsObserved(obs); err != nil {
		return err
	}
	payload, err := json.Marshal(obs)
	if err != nil {
		return err
	}
	_, err = o.emitPreparedExact(ctx, events.Event{ID: eventID, Type: projections.EventListenerSessionsObserved, TenantID: tenantID, Data: payload})
	return err
}
