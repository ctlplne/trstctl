// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// RecordCredentialUse records an API token's use as the API's usage recorder
// noted it (M1). eventID is the recorder's stable identity for the note, so
// replicas that noted the same window and count record it once.
func (o *Orchestrator) RecordCredentialUse(ctx context.Context, tenantID, eventID string, used projections.CredentialUsed) error {
	return o.recordUsageEvent(ctx, tenantID, eventID, projections.EventCredentialUsed, used)
}

// RecordCredentialUsageGap records a window in which uses could not be
// recorded, so a later reader never mistakes the gap for non-use.
func (o *Orchestrator) RecordCredentialUsageGap(ctx context.Context, tenantID, eventID string, gap projections.CredentialUsageGap) error {
	return o.recordUsageEvent(ctx, tenantID, eventID, projections.EventCredentialUsageGap, gap)
}

func (o *Orchestrator) recordUsageEvent(ctx context.Context, tenantID, eventID, eventType string, payload any) error {
	if eventID == "" {
		return errors.New("orchestrator: usage events need an event id")
	}
	if _, found, err := o.log.EventByID(ctx, eventID); err != nil || found {
		return err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = o.emitPrepared(events.ContextWithoutActor(ctx), events.Event{ID: eventID, Type: eventType, TenantID: tenantID, Data: data})
	return err
}
