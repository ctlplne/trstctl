// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Scoped secret sync (A237): each change is one event.

// DefineSecretScopedSync records a scoped sync definition.
func (o *Orchestrator) DefineSecretScopedSync(ctx context.Context, tenantID string, defined projections.SecretScopedSyncDefined) error {
	return o.emitSecretProjectEvent(ctx, tenantID, projections.EventSecretScopedSyncDefined, defined)
}

// RemoveSecretScopedSync records that a definition is gone; the destination
// keys it wrote stay where they are.
func (o *Orchestrator) RemoveSecretScopedSync(ctx context.Context, tenantID string, removed projections.SecretScopedSyncRemoved) error {
	return o.emitSecretProjectEvent(ctx, tenantID, projections.EventSecretScopedSyncRemoved, removed)
}

// RecordSecretScopedSyncApplied records an applied plan under its stable event
// ID, so a retried apply finds the plan it already fixed instead of making a
// new one. A different payload under the same ID is an idempotency conflict.
func (o *Orchestrator) RecordSecretScopedSyncApplied(ctx context.Context, tenantID, eventID string, applied projections.SecretScopedSyncApplied) (projections.SecretScopedSyncApplied, error) {
	data, err := json.Marshal(applied)
	if err != nil {
		return applied, err
	}
	ev, err := o.emitPrepared(ctx, events.Event{ID: eventID, Type: projections.EventSecretScopedSyncApplied, TenantID: tenantID, Data: data})
	if err != nil {
		return applied, err
	}
	if ev.ID != eventID || ev.Type != projections.EventSecretScopedSyncApplied || ev.TenantID != tenantID || !bytes.Equal(ev.Data, data) {
		return applied, fmt.Errorf("%w: a different scoped sync apply holds this plan's event", store.ErrIdempotencyConflict)
	}
	return applied, nil
}
