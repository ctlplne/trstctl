// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// RequestEventProtection retains a tenant's opt-in to event-field protection
// (A233). The request event's ID is derived from the tenant and its current
// registration, so a retry finds the same event; a different retention for the
// same lifetime is a conflict. Source admission refuses a stale registration
// before anything is appended. Projecting the request in the same transaction
// queues the bounded key-preparation worker; activation, not this call, makes
// the protection active.
func (o *Orchestrator) RequestEventProtection(ctx context.Context, tenantID string, request eventprivacy.Requested) error {
	expected, err := eventprivacy.NewRequested(tenantID, request.RegistrationIdentity, time.Duration(request.RetentionNanos))
	if err != nil || expected != request {
		return eventprivacy.ErrSource
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	id := eventprivacy.RequestedEventID(request)
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		event, found, err := o.log.EventByID(ctx, id)
		if err != nil {
			return err
		}
		if !found {
			event, err = o.log.Append(ctx, events.Event{ID: id, TenantID: tenantID, Type: eventprivacy.EventRequested, Data: payload})
			if err != nil {
				return err
			}
		}
		if event.Type != eventprivacy.EventRequested || event.TenantID != tenantID || !bytes.Equal(event.Data, payload) {
			return fmt.Errorf("%w: event protection was already requested with a different policy", store.ErrIdempotencyConflict)
		}
		return o.proj.ApplyTx(ctx, tx, event)
	})
}
