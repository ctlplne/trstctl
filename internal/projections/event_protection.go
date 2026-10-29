// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

const (
	EventTenantEventProtectionRequested = eventprivacy.EventRequested
	EventTenantEventProtectionActivated = eventprivacy.EventActivated
	EventTenantEventProtectionDestroyed = eventprivacy.EventDestroyed
)

type TenantEventProtectionRequested = eventprivacy.Requested
type TenantEventProtectionActivated = eventprivacy.Activated
type TenantEventProtectionDestroyed = eventprivacy.Destroyed

type EventProtectionActivationVerifier interface {
	WithVerifiedActivation(context.Context, events.Event, func(context.Context, store.EventKeyPreparationCommand) error) error
}

func WithEventProtectionActivationVerifier(verifier EventProtectionActivationVerifier) Option {
	return func(projector *Projector) { projector.eventProtectionActivationVerifier = verifier }
}

func (p *Projector) applyEventProtectionTx(ctx context.Context, tx pgx.Tx, event events.Event) (bool, error) {
	switch event.Type {
	case EventTenantEventProtectionRequested:
		request, err := eventprivacy.ParseRequested(event.TenantID, event.Data)
		if err != nil || event.ID != eventprivacy.RequestedEventID(request) || event.Sequence == 0 {
			return true, eventprivacy.ErrSource
		}
		tenant, err := uuid.Parse(event.TenantID)
		if err != nil || tenant == uuid.Nil {
			return true, eventprivacy.ErrSource
		}
		return true, p.store.EnsureEventKeyPreparationTx(ctx, tx, eventprivacy.PreparationCommand(eventprivacy.RequestSource{
			Meta: events.EnvelopeMetadata{ID: event.ID, Type: event.Type, TenantID: tenant.String(), Time: event.Time, SchemaVersion: event.SchemaVersion, Sequence: event.Sequence},
			Body: request,
		}))
	case EventTenantEventProtectionActivated:
		_, err := eventprivacy.ParseActivated(event)
		if err != nil || p.eventProtectionActivationVerifier == nil {
			return true, err
		}
		return true, p.eventProtectionActivationVerifier.WithVerifiedActivation(ctx, event, func(verified context.Context, command store.EventKeyPreparationCommand) error {
			return p.store.SettleEventKeyPreparationTx(verified, tx, command)
		})
	case EventTenantEventProtectionDestroyed:
		// Syntax is not destruction authority. No SQL completion/effect is derived
		// here: the current-custody reconciler must verify the exact pinned signed
		// receipt before deleting a pending intent or skipping an erased lifetime.
		_, err := eventprivacy.ParseDestroyed(event)
		return true, err
	}
	return false, nil
}
