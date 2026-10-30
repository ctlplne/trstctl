// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

const (
	EventTenantEventProtectionRequested    = eventprivacy.EventRequested
	EventTenantEventProtectionActivated    = eventprivacy.EventActivated
	EventTenantEventProtectionDestroyed    = eventprivacy.EventDestroyed
	EventTenantEventProtectionHoldsCleared = eventprivacy.EventHoldClearance
)

type TenantEventProtectionRequested = eventprivacy.Requested
type TenantEventProtectionActivated = eventprivacy.Activated
type TenantEventProtectionDestroyed = eventprivacy.Destroyed
type TenantEventProtectionHoldsCleared = eventprivacy.HoldClearance

type EventProtectionCompletionVerifier interface {
	WithVerifiedCompletion(context.Context, events.Event, func(context.Context, eventprotect.DestructionRequest) error) error
}

func WithEventProtectionCompletionVerifier(v EventProtectionCompletionVerifier) Option {
	return func(p *Projector) { p.eventProtectionCompletionVerifier = v }
}

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
	case EventTenantEventProtectionHoldsCleared:
		_, err := eventprivacy.ParseHoldClearance(event)
		return true, err
	case EventTenantEventProtectionDestroyed:
		_, err := eventprivacy.ParseDestroyed(event)
		if err != nil || p.eventProtectionCompletionVerifier == nil {
			return true, err
		}
		return true, p.eventProtectionCompletionVerifier.WithVerifiedCompletion(ctx, event, func(verified context.Context, request eventprotect.DestructionRequest) error {
			return p.store.SettleEventKeyDestructionTx(verified, tx, request)
		})
	}
	return false, nil
}
