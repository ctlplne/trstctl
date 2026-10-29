// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"context"
	"encoding/json"
	"time"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// PreparationClaim names the exact durable receiver invocation, not a caller's
// HTTP retry key. SQL verification must reject missing/stale/foreign tokens.
type PreparationClaim = store.EventKeyPreparationClaim

type PreparationClaims interface {
	WithEventKeyPreparationClaim(context.Context, PreparationClaim, func(context.Context) error) error
}

type PreparationCustody interface {
	WithCustodyFence(context.Context, eventprotect.KeyRef, func(context.Context) error) error
	Provision(context.Context, eventprotect.KeyRef) error
	CreationEvidence(context.Context, eventprotect.KeyRef) (eventprotect.KeyCreationEvidence, error)
}

type PreparationReceiver struct {
	Policy  SourcePolicy
	Claims  PreparationClaims
	Guard   TenantGuard
	Custody PreparationCustody
	// Record must append then project the exact supplied event. It must preserve
	// source identity/time and explicitly clear inherited human attribution while
	// retaining the service grant in ctx. Invoke it AFTER the preparation history
	// and custody callbacks end: emitPrepared takes the SQL/backup fence before
	// Append takes history/custody. Admission rechecks source and creation evidence
	// under its own tenant guard before publishing the public activation.
	Record func(context.Context, events.Event) (events.Event, error)
}

func PreparationCommand(source RequestSource) store.EventKeyPreparationCommand {
	return store.EventKeyPreparationCommand{
		Ref:                  eventprotect.KeyRef{TenantID: source.Meta.TenantID, ID: source.Body.KeyID},
		RegistrationIdentity: source.Body.RegistrationIdentity,
		RequestedEventID:     source.Meta.ID, RequestedSequence: source.Meta.Sequence,
		RequestedAt: source.Meta.Time, RetentionNanos: source.Body.RetentionNanos,
	}
}

func samePreparationCommand(a, b store.EventKeyPreparationCommand) bool {
	if !a.RequestedAt.Equal(b.RequestedAt) {
		return false
	}
	a.RequestedAt, b.RequestedAt = time.Time{}, time.Time{}
	return a == b
}

func (receiver PreparationReceiver) Prepare(ctx context.Context, claim PreparationClaim) error {
	if receiver.Claims == nil || receiver.Guard == nil || receiver.Custody == nil || receiver.Record == nil || receiver.Policy.Log == nil || claim.Command.Validate() != nil {
		return ErrSource
	}
	return receiver.Claims.WithEventKeyPreparationClaim(ctx, claim, func(serviceCtx context.Context) error {
		var prepared events.Event
		err := receiver.Policy.Log.WithHistoryRead(serviceCtx, func(readCtx context.Context) error {
			return receiver.Guard.WithTenantEventProtection(readCtx, claim.Command.Ref.TenantID, func(guardCtx context.Context) error {
				return receiver.Custody.WithCustodyFence(guardCtx, claim.Command.Ref, func(fenced context.Context) error {
					var err error
					prepared, err = receiver.prepareUnderCustody(fenced, claim.Command)
					return err
				})
			})
		})
		if err != nil {
			return err
		}
		_, err = receiver.Record(serviceCtx, prepared)
		return err
	})
}

// Re-read source AFTER acquiring independent custody: a database session may
// have disappeared while this operation waited behind an older file callback.
func (receiver PreparationReceiver) prepareUnderCustody(ctx context.Context, command store.EventKeyPreparationCommand) (events.Event, error) {
	lifetime, err := receiver.Policy.LatestLifetime(ctx, command.Ref.TenantID)
	if err != nil {
		return events.Event{}, err
	}
	if lifetime.Request == nil || lifetime.Offboard != nil || !samePreparationCommand(PreparationCommand(*lifetime.Request), command) {
		return events.Event{}, ErrSource
	}
	if lifetime.Activation == nil {
		if err := receiver.Custody.Provision(ctx, command.Ref); err != nil {
			return events.Event{}, err
		}
	}
	creation, err := receiver.Custody.CreationEvidence(ctx, command.Ref)
	if err != nil {
		return events.Event{}, err
	}
	activation := Activated{RegistrationIdentity: command.RegistrationIdentity, OperationID: command.Ref.ID, KeyID: command.Ref.ID, RetentionNanos: command.RetentionNanos, RequestedEventID: command.RequestedEventID, RequestedSequence: command.RequestedSequence, RequestedAt: command.RequestedAt, Creation: creation}
	at := creation.CreatedAt
	if lifetime.Activation != nil {
		if creation.Digest() != lifetime.Activation.Body.Creation.Digest() {
			return events.Event{}, eventprotect.ErrKey
		}
		activation = lifetime.Activation.Body
		at = lifetime.Activation.Meta.Time
	}
	wire, err := json.Marshal(activation)
	if err != nil {
		return events.Event{}, err
	}
	return events.Event{ID: command.Ref.ID, Type: EventActivated, TenantID: command.Ref.TenantID, SchemaVersion: 1, Time: at, Data: wire}, nil
}
