// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// SetMachineAuthMethodOverride commits the admission fence before publishing
// the event. A disable or pending enable denies fresh bearer minting even if
// the event publisher, projector, or API response fails.
func (o *Orchestrator) SetMachineAuthMethodOverride(ctx context.Context, tenantID, name, updatedBy string, disable bool) error {
	eventType := projections.EventMachineAuthMethodEnabled
	if disable {
		eventType = projections.EventMachineAuthMethodDisabled
	}
	payload, err := json.Marshal(projections.MachineAuthMethodOverride{Name: name, UpdatedBy: updatedBy})
	if err != nil {
		return err
	}
	var actor *events.Actor
	if a, ok := events.ActorFromContext(ctx); ok {
		actor = &a
	}
	candidate := store.MachineAuthMethodCommand{
		TenantID: tenantID, MethodName: name, TargetDisabled: disable,
		Event: events.Event{
			ID: uuid.NewString(), Type: eventType, TenantID: tenantID,
			SchemaVersion: events.DefaultSchemaVersion,
			Time:          time.Now().UTC().Truncate(time.Microsecond),
			Data:          payload, Actor: actor,
		},
	}
	canonical, created, err := o.store.ClaimMachineAuthMethodCommand(ctx, candidate)
	if err != nil {
		return err
	}
	return o.reconcileMachineAuthMethodCommand(ctx, canonical, created)
}

func (o *Orchestrator) reconcileMachineAuthMethodCommand(ctx context.Context, command store.MachineAuthMethodCommand, newlyClaimed bool) error {
	if command.Status == "completed" {
		return nil
	}
	fenced, release, err := o.beginTenantCommand(ctx, command.TenantID)
	if err != nil {
		return err
	}
	defer release()
	return o.store.WithPrivacyRecoveryBarrier(fenced, command.TenantID,
		"machine-auth command recovery privacy barrier", func(barrierCtx context.Context) error {
			return o.store.WithTenant(barrierCtx, command.TenantID, func(tx pgx.Tx) error {
				current, err := o.store.LockMachineAuthMethodCommandTx(barrierCtx, tx, command.TenantID, command.MethodName)
				if err != nil {
					return err
				}
				if current.Status == "completed" {
					return nil
				}
				if current.Event.ID != command.Event.ID || !current.Event.Time.Equal(command.Event.Time) ||
					!bytes.Equal(current.Event.Data, command.Event.Data) ||
					!reflect.DeepEqual(current.Event.Actor, command.Event.Actor) {
					return errors.New("orchestrator: machine-auth command changed during recovery")
				}
				var retained events.Event
				var found bool
				if !newlyClaimed {
					retained, found, err = o.log.EventByID(barrierCtx, current.Event.ID)
					if err != nil {
						return fmt.Errorf("orchestrator: resolve machine-auth command source: %w", err)
					}
				}
				if found {
					if retained.TenantID != current.Event.TenantID || retained.Type != current.Event.Type ||
						retained.SchemaVersion != current.Event.SchemaVersion ||
						!retained.Time.Equal(current.Event.Time) ||
						!bytes.Equal(retained.Data, current.Event.Data) ||
						!reflect.DeepEqual(retained.Actor, current.Event.Actor) {
						return errors.New("orchestrator: retained machine-auth event conflicts with first command")
					}
				} else {
					retained, err = o.log.Append(barrierCtx, current.Event)
					if err != nil {
						return err
					}
				}
				return o.proj.ApplyTx(barrierCtx, tx, retained)
			})
		})
}

// ReconcilePendingMachineAuthMethodCommands is bounded per tenant and safe to
// repeat after startup, a lost API response, or a projection outage.
func (o *Orchestrator) ReconcilePendingMachineAuthMethodCommands(ctx context.Context) (int, error) {
	tenants, err := o.store.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	healed := 0
	for _, tenant := range tenants {
		for {
			pending, err := o.store.ListPendingMachineAuthMethodCommands(ctx, tenant.TenantID, 100)
			if err != nil {
				return healed, err
			}
			if len(pending) == 0 {
				break
			}
			for _, command := range pending {
				if err := o.reconcileMachineAuthMethodCommand(ctx, command, false); err != nil {
					return healed, fmt.Errorf("orchestrator: reconcile machine-auth method %s: %w", command.Event.ID, err)
				}
				healed++
			}
		}
	}
	return healed, nil
}
