// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// reconcileAPITokenRevocation finishes one independently committed denial
// command. Only a freshly claimed command can append without consulting the
// durable event-ID index. Every retry first checks retained history, since
// JetStream's duplicate-ID memory is finite.
func (o *Orchestrator) reconcileAPITokenRevocation(ctx context.Context, command store.APITokenRevocationCommand, newlyClaimed bool) error {
	if command.Status == "completed" {
		return nil
	}
	fenced, release, err := o.beginTenantCommand(ctx, command.TenantID)
	if err != nil {
		return err
	}
	defer release()
	return o.store.WithPrivacyRecoveryBarrier(fenced, command.TenantID,
		"API-token revocation recovery privacy barrier", func(barrierCtx context.Context) error {
			return o.store.WithTenant(barrierCtx, command.TenantID, func(tx pgx.Tx) error {
				current, err := o.store.LockAPITokenRevocationCommandTx(barrierCtx, tx, command.TenantID, command.TokenID)
				if err != nil {
					return err
				}
				if current.Status == "completed" {
					return nil
				}
				if current.Event.ID != command.Event.ID || !bytes.Equal(current.Event.Data, command.Event.Data) ||
					!reflect.DeepEqual(current.Event.Actor, command.Event.Actor) {
					return errors.New("orchestrator: API-token revocation command changed during recovery")
				}
				var retained events.Event
				var found bool
				if !newlyClaimed {
					retained, found, err = o.log.EventByID(barrierCtx, current.Event.ID)
					if err != nil {
						return fmt.Errorf("orchestrator: resolve API-token revocation source: %w", err)
					}
				}
				if found {
					if retained.TenantID != current.Event.TenantID || retained.Type != current.Event.Type ||
						retained.SchemaVersion != current.Event.SchemaVersion ||
						!retained.Time.Equal(current.Event.Time) ||
						!bytes.Equal(retained.Data, current.Event.Data) ||
						!reflect.DeepEqual(retained.Actor, current.Event.Actor) {
						return errors.New("orchestrator: retained API-token revocation conflicts with first command")
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

// ReconcilePendingAPITokenRevocations runs after startup catch-up and on the
// bounded recovery cadence. No bearer request depends on this worker; the
// PostgreSQL fence alone denies admission while a command is pending.
func (o *Orchestrator) ReconcilePendingAPITokenRevocations(ctx context.Context) (int, error) {
	tenants, err := o.store.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	healed := 0
	for _, tenant := range tenants {
		for {
			pending, err := o.store.ListPendingAPITokenRevocations(ctx, tenant.TenantID, 100)
			if err != nil {
				return healed, err
			}
			if len(pending) == 0 {
				break
			}
			for _, command := range pending {
				if err := o.reconcileAPITokenRevocation(ctx, command, false); err != nil {
					return healed, fmt.Errorf("orchestrator: reconcile API-token revocation %s: %w", command.Event.ID, err)
				}
				healed++
			}
		}
	}
	return healed, nil
}
