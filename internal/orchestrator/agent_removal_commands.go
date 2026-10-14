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

// reconcileAgentRemovalCommand publishes and projects the exact first-writer
// event while the independently committed denial remains authoritative.
func (o *Orchestrator) reconcileAgentRemovalCommand(ctx context.Context, command store.AgentRemovalCommand, newlyClaimed bool) error {
	if command.Status == "completed" {
		return nil
	}
	fenced, release, err := o.beginTenantCommand(ctx, command.TenantID)
	if err != nil {
		return err
	}
	defer release()
	return o.store.WithPrivacyRecoveryBarrier(fenced, command.TenantID,
		"agent removal recovery privacy barrier", func(barrierCtx context.Context) error {
			return o.store.WithTenant(barrierCtx, command.TenantID, func(tx pgx.Tx) error {
				current, err := o.store.LockAgentRemovalCommandTx(barrierCtx, tx, command.TenantID, command.Event.ID)
				if err != nil {
					return err
				}
				if current.Status == "completed" {
					return nil
				}
				if current.AgentID != command.AgentID || current.Kind != command.Kind ||
					current.Serial != command.Serial || current.Fingerprint != command.Fingerprint ||
					!current.Event.Time.Equal(command.Event.Time) ||
					!bytes.Equal(current.Event.Data, command.Event.Data) ||
					!reflect.DeepEqual(current.Event.Actor, command.Event.Actor) {
					return errors.New("orchestrator: agent removal command changed during recovery")
				}
				var retained events.Event
				var found bool
				if !newlyClaimed {
					retained, found, err = o.log.EventByID(barrierCtx, current.Event.ID)
					if err != nil {
						return fmt.Errorf("orchestrator: resolve agent removal source: %w", err)
					}
				}
				if found {
					if retained.TenantID != current.Event.TenantID || retained.Type != current.Event.Type ||
						retained.SchemaVersion != current.Event.SchemaVersion ||
						!retained.Time.Equal(current.Event.Time) ||
						!bytes.Equal(retained.Data, current.Event.Data) ||
						!reflect.DeepEqual(retained.Actor, current.Event.Actor) {
						return errors.New("orchestrator: retained agent removal event conflicts with first command")
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

// ReconcilePendingAgentRemovals is bounded per tenant and safe after a crash or
// lost response. Admission never waits for this worker: its command row denies.
func (o *Orchestrator) ReconcilePendingAgentRemovals(ctx context.Context) (int, error) {
	tenants, err := o.store.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	healed := 0
	for _, tenant := range tenants {
		for {
			pending, err := o.store.ListPendingAgentRemovals(ctx, tenant.TenantID, 100)
			if err != nil {
				return healed, err
			}
			if len(pending) == 0 {
				break
			}
			for _, command := range pending {
				if err := o.reconcileAgentRemovalCommand(ctx, command, false); err != nil {
					return healed, fmt.Errorf("orchestrator: reconcile agent removal %s: %w", command.Event.ID, err)
				}
				healed++
			}
		}
	}
	return healed, nil
}
