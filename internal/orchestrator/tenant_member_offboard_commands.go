// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// reconcileTenantMemberOffboardCommand publishes the exact first event and
// projects it while the independently committed denial remains in force.
func (o *Orchestrator) reconcileTenantMemberOffboardCommand(ctx context.Context, command store.TenantMemberOffboardCommand, newlyClaimed bool) error {
	if command.Status == "completed" {
		return nil
	}
	var payload projections.TenantMemberOffboarded
	if err := json.Unmarshal(command.Event.Data, &payload); err != nil {
		return err
	}
	if payload.Subject == "" {
		return errors.New("orchestrator: member offboard command has no subject")
	}
	fenced, release, err := o.beginTenantCommand(ctx, command.TenantID)
	if err != nil {
		return err
	}
	defer release()
	return o.store.WithPrivacyRecoveryBarrier(fenced, command.TenantID,
		"member offboard recovery privacy barrier", func(barrierCtx context.Context) error {
			return o.store.WithTenant(barrierCtx, command.TenantID, func(tx pgx.Tx) error {
				if err := o.store.LockTenantMemberSubjectRefTx(barrierCtx, tx, command.TenantID, command.SubjectRef); err != nil {
					return err
				}
				current, err := o.store.LockTenantMemberOffboardCommandTx(barrierCtx, tx, command.TenantID, command.SubjectRef)
				if err != nil {
					return err
				}
				if current.Status == "completed" {
					return nil
				}
				if current.Event.ID != command.Event.ID || !current.Event.Time.Equal(command.Event.Time) ||
					!bytes.Equal(current.Event.Data, command.Event.Data) ||
					!reflect.DeepEqual(current.Event.Actor, command.Event.Actor) {
					return errors.New("orchestrator: member offboard command changed during recovery")
				}
				var retained events.Event
				var found bool
				if !newlyClaimed {
					retained, found, err = o.log.EventByID(barrierCtx, current.Event.ID)
					if err != nil {
						return fmt.Errorf("orchestrator: resolve member offboard source: %w", err)
					}
				}
				if found {
					if retained.TenantID != current.Event.TenantID || retained.Type != current.Event.Type ||
						retained.SchemaVersion != current.Event.SchemaVersion ||
						!retained.Time.Equal(current.Event.Time) || !bytes.Equal(retained.Data, current.Event.Data) ||
						!reflect.DeepEqual(retained.Actor, current.Event.Actor) {
						return errors.New("orchestrator: retained member offboard event conflicts with first command")
					}
				} else {
					retained, err = o.log.Append(barrierCtx, current.Event)
					if err != nil {
						return err
					}
				}
				if err := o.enqueueSCIMWritebackTx(barrierCtx, tx, retained, payload.Subject, "offboard"); err != nil {
					return err
				}
				return o.proj.ApplyTx(barrierCtx, tx, retained)
			})
		})
}

// ReconcilePendingTenantMemberOffboards is bounded per tenant and safe after a
// crash, a lost response, or a projection outage.
func (o *Orchestrator) ReconcilePendingTenantMemberOffboards(ctx context.Context) (int, error) {
	tenants, err := o.store.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	healed := 0
	for _, tenant := range tenants {
		for {
			pending, err := o.store.ListPendingTenantMemberOffboardCommands(ctx, tenant.TenantID, 100)
			if err != nil {
				return healed, err
			}
			if len(pending) == 0 {
				break
			}
			for _, command := range pending {
				if err := o.reconcileTenantMemberOffboardCommand(ctx, command, false); err != nil {
					return healed, fmt.Errorf("orchestrator: reconcile member offboard %s: %w", command.Event.ID, err)
				}
				healed++
			}
		}
	}
	return healed, nil
}
