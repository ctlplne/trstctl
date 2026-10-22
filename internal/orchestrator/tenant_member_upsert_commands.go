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

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// reconcileTenantMemberUpsertCommand publishes and projects the exact first
// event while the cookie-role fence stays committed. A newer offboard claim
// supersedes an upsert that never reached the immutable log.
func (o *Orchestrator) reconcileTenantMemberUpsertCommand(ctx context.Context, command store.TenantMemberUpsertCommand) error {
	if command.Status == "completed" {
		return nil
	}
	if command.Status == "superseded" {
		return store.ErrTenantMemberOffboarded
	}
	var payload projections.TenantMemberUpserted
	if err := json.Unmarshal(command.Event.Data, &payload); err != nil {
		return err
	}
	if payload.Subject == "" {
		return errors.New("orchestrator: member upsert command has no subject")
	}
	fenced, release, err := o.beginTenantCommand(ctx, command.TenantID)
	if err != nil {
		return err
	}
	defer release()
	superseded := false
	err = o.store.WithPrivacyRecoveryBarrier(fenced, command.TenantID,
		"member upsert recovery privacy barrier", func(barrierCtx context.Context) error {
			return o.store.WithTenant(barrierCtx, command.TenantID, func(tx pgx.Tx) error {
				if err := o.store.LockTenantMemberSubjectRefTx(barrierCtx, tx, command.TenantID, command.SubjectRef); err != nil {
					return err
				}
				current, err := o.store.LockTenantMemberUpsertCommandTx(barrierCtx, tx, command.TenantID, command.SubjectRef)
				if err != nil {
					return err
				}
				if current.Status == "completed" {
					return nil
				}
				if current.Status == "superseded" {
					return store.ErrTenantMemberOffboarded
				}
				if current.Event.ID != command.Event.ID || !current.Event.Time.Equal(command.Event.Time) ||
					!bytes.Equal(current.Event.Data, command.Event.Data) ||
					!reflect.DeepEqual(current.Event.Actor, command.Event.Actor) {
					return errors.New("orchestrator: member upsert command changed during recovery")
				}
				retained, found, err := o.log.EventByID(barrierCtx, current.Event.ID)
				if err != nil {
					return fmt.Errorf("orchestrator: resolve member upsert source: %w", err)
				}
				privacyChanged, erasureSequence, err := o.store.MemberUpsertPrivacyGenerationTx(barrierCtx, tx, current)
				if err != nil {
					return err
				}
				if found {
					if retained.TenantID != current.Event.TenantID || retained.Type != current.Event.Type ||
						retained.SchemaVersion != current.Event.SchemaVersion ||
						!retained.Time.Equal(current.Event.Time) || !bytes.Equal(retained.Data, current.Event.Data) ||
						!reflect.DeepEqual(retained.Actor, current.Event.Actor) {
						return errors.New("orchestrator: retained member upsert event conflicts with first command")
					}
					if erasureSequence > 0 {
						if retained.Sequence == 0 || retained.Sequence > 1<<63-1 {
							return errors.New("orchestrator: member upsert has invalid source sequence")
						}
						if int64(retained.Sequence) <= erasureSequence {
							if !privacyChanged || int64(retained.Sequence) == erasureSequence {
								return errors.New("orchestrator: member upsert source conflicts with privacy erasure order")
							}
							return o.store.CompleteTenantMemberUpsertCommandTx(barrierCtx, tx,
								current.TenantID, payload.Subject, retained)
						}
						if privacyChanged {
							return errors.New("orchestrator: pre-erasure member upsert source appeared after erasure")
						}
					}
				} else {
					if privacyChanged {
						if err := o.store.SupersedeTenantMemberUpsertCommandTx(barrierCtx, tx, current); err != nil {
							return err
						}
						superseded = true
						return nil
					}
					changed, err := o.store.MemberUpsertOffboardChangedTx(barrierCtx, tx, current)
					if err != nil {
						return err
					}
					if changed {
						if err := o.store.SupersedeTenantMemberUpsertCommandTx(barrierCtx, tx, current); err != nil {
							return err
						}
						superseded = true
						return nil
					}
					retained, err = o.log.Append(barrierCtx, current.Event)
					if err != nil {
						return err
					}
				}
				// A73: the row is read before the projection applies, so it
				// still says whether the directory owns this member.
				if err := o.enqueueSCIMWritebackTx(barrierCtx, tx, retained, payload.Subject, "upsert"); err != nil {
					return err
				}
				if err := o.enqueueLDAPWritebackTx(barrierCtx, tx, retained, payload.Subject, "upsert"); err != nil {
					return err
				}
				return o.proj.ApplyTx(barrierCtx, tx, retained)
			})
		})
	if err != nil {
		return err
	}
	if superseded {
		return store.ErrTenantMemberOffboarded
	}
	return nil
}

// ReconcilePendingTenantMemberUpserts is bounded per tenant and replays the
// exact pending commands after a crash, a lost response or a projection outage.
func (o *Orchestrator) ReconcilePendingTenantMemberUpserts(ctx context.Context) (int, error) {
	tenants, err := o.store.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	healed := 0
	for _, tenant := range tenants {
		for {
			pending, err := o.store.ListPendingTenantMemberUpsertCommands(ctx, tenant.TenantID, 100)
			if err != nil {
				return healed, err
			}
			if len(pending) == 0 {
				break
			}
			for _, command := range pending {
				if err := o.reconcileTenantMemberUpsertCommand(ctx, command); err != nil && !errors.Is(err, store.ErrTenantMemberOffboarded) {
					return healed, fmt.Errorf("orchestrator: reconcile member upsert %s: %w", command.Event.ID, err)
				}
				healed++
			}
		}
	}
	return healed, nil
}
