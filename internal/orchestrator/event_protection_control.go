// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
)

func WithEventProtectionDestructionAuthority(authority *eventprivacy.DestructionAuthority) OrchestratorOption {
	return func(o *Orchestrator) { o.eventProtectionDestructionAuthority = authority }
}

// RecordEventProtectionControl uses the assembled live projector and the normal
// SQL/backup-before-history order. Activation keeps ordinary live-tenant service
// admission. A post-offboard control needs a private exact-event grant AND a
// fresh SQL check of that committed receiver invocation. Event type alone is
// never permission to write for a deleted tenant.
func (o *Orchestrator) RecordEventProtectionControl(ctx context.Context, next events.Event) (events.Event, error) {
	if o == nil || o.store == nil || o.log == nil || o.proj == nil || next.SchemaVersion != 1 || next.Actor != nil || next.Protection != nil || next.SensitiveErased {
		return events.Event{}, errors.New("orchestrator: invalid event protection control")
	}
	ctx = events.ContextWithoutActor(ctx)
	if next.Type == eventprivacy.EventActivated {
		return o.emitPrepared(ctx, next)
	}
	if (next.Type != eventprivacy.EventHoldClearance && next.Type != eventprivacy.EventDestroyed) || o.eventProtectionDestructionAuthority == nil {
		return events.Event{}, errors.New("orchestrator: event protection control has no current receiver authority")
	}
	claim, err := o.eventProtectionDestructionAuthority.ControlClaim(ctx, next)
	if err != nil {
		return events.Event{}, err
	}
	var result events.Event
	err = o.store.WithEventKeyDestructionClaim(ctx, claim, func(current context.Context) error {
		return o.store.WithTenant(current, next.TenantID, func(tx pgx.Tx) error {
			var err error
			result, err = o.log.Append(current, next)
			if err != nil {
				return err
			}
			return o.proj.ApplyTx(current, tx, result)
		})
	})
	return result, err
}
