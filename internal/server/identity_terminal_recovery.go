// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// reconcilePendingIdentityTerminals publishes the first retained command, or
// applies its exact event after a lost SQL commit. It never invents a second
// terminal decision. Outbox reconciliation derives side effects from that event.
func reconcilePendingIdentityTerminals(ctx context.Context, st *store.Store, log *events.Log) (int, error) {
	if st == nil || log == nil {
		return 0, fmt.Errorf("server: identity terminal recovery needs store and event log")
	}
	healed := 0
	var afterTenant, afterIdentity string
	for {
		keys, err := st.PendingIdentityTerminalKeysSystem(ctx, afterTenant, afterIdentity, 100)
		if err != nil {
			return healed, err
		}
		if len(keys) == 0 {
			return healed, nil
		}
		for _, key := range keys {
			err := st.WithPrivacyRecoveryBarrier(ctx, key[0], "identity terminal command recovery", func(barrierCtx context.Context) error {
				command, err := st.IdentityTerminalCommandByIdentity(barrierCtx, key[0], key[1])
				if err != nil {
					return err
				}
				if command.Status != "pending" {
					return nil
				}
				retained, found, err := log.EventByID(barrierCtx, command.Event.ID)
				if err != nil {
					return err
				}
				if !found {
					retained, err = log.Append(barrierCtx, command.Event)
					if err != nil {
						return err
					}
				}
				if retained.ID != command.Event.ID || retained.TenantID != command.Event.TenantID ||
					retained.Type != command.Event.Type || retained.SchemaVersion != command.Event.SchemaVersion ||
					!retained.Time.Equal(command.Event.Time) || !bytes.Equal(retained.Data, command.Event.Data) {
					return fmt.Errorf("server: terminal identity %s event differs from first command", key[1])
				}
				return projections.New(st).Apply(barrierCtx, retained)
			})
			if err != nil {
				return healed, fmt.Errorf("server: recover terminal identity %s: %w", key[1], err)
			}
			healed++
		}
		last := keys[len(keys)-1]
		afterTenant, afterIdentity = last[0], last[1]
	}
}
