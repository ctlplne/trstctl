// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"fmt"
	"reflect"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// reconcilePendingWorkloadAttesterTrustCommands uses the indexed SQL command
// inventory, then re-enters each customer's RLS scope for the retained event.
// A missing broker ACK never releases the denial or mints a replacement event.
func reconcilePendingWorkloadAttesterTrustCommands(ctx context.Context, st *store.Store, log *events.Log) (int, error) {
	if st == nil || log == nil {
		return 0, fmt.Errorf("server: attester trust recovery needs store and event log")
	}
	healed := 0
	var afterTenant, afterSource string
	for {
		keys, err := st.PendingWorkloadAttesterTrustKeysSystem(ctx, afterTenant, afterSource, 100)
		if err != nil {
			return healed, err
		}
		if len(keys) == 0 {
			return healed, nil
		}
		for _, key := range keys {
			err := st.WithPrivacyRecoveryBarrier(ctx, key[0], "attester trust command recovery", func(barrierCtx context.Context) error {
				command, err := st.WorkloadAttesterTrustCommand(barrierCtx, key[0], key[1])
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
					!retained.Time.Equal(command.Event.Time) ||
					!bytes.Equal(retained.Data, command.Event.Data) ||
					!reflect.DeepEqual(retained.Actor, command.Event.Actor) {
					return fmt.Errorf("server: attester trust source %s differs from first command", key[1])
				}
				return projections.New(st).Apply(barrierCtx, retained)
			})
			if err != nil {
				return healed, fmt.Errorf("server: recover attester trust source %s: %w", key[1], err)
			}
			healed++
		}
		last := keys[len(keys)-1]
		afterTenant, afterSource = last[0], last[1]
	}
}
