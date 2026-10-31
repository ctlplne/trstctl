// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// This window bounds startup only; it changes neither the receiver's 25s delivery
// timeout/30s lease nor the health probe's 1s budget. Unexplained missing keys do
// not enter the loop. All effects still require the original committed command.
const eventKeyStartupRecoveryWindow = 45 * time.Second

func (r *eventProtectionRuntime) pendingDestruction(ctx context.Context, log *events.Log) (bool, error) {
	if r == nil || r.custody == nil {
		return false, nil
	}
	var pending bool
	err := log.WithHistoryRead(ctx, func(read context.Context) error {
		if err := log.RequireNoPendingBackupRestore(read); err != nil {
			return err
		}
		head, err := log.LastSequence(read)
		if err != nil {
			return err
		}
		return log.ReplayTypesThrough(read, 1, head, []string{eventprivacy.EventActivated}, func(event events.Event) error {
			activation, err := eventprivacy.ParseActivated(event)
			if err != nil {
				return err
			}
			request, found, err := r.custody.PendingDestruction(read, activation.Creation)
			if err != nil {
				return err
			}
			if !found {
				return nil
			}
			life, found, err := r.policy.LifetimeForKey(read, request.Ref)
			if err != nil {
				return err
			}
			if !found {
				return eventprivacy.ErrSource
			}
			expected, err := eventprivacy.NewDestructionRequest(life)
			if err != nil {
				return err
			}
			want, err := json.Marshal(expected)
			if err != nil {
				return err
			}
			got, err := json.Marshal(request)
			if err != nil || !bytes.Equal(want, got) {
				return eventprivacy.ErrSource
			}
			pending = true
			return nil
		})
	})
	return pending, err
}

func (r *eventProtectionRuntime) recoverPendingDestruction(ctx context.Context, st *store.Store, log *events.Log) error {
	if r == nil || r.custody == nil {
		return nil
	}
	recovery, cancel := context.WithTimeout(ctx, eventKeyStartupRecoveryWindow)
	defer cancel()
	pending, err := r.pendingDestruction(recovery, log)
	if err != nil {
		return err
	}
	if !pending {
		return nil
	}
	box := orchestrator.NewOutbox(st, orchestrator.WithTenantServiceCheck(st.RequireEventKeyDestructionService))
	projector := projections.New(st, r.projectionOptions()...)
	orch := orchestrator.NewOrchestrator(log, st, box, orchestrator.WithProjector(projector), orchestrator.WithEventProtectionDestructionAuthority(r.authority))
	handler, err := newEventKeyDestructionHandler(r, st, orch.RecordEventProtectionControl)
	if err != nil {
		return err
	}
	scope := orchestrator.DestinationScope{IncludeDestinations: []string{store.EventKeyDestructionDestination}}
	for {
		// The pending-restore decision and this delivery share a finite history
		// read. Restore cannot bind a partial generation during a recovery effect.
		err = log.WithHistoryRead(recovery, func(read context.Context) error {
			if err := log.RequireNoPendingBackupRestore(read); err != nil {
				return err
			}
			_, err := box.DispatchScoped(read, handler, scope)
			return err
		})
		if err != nil {
			return err
		}
		pending, err = r.pendingDestruction(recovery, log)
		if err != nil {
			return err
		}
		if !pending {
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-recovery.Done():
			timer.Stop()
			return fmt.Errorf("server: original event key destruction intent did not complete before startup deadline: %w", recovery.Err())
		case <-timer.C:
		}
	}
}
