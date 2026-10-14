// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func (h *caHierarchyService) CancelCeremony(ctx context.Context, tenantID, id, reason string) (api.CAKeyCeremony, error) {
	actor, ok := events.ActorFromContext(ctx)
	if !ok || strings.TrimSpace(actor.Subject) == "" {
		return api.CAKeyCeremony{}, api.ErrCAHierarchyConflict
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 512 {
		return api.CAKeyCeremony{}, api.ErrCAHierarchyInvalid
	}
	payload, err := json.Marshal(projections.CACeremonyCancelled{CeremonyID: id, Actor: actor.Subject, Reason: reason})
	if err != nil {
		return api.CAKeyCeremony{}, err
	}
	command, created, err := h.store.ClaimCACeremonyCancelCommand(ctx, store.CACeremonyCancelCommand{
		TenantID: tenantID, CeremonyID: id,
		Event: events.Event{ID: uuid.NewString(), Time: time.Now().UTC().Truncate(time.Microsecond),
			TenantID: tenantID, Type: projections.EventCACeremonyCancelled,
			SchemaVersion: events.DefaultSchemaVersion, Data: payload, Actor: &actor},
	})
	if err != nil {
		return api.CAKeyCeremony{}, caHierarchyConflict(err)
	}
	// Work continues after a caller disconnects: authority was already removed
	// when the first-writer claim committed.
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := reconcileCACeremonyCancel(readCtx, h.store, h.log, command, created); err != nil {
		return api.CAKeyCeremony{}, fmt.Errorf("%w: ceremony cancellation command %s unresolved: %v", orchestrator.ErrEffectIndeterminate, command.Event.ID, err)
	}
	closed, err := h.store.GetKeyCeremony(readCtx, tenantID, id)
	if err != nil || closed.Status != "cancelled" || closed.ClosedBy != actor.Subject || closed.CloseReason != reason {
		return api.CAKeyCeremony{}, fmt.Errorf("%w: ceremony cancellation command %s lacks exact terminal readback: %v", orchestrator.ErrEffectIndeterminate, command.Event.ID, err)
	}
	return ceremonyResponse(closed), nil
}

func reconcileCACeremonyCancel(ctx context.Context, s *store.Store, log *events.Log, command store.CACeremonyCancelCommand, newlyClaimed bool) error {
	return s.WithPrivacyRecoveryBarrier(ctx, command.TenantID, "CA ceremony cancellation recovery", func(barrierCtx context.Context) error {
		return s.WithTenant(barrierCtx, command.TenantID, func(tx pgx.Tx) error {
			current, err := s.LockCACeremonyCancelCommandTx(barrierCtx, tx, command.TenantID, command.CeremonyID)
			if err != nil {
				return err
			}
			if current.Status == "completed" {
				return nil
			}
			if current.Event.ID != command.Event.ID || !bytes.Equal(current.Event.Data, command.Event.Data) ||
				!reflect.DeepEqual(current.Event.Actor, command.Event.Actor) {
				return errors.New("server: CA ceremony cancellation command changed during recovery")
			}
			var retained events.Event
			var found bool
			if !newlyClaimed {
				retained, found, err = log.EventByID(barrierCtx, current.Event.ID)
				if err != nil {
					return err
				}
			}
			if found {
				if retained.TenantID != current.Event.TenantID || retained.Type != current.Event.Type ||
					retained.SchemaVersion != current.Event.SchemaVersion || !retained.Time.Equal(current.Event.Time) ||
					!bytes.Equal(retained.Data, current.Event.Data) || !reflect.DeepEqual(retained.Actor, current.Event.Actor) {
					return errors.New("server: retained CA ceremony cancellation conflicts with first command")
				}
			} else {
				retained, err = log.Append(barrierCtx, current.Event)
				if err != nil {
					return err
				}
			}
			return projections.New(s).ApplyTx(barrierCtx, tx, retained)
		})
	})
}

func reconcilePendingCACeremonyCancels(ctx context.Context, s *store.Store, log *events.Log) (int, error) {
	tenants, err := s.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	healed := 0
	for _, tenant := range tenants {
		for {
			pending, err := s.ListPendingCACeremonyCancels(ctx, tenant.TenantID, 100)
			if err != nil {
				return healed, err
			}
			if len(pending) == 0 {
				break
			}
			for _, command := range pending {
				if err := reconcileCACeremonyCancel(ctx, s, log, command, false); err != nil {
					return healed, err
				}
				healed++
			}
		}
	}
	return healed, nil
}
