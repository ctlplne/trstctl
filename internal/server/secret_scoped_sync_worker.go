// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A237: a scoped sync's managed key whose source is gone is deleted at the
// destination only through this outbox command, queued by the reviewed plan's
// apply. A delete of an absent key succeeds, so a retry after the remote
// delete (a crash before the settle event) is safe.

var scopedSyncEventNamespace = googleuuid.MustParse("d98c96a4-b0ce-58d4-9771-9c85e2aca8e0")

func scopedSyncEventID(tenantID, tenantEpoch, purpose, deleteID string) string {
	return "scoped-sync-event-" + googleuuid.NewSHA1(scopedSyncEventNamespace,
		[]byte(tenantID+"\x00"+tenantEpoch+"\x00"+purpose+"\x00"+deleteID)).String()
}

type scopedSyncDeleteCommand struct {
	TenantEpoch string `json:"tenant_epoch"`
	ID          string `json:"id"`
}

func (d *secretIntegrationOutboxDispatcher) scopedSyncDelete(ctx context.Context, m orchestrator.Message) (scopedSyncDeleteCommand, store.SecretScopedSyncDelete, error) {
	var cmd scopedSyncDeleteCommand
	if err := json.Unmarshal(m.Payload, &cmd); err != nil || cmd.TenantEpoch == "" || cmd.ID == "" {
		return cmd, store.SecretScopedSyncDelete{}, orchestrator.DefiniteNoEffect(errors.New("server: scoped sync delete payload is invalid"))
	}
	if d.store == nil {
		return cmd, store.SecretScopedSyncDelete{}, errors.New("server: scoped sync delete requires the store")
	}
	rec, err := d.store.GetSecretScopedSyncDelete(ctx, m.TenantID, cmd.ID)
	if err != nil {
		return cmd, rec, err
	}
	if m.IdempotencyKey != store.SecretScopedSyncDeleteOutboxKey(cmd.TenantEpoch, cmd.ID) || rec.TenantEpoch != cmd.TenantEpoch ||
		(rec.OutboxID != 0 && rec.OutboxID != m.ID) {
		return cmd, rec, orchestrator.DefiniteNoEffect(errors.New("server: scoped sync delete does not match its projected command"))
	}
	return cmd, rec, nil
}

func (d *secretIntegrationOutboxDispatcher) deleteScopedSyncKey(ctx context.Context, m orchestrator.Message) error {
	cmd, rec, err := d.scopedSyncDelete(ctx, m)
	if err != nil {
		return err
	}
	if rec.State != store.SecretScopedSyncDeleteQueued {
		return nil // settled; a replayed outbox row is cleanup only
	}
	target := d.secretSyncTarget(m.TenantID, rec.Target)
	if target == nil {
		return errors.New("server: the scoped sync's target is not configured")
	}
	scoped, ok := target.Scoped()
	if !ok {
		return errors.New("server: the scoped sync's target does not support deletes")
	}
	if err := scoped.Delete(ctx, rec.RemoteKey); err != nil {
		return err
	}
	return d.appendScopedSyncEvent(ctx, scopedSyncEventID(m.TenantID, cmd.TenantEpoch, "key-deleted", cmd.ID), m.TenantID,
		projections.EventSecretScopedSyncKeyDeleted, projections.SecretScopedSyncKeyDeleted{TenantEpoch: cmd.TenantEpoch, DeleteID: cmd.ID})
}

func (d *secretIntegrationOutboxDispatcher) failScopedSyncDelete(ctx context.Context, m orchestrator.Message, reason string) error {
	cmd, rec, err := d.scopedSyncDelete(ctx, m)
	if err != nil {
		return err
	}
	if rec.State != store.SecretScopedSyncDeleteQueued {
		return nil
	}
	return d.appendScopedSyncEvent(ctx, scopedSyncEventID(m.TenantID, cmd.TenantEpoch, "delete-failed", cmd.ID), m.TenantID,
		projections.EventSecretScopedSyncDeleteFailed,
		projections.SecretScopedSyncDeleteFailed{TenantEpoch: cmd.TenantEpoch, DeleteID: cmd.ID, Error: reason})
}

// appendScopedSyncEvent appends one settle event under its stable ID (schema
// v1) and projects it; a retry finds the same event and projects it again.
func (d *secretIntegrationOutboxDispatcher) appendScopedSyncEvent(ctx context.Context, eventID, tenantID, eventType string, payload any) error {
	if d.store == nil || d.log == nil {
		return errors.New("server: scoped sync delete evidence requires store and event log")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	candidate := events.Event{ID: eventID, Type: eventType, TenantID: tenantID, SchemaVersion: 1, Data: data}
	canonical, found, err := d.log.EventByID(ctx, eventID)
	if err != nil {
		return err
	}
	if !found {
		if canonical, err = d.log.Append(ctx, candidate); err != nil {
			return err
		}
	}
	if canonical.Type != eventType || canonical.TenantID != tenantID || !bytes.Equal(canonical.Data, data) {
		return fmt.Errorf("%w: canonical scoped sync event differs", store.ErrIdempotencyConflict)
	}
	return projections.New(d.store).Apply(ctx, canonical)
}
