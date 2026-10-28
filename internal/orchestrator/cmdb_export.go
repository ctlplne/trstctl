// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/cmdbexport"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// RequestCMDBCertificateExport retains one command before its same-transaction
// outbox intent. Reconciliation heals an append whose SQL transaction failed.
func (o *Orchestrator) RequestCMDBCertificateExport(ctx context.Context, tenantID string, command cmdbexport.Command) error {
	if err := command.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(command)
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		event, found, err := o.log.EventByID(ctx, command.ID)
		if err != nil {
			return err
		}
		if !found {
			event, err = o.log.Append(ctx, events.Event{ID: command.ID, TenantID: tenantID, Type: cmdbexport.EventRequested, Data: payload})
			if err != nil {
				return err
			}
		}
		if event.Type != cmdbexport.EventRequested || event.TenantID != tenantID || !bytes.Equal(event.Data, payload) {
			return fmt.Errorf("%w: certificate export command changed", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, event); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, cmdbCertificateExportEntry(tenantID, command, payload))
		return err
	})
}

func cmdbCertificateExportEntry(tenantID string, command cmdbexport.Command, payload []byte) Entry {
	return Entry{TenantID: tenantID, Destination: cmdbexport.Destination, IdempotencyKey: command.ID, Payload: payload,
		EffectLane: cmdbexport.Destination + ":" + command.BindingID + ":" + command.Fingerprint, RequiredAgentRole: "control_plane"}
}

func (o *Orchestrator) reconcileCMDBCertificateExport(ctx context.Context, event events.Event) (bool, error) {
	var command cmdbexport.Command
	if err := json.Unmarshal(event.Data, &command); err != nil {
		return false, err
	}
	if err := command.Validate(); err != nil {
		return false, err
	}
	if command.ID != event.ID || event.SchemaVersion != 1 {
		return false, fmt.Errorf("certificate export source binding differs")
	}
	var inserted bool
	err := o.store.WithTenant(ctx, event.TenantID, func(tx pgx.Tx) error {
		var err error
		inserted, err = o.outbox.EnqueueIfAbsent(ctx, tx, cmdbCertificateExportEntry(event.TenantID, command, event.Data))
		return err
	})
	return inserted, err
}
