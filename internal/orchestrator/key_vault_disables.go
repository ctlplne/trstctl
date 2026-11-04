// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Key Vault disables (N2). The request is recorded and its outbox job queued
// in one tenant transaction (AN-6): the vault call happens only from the job,
// and a retried command finds the same request and the same job.

// KeyVaultDisableID is the disable a command records: the same command retried
// records the same disable.
func KeyVaultDisableID(tenantID, command string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("key-vault-disable\x00"+tenantID+"\x00"+command)).String()
}

// KeyVaultDisableJob is the outbox payload: which request, which version.
type KeyVaultDisableJob struct {
	ID            string `json:"id"`
	CertificateID string `json:"certificate_id"`
	ResourceID    string `json:"resource_id"`
	SourceID      string `json:"source_id"`
}

// QueueKeyVaultDisable records a disable request beside its outbox job.
func (o *Orchestrator) QueueKeyVaultDisable(ctx context.Context, tenantID string, req projections.KeyVaultDisableRequested) error {
	if err := projections.ValidateKeyVaultDisableRequested(req); err != nil {
		return err
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(KeyVaultDisableJob{ID: req.ID, CertificateID: req.CertificateID, ResourceID: req.ResourceID, SourceID: req.SourceID})
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		canonical, found, err := o.log.EventByID(ctx, req.ID)
		if err != nil {
			return err
		}
		if !found {
			if canonical, err = o.log.Append(ctx, events.Event{ID: req.ID, TenantID: tenantID, Type: projections.EventKeyVaultDisableRequested,
				Data: raw}); err != nil {
				return err
			}
		}
		if canonical.Type != projections.EventKeyVaultDisableRequested || canonical.TenantID != tenantID {
			return fmt.Errorf("%w: Key Vault disable source envelope changed", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, canonical); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: tenantID, Destination: store.KeyVaultDisableDestination,
			IdempotencyKey: store.KeyVaultDisableJobKey(req.ID), Payload: payload})
		return err
	})
}

// RecordKeyVaultDisabled records the vault's readback. Recording it twice
// records it once.
func (o *Orchestrator) RecordKeyVaultDisabled(ctx context.Context, tenantID string, disabled projections.KeyVaultDisabled) error {
	data, err := json.Marshal(disabled)
	if err != nil {
		return err
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("key-vault-disabled\x00"+tenantID+"\x00"+disabled.ID)).String()
	_, err = o.emitPrepared(ctx, events.Event{ID: id, Type: projections.EventKeyVaultDisabled, TenantID: tenantID, Data: data})
	return err
}
