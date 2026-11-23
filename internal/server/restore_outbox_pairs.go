// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// verifyImportedRestoreOutboxPairs runs while the exact full-restore owner is
// fenced. Each staged mismatch must still name the imported row and the pinned
// event, and both sealed copies must authenticate under the imported key state.
func verifyImportedRestoreOutboxPairs(
	ctx context.Context, st *store.Store, log *events.Log, access tenantseal.Access,
	marker store.RestoreMarker,
) error {
	if err := st.RequireFullRestoreImportOwner(ctx, marker); err != nil {
		return err
	}
	tenants, err := st.RestoreOutboxPairTenants(ctx, marker.OperationID)
	if err != nil {
		return err
	}
	for _, tenantID := range tenants {
		pairs, err := st.ListRestoreOutboxPairs(ctx, tenantID, marker.OperationID)
		if err != nil {
			return err
		}
		for _, pair := range pairs {
			if err := verifyImportedRestoreOutboxPair(ctx, st, log, access, pair); err != nil {
				return fmt.Errorf("restore outbox pair %s: %w", pair.JobID, err)
			}
			if err := st.SettleRestoreOutboxPair(ctx, marker, pair); err != nil {
				return err
			}
		}
	}
	remaining, err := st.RestoreOutboxPairTenants(ctx, marker.OperationID)
	if err != nil {
		return err
	}
	if len(remaining) != 0 {
		return store.ErrRecoveryPairProofMismatch
	}
	return nil
}

func verifyImportedRestoreOutboxPair(
	ctx context.Context, st *store.Store, log *events.Log, access tenantseal.Access,
	pair store.RestoreOutboxPair,
) error {
	return withProjectedSecretSyncSourceCustody(ctx, st, log, access, pair.TenantID,
		func(readCtx context.Context, verify func([]byte, []byte, []byte) (bool, error)) error {
			return verifyImportedRestoreOutboxPairLocked(readCtx, st, log, pair, verify)
		})
}

func verifyImportedRestoreOutboxPairLocked(
	ctx context.Context, st *store.Store, log *events.Log, pair store.RestoreOutboxPair,
	verify func([]byte, []byte, []byte) (bool, error),
) error {
	job, err := st.GetSecretSyncJob(ctx, pair.TenantID, pair.JobID)
	if err != nil {
		return err
	}
	if job.TargetOrder != pair.EventSequence || job.OutboxID != pair.OutboxID {
		return store.ErrRecoveryPairProofMismatch
	}
	rowPayload, err := st.ImportedSecretSyncOutboxPayload(ctx, pair.TenantID, pair.OutboxID)
	if err != nil {
		return err
	}
	if crypto.SHA256Hex(rowPayload) != pair.RowPayloadSHA256 {
		return store.ErrRecoveryPairProofMismatch
	}
	var row secretSyncOutboxPayload
	if err := json.Unmarshal(rowPayload, &row); err != nil || len(row.Sealed) == 0 ||
		crypto.SHA256Hex(row.Sealed) != pair.RowSealedSHA256 {
		return store.ErrRecoveryPairProofMismatch
	}
	eventPayload, eventSealed, err := restoreEventSecretSyncPayload(ctx, log, pair)
	if err != nil {
		return err
	}
	if crypto.SHA256Hex(eventPayload) != pair.EventPayloadSHA256 ||
		crypto.SHA256Hex(eventSealed) != pair.EventSealedSHA256 {
		return store.ErrRecoveryPairProofMismatch
	}
	return validateProjectedSecretSyncSourcePair(ctx, log, job, row, verify)
}

func restoreEventSecretSyncPayload(
	ctx context.Context, log *events.Log, pair store.RestoreOutboxPair,
) ([]byte, []byte, error) {
	if log == nil || pair.EventSequence <= 0 {
		return nil, nil, store.ErrRecoveryPairProofMismatch
	}
	event, found, err := log.EventAtSequence(ctx, uint64(pair.EventSequence)) // #nosec G115 -- positive int64 is representable.
	if err != nil {
		return nil, nil, err
	}
	if !found || event.TenantID != pair.TenantID || event.Sequence != uint64(pair.EventSequence) { // #nosec G115 -- positive int64 is representable.
		return nil, nil, store.ErrRecoveryPairProofMismatch
	}
	var queued projections.SecretSyncQueued
	switch event.Type {
	case projections.EventSecretSyncQueued:
		if event.ID != store.SecretSyncQueuedEventID(pair.TenantID, pair.JobID) ||
			event.SchemaVersion != projections.SecretSyncEventSchemaVersion ||
			json.Unmarshal(event.Data, &queued) != nil {
			return nil, nil, store.ErrRecoveryPairProofMismatch
		}
	case projections.EventApplicationSecretCreated, projections.EventApplicationSecretRotated,
		projections.EventApplicationSecretRecovered, projections.EventApplicationSecretDeleted:
		var mutation projections.ApplicationSecretMutation
		if event.SchemaVersion != projections.ApplicationSecretMutationSchemaVersion ||
			json.Unmarshal(event.Data, &mutation) != nil || mutation.Sync == nil {
			return nil, nil, store.ErrRecoveryPairProofMismatch
		}
		queued = *mutation.Sync
	default:
		return nil, nil, errors.New("restore pair event is not a queued secret-sync command")
	}
	if queued.ID != pair.JobID || len(queued.Sealed) == 0 {
		return nil, nil, store.ErrRecoveryPairProofMismatch
	}
	payload, err := json.Marshal(secretSyncOutboxPayload{
		ID: queued.ID, Key: queued.RemoteKey, Target: queued.Target,
		RequestBinding: queued.RequestBinding, Sealed: queued.Sealed,
	})
	if err != nil {
		return nil, nil, err
	}
	return payload, queued.Sealed, nil
}
