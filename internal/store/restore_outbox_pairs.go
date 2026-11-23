// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RestoreOutboxPair is target-local evidence that an event-derived command and
// the signed PostgreSQL artifact disagree only in sealed bytes. It is not a
// cryptographic proof; the full-restore owner must re-read and authenticate
// both copies after importing the artifact's key state.
type RestoreOutboxPair struct {
	TenantID, OperationID, JobID string
	EventSequence                int64
	OutboxID                     int64
	EventPayloadSHA256           string
	RowPayloadSHA256             string
	EventSealedSHA256            string
	RowSealedSHA256              string
}

func (p RestoreOutboxPair) valid() bool {
	for _, id := range []string{p.TenantID, p.OperationID} {
		if _, err := uuid.Parse(id); err != nil {
			return false
		}
	}
	if p.JobID == "" || p.EventSequence <= 0 || p.OutboxID <= 0 {
		return false
	}
	for _, digest := range []string{p.EventPayloadSHA256, p.RowPayloadSHA256,
		p.EventSealedSHA256, p.RowSealedSHA256} {
		if !restoreArtifactDigest.MatchString(digest) {
			return false
		}
	}
	return true
}

// StageRestoreOutboxPairTx uses the importer's owner transaction. A retry of
// the same artifact can retain the same hashes; changed evidence refuses.
func (s *Store) StageRestoreOutboxPairTx(ctx context.Context, tx pgx.Tx, pair RestoreOutboxPair) error {
	if s == nil || tx == nil || !pair.valid() {
		return fmt.Errorf("store: invalid staged restore outbox pair: %w", ErrRecoveryPairProofMismatch)
	}
	if err := s.SetTenantGUCTx(ctx, tx, pair.TenantID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO trstctl_recovery.restore_outbox_pairs
		(tenant_id,operation_id,job_id,event_sequence,outbox_id,
		 event_payload_sha256,row_payload_sha256,event_sealed_sha256,row_sealed_sha256)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (tenant_id,operation_id,job_id) DO UPDATE
		SET event_sequence=EXCLUDED.event_sequence
		WHERE trstctl_recovery.restore_outbox_pairs.event_sequence=EXCLUDED.event_sequence
		  AND trstctl_recovery.restore_outbox_pairs.outbox_id=EXCLUDED.outbox_id
		  AND trstctl_recovery.restore_outbox_pairs.event_payload_sha256=EXCLUDED.event_payload_sha256
		  AND trstctl_recovery.restore_outbox_pairs.row_payload_sha256=EXCLUDED.row_payload_sha256
		  AND trstctl_recovery.restore_outbox_pairs.event_sealed_sha256=EXCLUDED.event_sealed_sha256
		  AND trstctl_recovery.restore_outbox_pairs.row_sealed_sha256=EXCLUDED.row_sealed_sha256`,
		pair.TenantID, pair.OperationID, pair.JobID, pair.EventSequence, pair.OutboxID,
		pair.EventPayloadSHA256, pair.RowPayloadSHA256, pair.EventSealedSHA256, pair.RowSealedSHA256)
	if err != nil {
		return fmt.Errorf("store: stage restore outbox pair: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("store: changed staged restore outbox pair: %w", ErrRecoveryPairProofMismatch)
	}
	return nil
}

// RestoreOutboxPairTenants is an audited system enumeration of only the tenant
// IDs with unresolved proof rows for this exact restore operation.
func (s *Store) RestoreOutboxPairTenants(ctx context.Context, operationID string) ([]string, error) {
	if s == nil {
		return nil, ErrRecoveryPairProofMismatch
	}
	if _, err := uuid.Parse(operationID); err != nil {
		return nil, ErrRecoveryPairProofMismatch
	}
	//trstctl:system-query — system recovery makes a cross-tenant enumeration of only tenant_id for this exact operation; each tenant's proof rows are then read through RLS.
	rows, err := s.SystemPool().Query(ctx, `SELECT DISTINCT tenant_id::text
		FROM trstctl_recovery.restore_outbox_pairs WHERE operation_id=$1 ORDER BY tenant_id`, operationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		tenants = append(tenants, tenantID)
	}
	return tenants, rows.Err()
}

func (s *Store) ListRestoreOutboxPairs(ctx context.Context, tenantID, operationID string) ([]RestoreOutboxPair, error) {
	if s == nil {
		return nil, ErrRecoveryPairProofMismatch
	}
	if _, err := uuid.Parse(operationID); err != nil {
		return nil, ErrRecoveryPairProofMismatch
	}
	var pairs []RestoreOutboxPair
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text,operation_id::text,job_id::text,
			event_sequence,outbox_id,event_payload_sha256,row_payload_sha256,
			event_sealed_sha256,row_sealed_sha256
			FROM trstctl_recovery.restore_outbox_pairs
			WHERE tenant_id=$1 AND operation_id=$2 ORDER BY job_id`, tenantID, operationID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var pair RestoreOutboxPair
			if err := rows.Scan(&pair.TenantID, &pair.OperationID, &pair.JobID,
				&pair.EventSequence, &pair.OutboxID, &pair.EventPayloadSHA256,
				&pair.RowPayloadSHA256, &pair.EventSealedSHA256, &pair.RowSealedSHA256); err != nil {
				return err
			}
			pairs = append(pairs, pair)
		}
		return rows.Err()
	})
	return pairs, err
}

// ImportedSecretSyncOutboxPayload rereads the artifact's committed row by its
// exact tenant and SQL identity, after the importer transaction has committed.
func (s *Store) ImportedSecretSyncOutboxPayload(ctx context.Context, tenantID string, outboxID int64) ([]byte, error) {
	if s == nil || outboxID <= 0 {
		return nil, ErrRecoveryPairProofMismatch
	}
	var payload []byte
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT payload FROM outbox
			WHERE tenant_id=$1 AND id=$2 AND destination LIKE 'secret.sync.%'`, tenantID, outboxID).Scan(&payload)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRecoveryPairProofMismatch
	}
	return payload, err
}

// SettleRestoreOutboxPair is called only after event, row and key custody all
// authenticated under the live full-restore marker. A changed row cannot be
// erased by a stale proof, even if another caller presents the same job ID.
func (s *Store) SettleRestoreOutboxPair(ctx context.Context, marker RestoreMarker, pair RestoreOutboxPair) error {
	if s == nil || !pair.valid() || pair.OperationID != marker.OperationID {
		return ErrRecoveryPairProofMismatch
	}
	if err := s.RequireFullRestoreImportOwner(ctx, marker); err != nil {
		return err
	}
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := s.SetTenantGUCTx(ctx, tx, pair.TenantID); err != nil {
		return err
	}
	{
		tag, err := tx.Exec(ctx, `DELETE FROM trstctl_recovery.restore_outbox_pairs
			WHERE tenant_id=$1 AND operation_id=$2 AND job_id=$3
			AND event_sequence=$4 AND outbox_id=$5
			AND event_payload_sha256=$6 AND row_payload_sha256=$7
			AND event_sealed_sha256=$8 AND row_sealed_sha256=$9`,
			pair.TenantID, pair.OperationID, pair.JobID, pair.EventSequence, pair.OutboxID,
			pair.EventPayloadSHA256, pair.RowPayloadSHA256, pair.EventSealedSHA256, pair.RowSealedSHA256)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrRecoveryPairProofMismatch
		}
	}
	return tx.Commit(ctx)
}
