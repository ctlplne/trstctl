// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

// WithRawHistoryRecordJournal records one HMAC-verified artifact record's
// exact target intent before NATS I/O. run must read back the target message
// after ACK. Any ambiguous outcome leaves a durable started row and the
// full-restore marker armed for exact-artifact continuation.
func (s *Store) WithRawHistoryRecordJournal(
	ctx context.Context, cut uint64, artifactDigest, action string,
	record events.BackupHistoryRecord, run func(context.Context) error,
) error {
	if s == nil || run == nil ||
		record.Sequence > math.MaxInt64 || !restoreArtifactDigest.MatchString(artifactDigest) {
		return ErrRestoreAdmissionLost
	}
	if record.Sequence > cut {
		return ErrRestoreAdmissionLost
	}
	if err := s.RequireFullRestoreHistoryOwner(ctx, cut, artifactDigest); err != nil {
		return err
	}
	lease := ctx.Value(restoreOwnerContextKey{}).(*restoreOwnerLease)
	tenantID := RestoreControlTenantID
	switch action {
	case "bind", "index", "unbind":
		if record.Sequence != 0 || record.IsGap() || len(record.Stored) != 0 ||
			record.Subject == "" || record.MessageID != "" {
			return ErrRestoreAdmissionLost
		}
	case "gap":
		if record.Sequence == 0 || !record.IsGap() {
			return ErrRestoreAdmissionLost
		}
		if record.GapThrough != record.Sequence || len(record.Stored) != 0 ||
			record.Subject == "" || record.MessageID == "" {
			return ErrRestoreAdmissionLost
		}
	case "live":
		if record.Sequence == 0 || record.IsGap() {
			return ErrRestoreAdmissionLost
		}
		event, err := events.DecodeBackupHistoryEvent(record)
		if err != nil {
			return err
		}
		if _, err := uuid.Parse(event.TenantID); err != nil {
			return ErrRestoreAdmissionLost
		}
		tenantID = event.TenantID
	default:
		return ErrRestoreAdmissionLost
	}
	digest := crypto.SHA256Hex(record.Stored)
	sequence := int64(record.Sequence) // #nosec G115 -- checked against MaxInt64 above.
	if err := s.stageRawHistoryRecord(ctx, tenantID, lease.marker.OperationID,
		artifactDigest, sequence, action, digest, record.Subject, record.MessageID); err != nil {
		return err
	}
	if err := run(ctx); err != nil {
		return err
	}
	if err := s.RequireFullRestoreHistoryOwner(ctx, cut, artifactDigest); err != nil {
		return err
	}
	return s.verifyRawHistoryRecord(ctx, tenantID, lease.marker.OperationID,
		artifactDigest, sequence, action, digest, record.Subject, record.MessageID)
}

func (s *Store) stageRawHistoryRecord(ctx context.Context, tenantID, operationID,
	artifactDigest string, sequence int64, action, digest, subject, messageID string,
) error {
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := s.SetTenantGUCTx(ctx, tx, tenantID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO trstctl_recovery.raw_history_journal
		(tenant_id,operation_id,artifact_sha256,source_sequence,action,raw_sha256,
		 source_subject,source_message_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (tenant_id,operation_id,source_sequence,action) DO UPDATE
		SET phase=trstctl_recovery.raw_history_journal.phase
		WHERE trstctl_recovery.raw_history_journal.artifact_sha256=EXCLUDED.artifact_sha256
		  AND trstctl_recovery.raw_history_journal.raw_sha256=EXCLUDED.raw_sha256
		  AND trstctl_recovery.raw_history_journal.source_subject=EXCLUDED.source_subject
		  AND trstctl_recovery.raw_history_journal.source_message_id=EXCLUDED.source_message_id`,
		tenantID, operationID, artifactDigest, sequence, action, digest, subject, messageID)
	if err != nil {
		return fmt.Errorf("store: stage raw history record: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrRestoreInProgress
	}
	return tx.Commit(ctx)
}

func (s *Store) verifyRawHistoryRecord(ctx context.Context, tenantID, operationID,
	artifactDigest string, sequence int64, action, digest, subject, messageID string,
) error {
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := s.SetTenantGUCTx(ctx, tx, tenantID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE trstctl_recovery.raw_history_journal
		SET phase='verified', verified_at=COALESCE(verified_at,now())
		WHERE tenant_id=$1 AND operation_id=$2 AND artifact_sha256=$3
		AND source_sequence=$4 AND action=$5 AND raw_sha256=$6
		AND source_subject=$7 AND source_message_id=$8`,
		tenantID, operationID, artifactDigest, sequence, action, digest, subject, messageID)
	if err != nil {
		return fmt.Errorf("store: verify raw history record: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("store: raw history journal identity changed")
	}
	return tx.Commit(ctx)
}
