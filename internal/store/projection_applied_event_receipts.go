// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrProjectionStagedEventMismatch = errors.New("store: staged projection event does not match its receipt")

// LockProjectionEventTx serializes a staged read-model write with replay of
// the same event until its transaction commits or rolls back.
func (s *Store) LockProjectionEventTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string) error {
	if tx == nil || eventID == "" {
		return nil
	}
	if _, err := uuid.Parse(tenantID); err != nil {
		return nil
	}
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"projection-event\x1f"+tenantID+"\x1f"+eventID)
	return err
}

// StagedProjectionEventReceiptTx returns a digest only for a projection that
// committed with this exact event. A legacy receipt has no staged digest.
func (s *Store) StagedProjectionEventReceiptTx(ctx context.Context, tx pgx.Tx,
	tenantID, eventID string, sequence uint64,
) ([]byte, bool, error) {
	if tx == nil || eventID == "" || sequence == 0 || sequence > math.MaxInt64 {
		return nil, false, nil
	}
	if _, err := uuid.Parse(tenantID); err != nil {
		return nil, false, nil
	}
	var storedSequence int64
	var digest []byte
	err := tx.QueryRow(ctx,
		`SELECT event_sequence, stage_digest FROM projection_applied_event_receipts
		 WHERE tenant_id=$1 AND event_id=$2`, tenantID, eventID).Scan(&storedSequence, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if storedSequence != int64(sequence) {
		return nil, false, ErrProjectionStagedEventMismatch
	}
	if len(digest) == 0 {
		return nil, false, nil
	}
	if len(digest) != 32 {
		return nil, false, ErrProjectionStagedEventMismatch
	}
	return digest, true, nil
}

// RecordStagedProjectionEventReceiptTx commits the exact event binding with
// its core read-model changes. A different receipt never becomes a replay skip.
func (s *Store) RecordStagedProjectionEventReceiptTx(ctx context.Context, tx pgx.Tx,
	tenantID, eventID string, sequence uint64, digest []byte,
) error {
	if tx == nil || eventID == "" || sequence == 0 || sequence > math.MaxInt64 || len(digest) != 32 {
		return ErrProjectionStagedEventMismatch
	}
	// A core handler may have written the same event's legacy sequence
	// receipt earlier in this transaction. Replace only that exact empty
	// receipt, using the table's existing narrow delete/insert grants.
	if _, err := tx.Exec(ctx,
		`DELETE FROM projection_applied_event_receipts
		 WHERE tenant_id=$1 AND event_id=$2 AND event_sequence=$3 AND stage_digest IS NULL`,
		tenantID, eventID, int64(sequence)); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO projection_applied_event_receipts
		 (tenant_id, event_id, event_sequence, stage_digest) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (tenant_id, event_id) DO NOTHING`,
		tenantID, eventID, int64(sequence), digest)
	if err != nil {
		return err
	}
	stored, found, err := s.StagedProjectionEventReceiptTx(ctx, tx, tenantID, eventID, sequence)
	if err != nil {
		return err
	}
	if !found || !bytes.Equal(stored, digest) {
		return ErrProjectionStagedEventMismatch
	}
	return nil
}

func (s *Store) ProjectionAppliedEventReceipt(ctx context.Context, tenantID, eventID string, sequence uint64) (bool, error) {
	var applied bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var queryErr error
		applied, queryErr = s.ProjectionAppliedEventReceiptTx(ctx, tx, tenantID, eventID, sequence)
		return queryErr
	})
	return applied, err
}

func (s *Store) ProjectionAppliedEventReceiptTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string, sequence uint64) (bool, error) {
	if sequence == 0 || sequence > math.MaxInt64 || eventID == "" {
		return false, nil
	}
	var applied bool
	err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM projection_applied_event_receipts
		  WHERE tenant_id=$1 AND event_id=$2 AND event_sequence=$3)`,
		tenantID, eventID, int64(sequence)).Scan(&applied)
	return applied, err
}

func (s *Store) RecordProjectionAppliedEventReceiptTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string, sequence uint64) error {
	if sequence == 0 || eventID == "" {
		return nil
	}
	if sequence > math.MaxInt64 {
		return errors.New("store: projection event sequence exceeds PostgreSQL range")
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO projection_applied_event_receipts (tenant_id, event_id, event_sequence)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (tenant_id, event_id) DO NOTHING`,
		tenantID, eventID, int64(sequence))
	if err != nil {
		return err
	}
	applied, err := s.ProjectionAppliedEventReceiptTx(ctx, tx, tenantID, eventID, sequence)
	if err != nil {
		return err
	}
	if !applied {
		return fmt.Errorf("store: projection event receipt has a different sequence for event %s", eventID)
	}
	return nil
}
