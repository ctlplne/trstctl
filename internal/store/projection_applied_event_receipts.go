// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"
)

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
