// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// BreakglassAuthorityReceipt contains public certificates, never signer keys.
// List queries omit Result; an exact ceremony GET retrieves the full result.
type BreakglassAuthorityReceipt struct {
	TenantID      string          `json:"tenant_id"`
	CeremonyID    string          `json:"ceremony_id"`
	Kind          string          `json:"kind"`
	Subject       string          `json:"subject"`
	RequestDigest string          `json:"request_digest"`
	Result        json.RawMessage `json:"result,omitempty"`
	EventSequence uint64          `json:"event_sequence"`
	CompletedAt   time.Time       `json:"completed_at"`
}

func (s *Store) ApplyBreakglassAuthorityReceiptTx(ctx context.Context, tx pgx.Tx, rec BreakglassAuthorityReceipt) error {
	if rec.TenantID == "" || rec.CeremonyID == "" || (rec.Kind != "rotation" && rec.Kind != "cross_sign") ||
		rec.Subject == "" || rec.RequestDigest == "" || len(rec.Result) == 0 || !json.Valid(rec.Result) ||
		rec.EventSequence == 0 || rec.EventSequence > math.MaxInt64 || rec.CompletedAt.IsZero() {
		return errors.New("store: incomplete break-glass authority receipt")
	}
	seq := int64(rec.EventSequence) // #nosec G115 -- MaxInt64 checked above.
	// A second writer can project the same immutable event during recovery. Lock
	// the exact tenant/ceremony arbiter before INSERT so the source-sequence
	// uniqueness check cannot race an otherwise identical primary-key retry.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"breakglass-authority-receipt\x1f"+rec.TenantID+"\x1f"+rec.CeremonyID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO breakglass_authority_receipts
		(tenant_id,ceremony_id,kind,subject,request_digest,result,event_sequence,completed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (tenant_id,ceremony_id) DO NOTHING`,
		rec.TenantID, rec.CeremonyID, rec.Kind, rec.Subject, rec.RequestDigest, rec.Result, seq, rec.CompletedAt)
	if err != nil {
		return err
	}
	var saved BreakglassAuthorityReceipt
	var savedSeq int64
	err = tx.QueryRow(ctx, `SELECT tenant_id::text,ceremony_id::text,kind,subject,request_digest,result,event_sequence,completed_at
		FROM breakglass_authority_receipts WHERE tenant_id=$1 AND ceremony_id=$2`, rec.TenantID, rec.CeremonyID).
		Scan(&saved.TenantID, &saved.CeremonyID, &saved.Kind, &saved.Subject, &saved.RequestDigest, &saved.Result, &savedSeq, &saved.CompletedAt)
	if err != nil {
		return err
	}
	if saved.Kind != rec.Kind || saved.Subject != rec.Subject || saved.RequestDigest != rec.RequestDigest ||
		savedSeq != seq || !saved.CompletedAt.Equal(rec.CompletedAt.Truncate(time.Microsecond)) ||
		!bytes.Equal(canonicalJSON(saved.Result), canonicalJSON(rec.Result)) {
		return fmt.Errorf("%w: break-glass authority receipt changed", ErrIdempotencyConflict)
	}
	return nil
}

func (s *Store) GetBreakglassAuthorityReceipt(ctx context.Context, tenantID, ceremonyID string) (BreakglassAuthorityReceipt, error) {
	var rec BreakglassAuthorityReceipt
	var seq int64
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id::text,ceremony_id::text,kind,subject,request_digest,result,event_sequence,completed_at
			FROM breakglass_authority_receipts WHERE tenant_id=$1 AND ceremony_id=$2`, tenantID, ceremonyID).
			Scan(&rec.TenantID, &rec.CeremonyID, &rec.Kind, &rec.Subject, &rec.RequestDigest, &rec.Result, &seq, &rec.CompletedAt)
	})
	if seq >= 0 {
		rec.EventSequence = uint64(seq)
	}
	return rec, err
}

func (s *Store) ListBreakglassAuthorityReceipts(ctx context.Context, tenantID string, before uint64, limit int) ([]BreakglassAuthorityReceipt, error) {
	if limit < 1 || limit > 100 || before > math.MaxInt64 {
		return nil, errors.New("store: invalid break-glass authority receipt page")
	}
	beforeSeq := int64(before) // #nosec G115 -- MaxInt64 checked above.
	result := make([]BreakglassAuthorityReceipt, 0, limit)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text,ceremony_id::text,kind,subject,request_digest,event_sequence,completed_at
			FROM breakglass_authority_receipts WHERE tenant_id=$1 AND ($2::bigint=0 OR event_sequence<$2)
			ORDER BY event_sequence DESC LIMIT $3`, tenantID, beforeSeq, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec BreakglassAuthorityReceipt
			var seq int64
			if err := rows.Scan(&rec.TenantID, &rec.CeremonyID, &rec.Kind, &rec.Subject, &rec.RequestDigest, &seq, &rec.CompletedAt); err != nil {
				return err
			}
			if seq < 0 {
				return errors.New("store: negative break-glass authority event sequence")
			}
			rec.EventSequence = uint64(seq)
			result = append(result, rec)
		}
		return rows.Err()
	})
	return result, err
}

func (s *Store) BreakglassAuthorityRecoveryCursor(ctx context.Context) (uint64, error) {
	var checked int64
	err := s.poolFor(ctx).QueryRow(ctx, `SELECT COALESCE(breakglass_authority_checked_through,0) FROM projection_checkpoint WHERE id=1`).Scan(&checked)
	if err != nil {
		return 0, err
	}
	if checked < 0 {
		return 0, errors.New("store: negative break-glass authority recovery cursor")
	}
	return uint64(checked), nil
}

func (s *Store) MarkBreakglassAuthorityCheckedThrough(ctx context.Context, seq uint64) error {
	if seq > math.MaxInt64 {
		return errors.New("store: break-glass authority recovery head exceeds PostgreSQL bigint")
	}
	checked := int64(seq) // #nosec G115 -- MaxInt64 checked above.
	_, err := s.poolFor(ctx).Exec(ctx, `UPDATE projection_checkpoint
		SET breakglass_authority_checked_through=GREATEST(COALESCE(breakglass_authority_checked_through,0),$1),updated_at=now()
		WHERE id=1`, checked)
	return err
}
