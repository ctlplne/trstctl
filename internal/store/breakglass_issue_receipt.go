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

// BreakglassIssueReceipt is an immutable, event-derived public certificate and
// signature. The subject's private key never enters this table or the event.
type BreakglassIssueReceipt struct {
	TenantID      string          `json:"tenant_id"`
	CeremonyID    string          `json:"ceremony_id"`
	RequestID     string          `json:"request_id"`
	Subject       string          `json:"subject"`
	RequestDigest string          `json:"request_digest"`
	Bundle        json.RawMessage `json:"bundle,omitempty"`
	EventSequence uint64          `json:"event_sequence"`
	IssuedAt      time.Time       `json:"issued_at"`
}

func (s *Store) ApplyBreakglassIssueReceiptTx(ctx context.Context, tx pgx.Tx, rec BreakglassIssueReceipt) error {
	if rec.TenantID == "" || rec.CeremonyID == "" || rec.RequestID == "" || rec.Subject == "" ||
		rec.RequestDigest == "" || len(rec.Bundle) == 0 || rec.EventSequence == 0 || rec.EventSequence > math.MaxInt64 || rec.IssuedAt.IsZero() || !json.Valid(rec.Bundle) {
		return errors.New("store: incomplete break-glass issue receipt")
	}
	eventSeq := int64(rec.EventSequence) // #nosec G115 -- the explicit MaxInt64 bound above prevents narrowing (CWE-190).
	_, err := tx.Exec(ctx, `INSERT INTO breakglass_issue_receipts
        (tenant_id,ceremony_id,request_id,subject,request_digest,bundle,event_sequence,issued_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (tenant_id,ceremony_id) DO NOTHING`,
		rec.TenantID, rec.CeremonyID, rec.RequestID, rec.Subject, rec.RequestDigest, rec.Bundle,
		eventSeq, rec.IssuedAt)
	if err != nil {
		return err
	}
	var saved BreakglassIssueReceipt
	var seq int64
	err = tx.QueryRow(ctx, `SELECT tenant_id::text,ceremony_id::text,request_id,subject,request_digest,bundle,event_sequence,issued_at
        FROM breakglass_issue_receipts WHERE tenant_id=$1 AND ceremony_id=$2`, rec.TenantID, rec.CeremonyID).
		Scan(&saved.TenantID, &saved.CeremonyID, &saved.RequestID, &saved.Subject, &saved.RequestDigest, &saved.Bundle, &seq, &saved.IssuedAt)
	if err != nil {
		return err
	}
	if saved.RequestID != rec.RequestID || saved.Subject != rec.Subject || saved.RequestDigest != rec.RequestDigest ||
		seq != eventSeq || !saved.IssuedAt.Equal(rec.IssuedAt.Truncate(time.Microsecond)) ||
		!bytes.Equal(canonicalJSON(saved.Bundle), canonicalJSON(rec.Bundle)) {
		return fmt.Errorf("%w: break-glass issue receipt changed", ErrIdempotencyConflict)
	}
	return nil
}

func canonicalJSON(raw []byte) []byte {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return raw
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return raw
	}
	return normalized
}

func (s *Store) GetBreakglassIssueReceipt(ctx context.Context, tenantID, ceremonyID string) (BreakglassIssueReceipt, error) {
	var rec BreakglassIssueReceipt
	var seq int64
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id::text,ceremony_id::text,request_id,subject,request_digest,bundle,event_sequence,issued_at
            FROM breakglass_issue_receipts WHERE tenant_id=$1 AND ceremony_id=$2`, tenantID, ceremonyID).
			Scan(&rec.TenantID, &rec.CeremonyID, &rec.RequestID, &rec.Subject, &rec.RequestDigest, &rec.Bundle, &seq, &rec.IssuedAt)
	})
	if seq >= 0 {
		rec.EventSequence = uint64(seq)
	}
	return rec, err
}

func (s *Store) ListBreakglassIssueReceipts(ctx context.Context, tenantID string, before uint64, limit int) ([]BreakglassIssueReceipt, error) {
	if limit < 1 || limit > 100 {
		return nil, errors.New("store: break-glass receipt limit must be 1..100")
	}
	if before > math.MaxInt64 {
		return nil, errors.New("store: invalid break-glass receipt cursor")
	}
	beforeSeq := int64(before) // #nosec G115 -- MaxInt64 bound above rejects narrowing (CWE-190).
	result := make([]BreakglassIssueReceipt, 0, limit)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text,ceremony_id::text,request_id,subject,request_digest,event_sequence,issued_at
			FROM breakglass_issue_receipts WHERE tenant_id=$1 AND ($2::bigint=0 OR event_sequence<$2)
			ORDER BY event_sequence DESC LIMIT $3`, tenantID, beforeSeq, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec BreakglassIssueReceipt
			var seq int64
			if err := rows.Scan(&rec.TenantID, &rec.CeremonyID, &rec.RequestID, &rec.Subject, &rec.RequestDigest, &seq, &rec.IssuedAt); err != nil {
				return err
			}
			if seq < 0 {
				return errors.New("store: negative break-glass event sequence")
			}
			rec.EventSequence = uint64(seq)
			result = append(result, rec)
		}
		return rows.Err()
	})
	return result, err
}

func (s *Store) BreakglassIssueRecoveryCursor(ctx context.Context) (uint64, error) {
	var checked int64
	err := s.poolFor(ctx).QueryRow(ctx, `SELECT COALESCE(breakglass_issue_checked_through,0) FROM projection_checkpoint WHERE id=1`).Scan(&checked)
	if err != nil {
		return 0, err
	}
	if checked < 0 {
		return 0, errors.New("store: negative break-glass recovery cursor")
	}
	return uint64(checked), nil
}

func (s *Store) MarkBreakglassIssueCheckedThrough(ctx context.Context, seq uint64) error {
	if seq > math.MaxInt64 {
		return errors.New("store: break-glass recovery head exceeds PostgreSQL bigint")
	}
	checkedSeq := int64(seq) // #nosec G115 -- MaxInt64 bound above rejects narrowing (CWE-190).
	_, err := s.poolFor(ctx).Exec(ctx, `UPDATE projection_checkpoint SET breakglass_issue_checked_through=GREATEST(COALESCE(breakglass_issue_checked_through,0),$1),updated_at=now() WHERE id=1`, checkedSeq)
	return err
}
