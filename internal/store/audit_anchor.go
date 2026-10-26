// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
)

// AuditAnchor is one projected audit.anchored event (A147): a TSA timestamp
// over a tenant's full audit chain through a tenant-local record. The event in
// the tenant's audit log is the source of truth; this row serves the anchoring
// status and the anchor log.
type AuditAnchor struct {
	TenantID        string    `json:"tenant_id"`
	EventID         string    `json:"event_id"`
	ThroughSequence uint64    `json:"through_sequence"`
	ChainHead       string    `json:"chain_head"`
	AnchoredAt      time.Time `json:"anchored_at"`
	TokenSerial     uint64    `json:"token_serial"`
	TokenSHA256     string    `json:"token_sha256"`
	CadenceSeconds  int64     `json:"cadence_seconds"`
	EventSequence   uint64    `json:"event_sequence"`
	RecordedAt      time.Time `json:"recorded_at"`
}

var auditAnchorHexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ApplyAuditAnchorTx records one anchor from its event, during live projection
// or rebuild. Replaying the same event is a no-op.
func (s *Store) ApplyAuditAnchorTx(ctx context.Context, tx pgx.Tx, anchor AuditAnchor) error {
	if anchor.TenantID == "" || anchor.EventID == "" || anchor.ThroughSequence == 0 || anchor.EventSequence == 0 ||
		anchor.CadenceSeconds <= 0 || anchor.AnchoredAt.IsZero() ||
		!auditAnchorHexRE.MatchString(anchor.ChainHead) || !auditAnchorHexRE.MatchString(anchor.TokenSHA256) {
		return errors.New("store: audit anchor event is incomplete")
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO audit_anchors (tenant_id, event_id, through_sequence, chain_head, anchored_at, token_serial,
		                            token_sha256, cadence_seconds, event_sequence, recorded_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (tenant_id, event_id) DO NOTHING`,
		anchor.TenantID, anchor.EventID, int64(anchor.ThroughSequence), anchor.ChainHead, anchor.AnchoredAt.UTC(), // #nosec G115 -- tenant-local audit ordinal fits a Postgres bigint (CWE-190)
		fmt.Sprintf("%d", anchor.TokenSerial), anchor.TokenSHA256, anchor.CadenceSeconds,
		int64(anchor.EventSequence), anchor.RecordedAt.UTC()) // #nosec G115 -- event-log sequence fits a Postgres bigint (CWE-190)
	return err
}

// ListAuditAnchors returns a tenant's most recent anchors, newest first.
func (s *Store) ListAuditAnchors(ctx context.Context, tenantID string, limit int) ([]AuditAnchor, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	return s.queryAuditAnchors(ctx, tenantID,
		`SELECT tenant_id::text, event_id, through_sequence, chain_head, anchored_at, token_serial::text, token_sha256,
		        cadence_seconds, event_sequence, recorded_at
		   FROM audit_anchors WHERE tenant_id = $1 ORDER BY anchored_at DESC, event_sequence DESC LIMIT $2`,
		tenantID, limit)
}

// CountAuditAnchors returns how many anchors a tenant has.
func (s *Store) CountAuditAnchors(ctx context.Context, tenantID string) (int64, error) {
	var count int64
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_anchors WHERE tenant_id = $1`, tenantID).Scan(&count)
	})
	return count, err
}

func (s *Store) queryAuditAnchors(ctx context.Context, tenantID, query string, args ...any) ([]AuditAnchor, error) {
	var out []AuditAnchor
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				anchor          AuditAnchor
				through, evSeq  int64
				serial          string
				anchoredAt, rec time.Time
			)
			if err := rows.Scan(&anchor.TenantID, &anchor.EventID, &through, &anchor.ChainHead, &anchoredAt, &serial,
				&anchor.TokenSHA256, &anchor.CadenceSeconds, &evSeq, &rec); err != nil {
				return err
			}
			if _, err := fmt.Sscan(serial, &anchor.TokenSerial); err != nil {
				return fmt.Errorf("store: audit anchor token serial: %w", err)
			}
			anchor.ThroughSequence, anchor.EventSequence = uint64(through), uint64(evSeq) // #nosec G115 -- the table CHECKs keep both positive (CWE-190)
			anchor.AnchoredAt, anchor.RecordedAt = anchoredAt.UTC(), rec.UTC()
			out = append(out, anchor)
		}
		return rows.Err()
	})
	return out, err
}
