// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// CARolloverDraft is the re-key ceremony the CA calendar drafted for an
// authority entering the configured rollover band, or why none could be
// opened (A216).
type CARolloverDraft struct {
	TenantID           string
	AuthorityID        string
	BandMonths         int
	NotAfter           time.Time
	CeremonyID         string
	PreviewFingerprint string
	Reason             string
	TTLSeconds         int64
	NotDraftedReason   string
	DraftedAt          time.Time
	EventSequence      uint64
}

// ApplyCARolloverDraftedTx keeps an authority's newest draft; a replayed or
// older one changes nothing.
func (s *Store) ApplyCARolloverDraftedTx(ctx context.Context, tx pgx.Tx, d CARolloverDraft) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO ca_rollover_drafts (tenant_id, authority_id, band_months, not_after, ceremony_id,
		        preview_fingerprint, reason, ttl_seconds, not_drafted_reason, drafted_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (tenant_id, authority_id) DO UPDATE
		    SET band_months = EXCLUDED.band_months, not_after = EXCLUDED.not_after,
		        ceremony_id = EXCLUDED.ceremony_id, preview_fingerprint = EXCLUDED.preview_fingerprint,
		        reason = EXCLUDED.reason, ttl_seconds = EXCLUDED.ttl_seconds,
		        not_drafted_reason = EXCLUDED.not_drafted_reason, drafted_at = EXCLUDED.drafted_at,
		        event_sequence = EXCLUDED.event_sequence
		  WHERE ca_rollover_drafts.event_sequence < EXCLUDED.event_sequence`,
		d.TenantID, d.AuthorityID, d.BandMonths, d.NotAfter, d.CeremonyID, d.PreviewFingerprint, d.Reason,
		d.TTLSeconds, d.NotDraftedReason, d.DraftedAt,
		int64(d.EventSequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	return err
}

// CARolloverDrafts returns the tenant's drafts by authority id.
func (s *Store) CARolloverDrafts(ctx context.Context, tenantID string) (map[string]CARolloverDraft, error) {
	out := map[string]CARolloverDraft{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, authority_id::text, band_months, not_after, ceremony_id, preview_fingerprint,
			        reason, ttl_seconds, not_drafted_reason, drafted_at, event_sequence
			   FROM ca_rollover_drafts WHERE tenant_id = $1`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d CARolloverDraft
			var seq int64
			if err := rows.Scan(&d.TenantID, &d.AuthorityID, &d.BandMonths, &d.NotAfter, &d.CeremonyID,
				&d.PreviewFingerprint, &d.Reason, &d.TTLSeconds, &d.NotDraftedReason, &d.DraftedAt, &seq); err != nil {
				return err
			}
			d.EventSequence = uint64(seq) // #nosec G115 -- positive by constraint (CWE-190)
			out[d.AuthorityID] = d
		}
		return rows.Err()
	})
	return out, err
}

// PendingKeyCeremonyForPurpose finds a pending ceremony opened for exactly
// this purpose, so a drafted ceremony is reused rather than opened twice.
func (s *Store) PendingKeyCeremonyForPurpose(ctx context.Context, tenantID, purpose string) (string, bool, error) {
	var id string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text FROM ca_key_ceremonies
			  WHERE tenant_id = $1 AND purpose = $2 AND status = 'pending'
			  ORDER BY created_at, id LIMIT 1`, tenantID, purpose).Scan(&id)
	})
	if IsNotFound(err) {
		return "", false, nil
	}
	return id, err == nil, err
}
