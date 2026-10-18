// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CAOfflineRekeyReceipt is an indexed public trust-path projection. A replay
// confirms the first written result rather than replacing the trust path.
type CAOfflineRekeyReceipt struct {
	TenantID               string
	CeremonyID             string
	PredecessorAuthorityID string
	SuccessorAuthorityID   string
	NewSignedByPreviousDER []byte
	PreviousSignedByNewDER []byte
	CompletedAt            time.Time
}

func (s *Store) GetCAOfflineRekeyReceipt(ctx context.Context, tenantID, ceremonyID string) (CAOfflineRekeyReceipt, error) {
	var rec CAOfflineRekeyReceipt
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id::text, ceremony_id::text, predecessor_authority_id::text,
            successor_authority_id::text, new_signed_by_previous_der, previous_signed_by_new_der, completed_at
            FROM ca_offline_rekey_receipts WHERE tenant_id = $1 AND ceremony_id = $2`, tenantID, ceremonyID).
			Scan(&rec.TenantID, &rec.CeremonyID, &rec.PredecessorAuthorityID,
				&rec.SuccessorAuthorityID, &rec.NewSignedByPreviousDER, &rec.PreviousSignedByNewDER, &rec.CompletedAt)
	})
	return rec, err
}

func (s *Store) ApplyCAOfflineRekeyReceiptTx(ctx context.Context, tx pgx.Tx, rec CAOfflineRekeyReceipt) error {
	if rec.TenantID == "" || rec.CeremonyID == "" || rec.PredecessorAuthorityID == "" ||
		rec.SuccessorAuthorityID == "" || rec.PredecessorAuthorityID == rec.SuccessorAuthorityID ||
		len(rec.NewSignedByPreviousDER) == 0 || len(rec.PreviousSignedByNewDER) == 0 || rec.CompletedAt.IsZero() {
		return errors.New("store: incomplete offline-root re-key receipt")
	}
	_, err := tx.Exec(ctx, `INSERT INTO ca_offline_rekey_receipts
        (tenant_id, ceremony_id, predecessor_authority_id, successor_authority_id,
         new_signed_by_previous_der, previous_signed_by_new_der, completed_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (tenant_id, ceremony_id) DO NOTHING`,
		rec.TenantID, rec.CeremonyID, rec.PredecessorAuthorityID, rec.SuccessorAuthorityID,
		rec.NewSignedByPreviousDER, rec.PreviousSignedByNewDER, rec.CompletedAt)
	if err != nil {
		return err
	}
	var saved CAOfflineRekeyReceipt
	err = tx.QueryRow(ctx, `SELECT tenant_id::text, ceremony_id::text, predecessor_authority_id::text,
        successor_authority_id::text, new_signed_by_previous_der, previous_signed_by_new_der, completed_at
        FROM ca_offline_rekey_receipts WHERE tenant_id = $1 AND ceremony_id = $2`, rec.TenantID, rec.CeremonyID).
		Scan(&saved.TenantID, &saved.CeremonyID, &saved.PredecessorAuthorityID,
			&saved.SuccessorAuthorityID, &saved.NewSignedByPreviousDER, &saved.PreviousSignedByNewDER, &saved.CompletedAt)
	if err != nil {
		return err
	}
	if saved.PredecessorAuthorityID != rec.PredecessorAuthorityID || saved.SuccessorAuthorityID != rec.SuccessorAuthorityID ||
		!bytes.Equal(saved.NewSignedByPreviousDER, rec.NewSignedByPreviousDER) ||
		!bytes.Equal(saved.PreviousSignedByNewDER, rec.PreviousSignedByNewDER) ||
		!saved.CompletedAt.Equal(rec.CompletedAt.Truncate(time.Microsecond)) {
		return fmt.Errorf("%w: offline-root re-key ceremony receipt changed", ErrIdempotencyConflict)
	}
	return nil
}
