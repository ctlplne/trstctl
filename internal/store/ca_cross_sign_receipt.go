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

// CACrossSignReceipt contains only public certificate material. The event is
// authoritative; this indexed row is the recoverable tenant read model.
type CACrossSignReceipt struct {
	TenantID             string
	CeremonyID           string
	IssuerAuthorityID    string
	TargetSHA256         string
	TargetCertificateDER []byte
	CrossCertificateDER  []byte
	Imported             bool
	CompletedAt          time.Time
}

func (s *Store) GetCACrossSignReceipt(ctx context.Context, tenantID, ceremonyID string) (CACrossSignReceipt, error) {
	var rec CACrossSignReceipt
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id::text, ceremony_id::text, issuer_authority_id::text,
            target_sha256, target_certificate_der, cross_certificate_der, imported, completed_at
            FROM ca_cross_sign_receipts WHERE tenant_id = $1 AND ceremony_id = $2`, tenantID, ceremonyID).
			Scan(&rec.TenantID, &rec.CeremonyID, &rec.IssuerAuthorityID, &rec.TargetSHA256,
				&rec.TargetCertificateDER, &rec.CrossCertificateDER, &rec.Imported, &rec.CompletedAt)
	})
	return rec, err
}

// ApplyCACrossSignReceiptTx inserts or confirms the exact immutable receipt.
// Replaying an event never changes an existing public trust path.
func (s *Store) ApplyCACrossSignReceiptTx(ctx context.Context, tx pgx.Tx, rec CACrossSignReceipt) error {
	if rec.TenantID == "" || rec.CeremonyID == "" || rec.IssuerAuthorityID == "" ||
		len(rec.TargetSHA256) != 64 || len(rec.TargetCertificateDER) == 0 ||
		len(rec.CrossCertificateDER) == 0 || rec.CompletedAt.IsZero() {
		return errors.New("store: incomplete CA cross-sign receipt")
	}
	_, err := tx.Exec(ctx, `INSERT INTO ca_cross_sign_receipts
        (tenant_id, ceremony_id, issuer_authority_id, target_sha256,
         target_certificate_der, cross_certificate_der, imported, completed_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        ON CONFLICT (tenant_id, ceremony_id) DO NOTHING`,
		rec.TenantID, rec.CeremonyID, rec.IssuerAuthorityID, rec.TargetSHA256,
		rec.TargetCertificateDER, rec.CrossCertificateDER, rec.Imported, rec.CompletedAt)
	if err != nil {
		return err
	}
	var saved CACrossSignReceipt
	err = tx.QueryRow(ctx, `SELECT tenant_id::text, ceremony_id::text, issuer_authority_id::text,
        target_sha256, target_certificate_der, cross_certificate_der, imported, completed_at
        FROM ca_cross_sign_receipts WHERE tenant_id = $1 AND ceremony_id = $2`, rec.TenantID, rec.CeremonyID).
		Scan(&saved.TenantID, &saved.CeremonyID, &saved.IssuerAuthorityID, &saved.TargetSHA256,
			&saved.TargetCertificateDER, &saved.CrossCertificateDER, &saved.Imported, &saved.CompletedAt)
	if err != nil {
		return err
	}
	if saved.IssuerAuthorityID != rec.IssuerAuthorityID || saved.TargetSHA256 != rec.TargetSHA256 ||
		!bytes.Equal(saved.TargetCertificateDER, rec.TargetCertificateDER) ||
		!bytes.Equal(saved.CrossCertificateDER, rec.CrossCertificateDER) ||
		saved.Imported != rec.Imported || !saved.CompletedAt.Equal(rec.CompletedAt.Truncate(time.Microsecond)) {
		return fmt.Errorf("%w: CA cross-sign ceremony receipt changed", ErrIdempotencyConflict)
	}
	return nil
}
