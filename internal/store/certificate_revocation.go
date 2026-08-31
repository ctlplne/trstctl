// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

const CertificateCRLPublicationDestination = "revocation.crl.publish"

type CertificateCRLPublication struct {
	EventID string `json:"event_id"`
	CAID    string `json:"ca_id"`
}

// LockCertificateRevocationCommandTx serializes retries before consulting
// retained events, including after the broker's finite duplicate window.
func (s *Store) LockCertificateRevocationCommandTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string) error {
	if tenantID == "" || eventID == "" {
		return fmt.Errorf("store: certificate revocation command identity is required")
	}
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"certificate-revocation-command\x1f"+tenantID+"\x1f"+eventID)
	return err
}

// CertificateForRevocationTx freezes the exact certificate and its owner while
// the command evaluates policy. Callers lock a batch in sorted ID order.
func (s *Store) CertificateForRevocationTx(ctx context.Context, tx pgx.Tx, tenantID, id string) (Certificate, error) {
	var certificate Certificate
	err := scanCertificate(tx.QueryRow(ctx,
		`SELECT `+certificateColumns+` FROM certificates
		 WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, id), &certificate)
	return certificate, err
}

// IssuedCertificateForRevocationTx locks the existing authority record after
// the inventory row. The producer has already verified the leaf signature;
// this read determines whether "already revoked" is actually true at its CA.
func (s *Store) IssuedCertificateForRevocationTx(ctx context.Context, tx pgx.Tx, tenantID, caID, serial string) (IssuedCert, error) {
	var issued IssuedCert
	err := tx.QueryRow(ctx, `SELECT tenant_id::text, ca_id::text, serial, issued_at, revoked_at, reason_code
		FROM ca_issued_certs WHERE tenant_id = $1 AND ca_id = $2 AND serial = $3 FOR UPDATE`,
		tenantID, caID, serial).Scan(&issued.TenantID, &issued.CAID, &issued.Serial, &issued.IssuedAt, &issued.RevokedAt, &issued.ReasonCode)
	return issued, err
}

// ApplyExactCertificateRevocationTx cannot invent an issued-serial row. A
// discovered/imported certificate is not authority to revoke a different leaf
// with the same serial at an unrelated CA.
func (s *Store) ApplyExactCertificateRevocationTx(ctx context.Context, tx pgx.Tx, tenantID, id, fingerprint, serial, caID, reason string, reasonCode int, at time.Time) error {
	certificate, err := s.CertificateForRevocationTx(ctx, tx, tenantID, id)
	if err != nil {
		return err
	}
	if certificate.Fingerprint != fingerprint || certificate.Serial != serial {
		return fmt.Errorf("%w: certificate revocation target changed", ErrIdempotencyConflict)
	}
	if !crypto.IsValidRevocationReason(reason) || crypto.CRLReasonCode(crypto.RevocationReason(reason)) != reasonCode || reason == "removeFromCRL" {
		return fmt.Errorf("store: certificate revocation reason disagrees with authority code")
	}
	// UPDATE, never UPSERT: a retained receipt cannot invent an issuer record.
	// Preserve the CA's first revocation facts, then synchronize inventory from
	// those exact values instead of overwriting it with a later replay's time.
	var canonicalAt time.Time
	var canonicalCode int
	if err := tx.QueryRow(ctx, `UPDATE ca_issued_certs
		SET revoked_at = COALESCE(revoked_at, $4),
		    reason_code = CASE WHEN revoked_at IS NULL THEN $5 ELSE reason_code END
		WHERE tenant_id = $1 AND ca_id = $2 AND serial = $3
		RETURNING revoked_at, reason_code`, tenantID, caID, serial, at.UTC(), reasonCode).Scan(&canonicalAt, &canonicalCode); err != nil {
		return err
	}
	canonicalReason, ok := crypto.RevocationReasonFromCRLCode(canonicalCode)
	if !ok || canonicalReason == crypto.RevocationReasonRemoveFromCRL {
		return fmt.Errorf("store: retained issuer revocation reason is invalid")
	}
	return s.SetCertificateRevokedTx(ctx, tx, tenantID, fingerprint, string(canonicalReason), canonicalAt)
}

// EnsureCertificateCRLPublicationTx preserves delivered work on replay and
// refuses a colliding command instead of overwriting a different outbox intent.
func (s *Store) EnsureCertificateCRLPublicationTx(ctx context.Context, tx pgx.Tx, tenantID, eventID, caID string) error {
	if tenantID == "" || eventID == "" || caID == "" {
		return fmt.Errorf("store: CRL publication requires tenant, event and authority")
	}
	payload, err := json.Marshal(CertificateCRLPublication{EventID: eventID, CAID: caID})
	if err != nil {
		return err
	}
	key := CertificateCRLPublicationDestination + ":" + eventID + ":" + caID
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, tenantID+"\x1f"+key); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
		SELECT $1, $2, $2, $3, $4 WHERE NOT EXISTS
		(SELECT 1 FROM outbox WHERE tenant_id = $1 AND idempotency_key = $4)`,
		tenantID, CertificateCRLPublicationDestination, payload, key)
	if err != nil || tag.RowsAffected() == 1 {
		return err
	}
	var destination, lane string
	var existing []byte
	if err := tx.QueryRow(ctx, `SELECT destination, COALESCE(NULLIF(effect_lane, ''), destination), payload
		FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2 ORDER BY id LIMIT 1`,
		tenantID, key).Scan(&destination, &lane, &existing); err != nil {
		return err
	}
	if destination != CertificateCRLPublicationDestination || lane != destination || !bytes.Equal(payload, existing) {
		return fmt.Errorf("%w: certificate CRL publication command differs", ErrIdempotencyConflict)
	}
	return nil
}
