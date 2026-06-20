package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// This file holds the certificate-lifecycle repository methods (F6, S4.5): the
// alert bookkeeping plus the scans that drive renewal and expiry alerting. The
// mutating methods take the caller's transaction so the state change and its
// outbox entry (AN-6) commit atomically. All queries are tenant-scoped (AN-1).
//
// Certificate status transitions (successor recorded, predecessor superseded,
// revoked) are NOT written here as direct read-table UPDATEs — that was the
// CORRECT-002 defect, where the emitted events had no projector case and the
// status was lost on a Rebuild(). Those transitions are now event-sourced through
// the orchestrator (RecordSuccessorCertificate / SupersedeCertificate /
// RevokeCertificate) and applied by the projector — the sole read-model writer
// (AN-2) — so they are reconstructable from the log. The alert stamp below is a
// projection-side annotation (not a lifecycle status), so it remains a direct
// write here.

// MarkCertificateAlertedTx stamps alerted_at, on the caller's tx, so an expiry
// alert is emitted to the notification surface at most once per certificate.
func (s *Store) MarkCertificateAlertedTx(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE certificates SET alerted_at = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, at)
	return err
}

// ListExpiringActiveCertificates returns active certificates whose not_after is
// before the cutoff, oldest expiry first — the renewal scan's input.
func (s *Store) ListExpiringActiveCertificates(ctx context.Context, tenantID string, before time.Time) ([]Certificate, error) {
	var out []Certificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, owner_id::text, subject, sans, issuer, serial,
			        fingerprint, key_algorithm, not_before, not_after, deployment_location, source,
			        certificate_der, issuance_idempotency_key, created_at,
			        status, replaces_id::text, revoked_at, revocation_reason, renewed_at, alerted_at
			   FROM certificates
			  WHERE tenant_id = $1 AND status = 'active'
			    AND not_after IS NOT NULL AND not_after < $2
			  ORDER BY not_after`,
			tenantID, before)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c Certificate
			if err := scanCertificate(rows, &c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// ListAlertableCertificates returns active certificates expiring within the
// window (now, before) that have not yet been alerted — the expiry-alert scan's
// input. Already-expired certs (not_after < now) are excluded: alerts fire
// before expiry.
func (s *Store) ListAlertableCertificates(ctx context.Context, tenantID string, now, before time.Time) ([]Certificate, error) {
	var out []Certificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, owner_id::text, subject, sans, issuer, serial,
			        fingerprint, key_algorithm, not_before, not_after, deployment_location, source,
			        certificate_der, issuance_idempotency_key, created_at,
			        status, replaces_id::text, revoked_at, revocation_reason, renewed_at, alerted_at
			   FROM certificates
			  WHERE tenant_id = $1 AND status = 'active' AND alerted_at IS NULL
			    AND not_after IS NOT NULL AND not_after >= $2 AND not_after < $3
			  ORDER BY not_after`,
			tenantID, now, before)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c Certificate
			if err := scanCertificate(rows, &c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
