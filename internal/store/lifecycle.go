package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// This file holds the certificate-lifecycle repository methods (F6, S4.5):
// inserting a rotation's successor, retiring the predecessor, revoking, and the
// alert bookkeeping, plus the scans that drive renewal and expiry alerting. The
// mutating methods take the caller's transaction so the state change and its
// outbox entry (AN-6) commit atomically. All queries are tenant-scoped (AN-1).

// InsertSuccessorCertificateTx inserts the certificate produced by a renewal or
// rotation, marking it active and linking it to the credential it replaces, on
// the caller's transaction. It is keyed by (tenant, fingerprint) so re-running a
// renewal whose mint was idempotently cached refreshes the same successor row
// rather than creating a duplicate. Returns the successor's id.
func (s *Store) InsertSuccessorCertificateTx(ctx context.Context, tx pgx.Tx, c Certificate, replacesID string) (string, error) {
	sans := c.SANs
	if sans == nil {
		sans = []string{}
	}
	var id string
	err := tx.QueryRow(ctx,
		`INSERT INTO certificates
		        (id, tenant_id, owner_id, subject, sans, issuer, serial, fingerprint,
		         key_algorithm, not_before, not_after, deployment_location, source, status, replaces_id)
		 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'active', $13)
		 ON CONFLICT (tenant_id, fingerprint) DO UPDATE
		    SET owner_id = EXCLUDED.owner_id, subject = EXCLUDED.subject, sans = EXCLUDED.sans,
		        issuer = EXCLUDED.issuer, serial = EXCLUDED.serial, key_algorithm = EXCLUDED.key_algorithm,
		        not_before = EXCLUDED.not_before, not_after = EXCLUDED.not_after,
		        deployment_location = EXCLUDED.deployment_location, source = EXCLUDED.source,
		        status = 'active', replaces_id = EXCLUDED.replaces_id, revoked_at = NULL,
		        revocation_reason = '', renewed_at = NULL
		 RETURNING id::text`,
		c.TenantID, c.OwnerID, c.Subject, sans, c.Issuer, c.Serial, c.Fingerprint,
		c.KeyAlgorithm, c.NotBefore, c.NotAfter, c.DeploymentLocation, c.Source, replacesID).
		Scan(&id)
	return id, err
}

// SupersedeCertificateTx retires a certificate that has been renewed/rotated:
// status becomes superseded and renewed_at is stamped, on the caller's tx.
func (s *Store) SupersedeCertificateTx(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE certificates SET status = 'superseded', renewed_at = $3
		   WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, at)
	return err
}

// RevokeCertificateTx marks a certificate revoked with its reason and timestamp,
// on the caller's tx (so the revocation.publish outbox entry commits with it).
func (s *Store) RevokeCertificateTx(ctx context.Context, tx pgx.Tx, tenantID, id, reason string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE certificates SET status = 'revoked', revoked_at = $3, revocation_reason = $4
		   WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, at, reason)
	return err
}

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
			        fingerprint, key_algorithm, not_before, not_after, deployment_location, source, created_at,
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
			        fingerprint, key_algorithm, not_before, not_after, deployment_location, source, created_at,
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
