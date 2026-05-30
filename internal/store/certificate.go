package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Certificate is an inventoried certificate's metadata (F1). It is keyed within a
// tenant by its fingerprint, so re-ingesting the same certificate refreshes the
// existing row rather than duplicating it.
type Certificate struct {
	ID                 string
	TenantID           string
	OwnerID            *string
	Subject            string
	SANs               []string
	Issuer             string
	Serial             string
	Fingerprint        string
	KeyAlgorithm       string
	NotBefore          *time.Time
	NotAfter           *time.Time
	DeploymentLocation string
	Source             string
	CreatedAt          time.Time

	// Lifecycle bookkeeping (S4.5). Status is one of active, superseded,
	// revoked. ReplacesID links a rotation's successor to the credential it
	// supersedes. The timestamps make renewal and alerting idempotent.
	Status           string
	ReplacesID       *string
	RevokedAt        *time.Time
	RevocationReason string
	RenewedAt        *time.Time
	AlertedAt        *time.Time
}

// UpsertCertificate inserts or refreshes a certificate by (tenant, fingerprint),
// returning it with its id and created_at. Tenant-scoped (RLS-enforced).
func (s *Store) UpsertCertificate(ctx context.Context, c Certificate) (Certificate, error) {
	sans := c.SANs
	if sans == nil {
		sans = []string{}
	}
	err := s.WithTenant(ctx, c.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO certificates
			        (id, tenant_id, owner_id, subject, sans, issuer, serial, fingerprint,
			         key_algorithm, not_before, not_after, deployment_location, source)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			 ON CONFLICT (tenant_id, fingerprint) DO UPDATE
			    SET owner_id = EXCLUDED.owner_id, subject = EXCLUDED.subject, sans = EXCLUDED.sans,
			        issuer = EXCLUDED.issuer, serial = EXCLUDED.serial, key_algorithm = EXCLUDED.key_algorithm,
			        not_before = EXCLUDED.not_before, not_after = EXCLUDED.not_after,
			        deployment_location = EXCLUDED.deployment_location, source = EXCLUDED.source
			 RETURNING id::text, created_at`,
			c.TenantID, c.OwnerID, c.Subject, sans, c.Issuer, c.Serial, c.Fingerprint,
			c.KeyAlgorithm, c.NotBefore, c.NotAfter, c.DeploymentLocation, c.Source).
			Scan(&c.ID, &c.CreatedAt)
	})
	c.SANs = sans
	return c, err
}

func scanCertificate(row pgx.Row, c *Certificate) error {
	return row.Scan(&c.ID, &c.TenantID, &c.OwnerID, &c.Subject, &c.SANs, &c.Issuer, &c.Serial,
		&c.Fingerprint, &c.KeyAlgorithm, &c.NotBefore, &c.NotAfter, &c.DeploymentLocation, &c.Source, &c.CreatedAt,
		&c.Status, &c.ReplacesID, &c.RevokedAt, &c.RevocationReason, &c.RenewedAt, &c.AlertedAt)
}

// GetCertificate loads a certificate in its tenant context.
func (s *Store) GetCertificate(ctx context.Context, tenantID, id string) (Certificate, error) {
	var c Certificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanCertificate(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, owner_id::text, subject, sans, issuer, serial,
			        fingerprint, key_algorithm, not_before, not_after, deployment_location, source, created_at,
			        status, replaces_id::text, revoked_at, revocation_reason, renewed_at, alerted_at
			   FROM certificates WHERE tenant_id = $1 AND id = $2`, tenantID, id), &c)
	})
	return c, err
}

// CertificateExists reports whether the tenant's inventory already contains a
// certificate matching the given fingerprint, or the given issuer-and-serial
// pair. CT monitoring (F17) uses it to separate expected issuance (already
// inventoried) from shadow IT: a CT entry is matched by fingerprint when it is
// the final certificate, and by issuer+serial when it is a precertificate
// (whose fingerprint differs from the certificate eventually issued). Empty
// inputs never match, so an all-empty query cannot report everything as known.
func (s *Store) CertificateExists(ctx context.Context, tenantID, fingerprint, issuer, serial string) (bool, error) {
	var exists bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			    SELECT 1 FROM certificates
			     WHERE tenant_id = $1
			       AND ( ($2 <> '' AND fingerprint = $2)
			          OR ($3 <> '' AND $4 <> '' AND issuer = $3 AND serial = $4) )
			 )`, tenantID, fingerprint, issuer, serial).Scan(&exists)
	})
	return exists, err
}

// ListCertificatesPage returns up to limit certificates with id greater than
// afterID (keyset pagination; pass ZeroUUID for the first page). When
// expiringBefore is non-nil, only certificates whose not_after is before it are
// returned.
func (s *Store) ListCertificatesPage(ctx context.Context, tenantID, afterID string, limit int, expiringBefore *time.Time) ([]Certificate, error) {
	var out []Certificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, owner_id::text, subject, sans, issuer, serial,
			        fingerprint, key_algorithm, not_before, not_after, deployment_location, source, created_at,
			        status, replaces_id::text, revoked_at, revocation_reason, renewed_at, alerted_at
			   FROM certificates
			  WHERE tenant_id = $1 AND id > $2
			    AND ($3::timestamptz IS NULL OR not_after < $3)
			  ORDER BY id LIMIT $4`,
			tenantID, afterID, expiringBefore, limit)
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
