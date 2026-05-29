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
		&c.Fingerprint, &c.KeyAlgorithm, &c.NotBefore, &c.NotAfter, &c.DeploymentLocation, &c.Source, &c.CreatedAt)
}

// GetCertificate loads a certificate in its tenant context.
func (s *Store) GetCertificate(ctx context.Context, tenantID, id string) (Certificate, error) {
	var c Certificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanCertificate(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, owner_id::text, subject, sans, issuer, serial,
			        fingerprint, key_algorithm, not_before, not_after, deployment_location, source, created_at
			   FROM certificates WHERE tenant_id = $1 AND id = $2`, tenantID, id), &c)
	})
	return c, err
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
			        fingerprint, key_algorithm, not_before, not_after, deployment_location, source, created_at
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
