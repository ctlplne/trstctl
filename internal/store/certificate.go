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
	ID       string
	TenantID string
	// CAID is not stored on the inventory row. Served issuance sets it so the
	// certificate.recorded event can also rebuild the OCSP/CRL responder row.
	CAID                   string
	OwnerID                *string
	Subject                string
	SANs                   []string
	Issuer                 string
	Serial                 string
	Fingerprint            string
	KeyAlgorithm           string
	NotBefore              *time.Time
	NotAfter               *time.Time
	DeploymentLocation     string
	Source                 string
	CertificateDER         []byte
	IssuanceIdempotencyKey string
	CreatedAt              time.Time

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
	certDER := c.CertificateDER
	if certDER == nil {
		certDER = []byte{}
	}
	err := s.WithTenant(ctx, c.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO certificates
			        (id, tenant_id, owner_id, subject, sans, issuer, serial, fingerprint,
			         key_algorithm, not_before, not_after, deployment_location, source,
			         certificate_der, issuance_idempotency_key)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			 ON CONFLICT (tenant_id, fingerprint) DO UPDATE
			    SET owner_id = EXCLUDED.owner_id, subject = EXCLUDED.subject, sans = EXCLUDED.sans,
			        issuer = EXCLUDED.issuer, serial = EXCLUDED.serial, key_algorithm = EXCLUDED.key_algorithm,
			        not_before = EXCLUDED.not_before, not_after = EXCLUDED.not_after,
			        deployment_location = EXCLUDED.deployment_location, source = EXCLUDED.source,
			        certificate_der = EXCLUDED.certificate_der,
			        issuance_idempotency_key = EXCLUDED.issuance_idempotency_key
			 RETURNING id::text, created_at`,
			c.TenantID, c.OwnerID, c.Subject, sans, c.Issuer, c.Serial, c.Fingerprint,
			c.KeyAlgorithm, c.NotBefore, c.NotAfter, c.DeploymentLocation, c.Source,
			certDER, c.IssuanceIdempotencyKey).
			Scan(&c.ID, &c.CreatedAt)
	})
	c.SANs = sans
	c.CertificateDER = certDER
	return c, err
}

func scanCertificate(row pgx.Row, c *Certificate) error {
	return row.Scan(&c.ID, &c.TenantID, &c.OwnerID, &c.Subject, &c.SANs, &c.Issuer, &c.Serial,
		&c.Fingerprint, &c.KeyAlgorithm, &c.NotBefore, &c.NotAfter, &c.DeploymentLocation, &c.Source,
		&c.CertificateDER, &c.IssuanceIdempotencyKey, &c.CreatedAt,
		&c.Status, &c.ReplacesID, &c.RevokedAt, &c.RevocationReason, &c.RenewedAt, &c.AlertedAt)
}

// GetCertificate loads a certificate in its tenant context.
func (s *Store) GetCertificate(ctx context.Context, tenantID, id string) (Certificate, error) {
	var c Certificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanCertificate(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, owner_id::text, subject, sans, issuer, serial,
			        fingerprint, key_algorithm, not_before, not_after, deployment_location, source,
			        certificate_der, issuance_idempotency_key, created_at,
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

// ListActiveIssuedCertificatesForIdentity returns the active, internally-issued
// certificates that belong to an identity, matched by the identity's owner and
// its name appearing as a DNS SAN. The served mint sets owner_id =
// identity.owner, source = "issued", and DNS SAN = identity.name (the subject is
// stored as the full DN "CN=<name>", so the name is matched against the SANs, not
// the subject string). The served revocation handler uses it to find the cert(s)
// to revoke when an identity transitions to revoked. Only active certs are
// returned, so a superseded or already-revoked row is left untouched. Tenant
// scoped under RLS (AN-1).
func (s *Store) ListActiveIssuedCertificatesForIdentity(ctx context.Context, tenantID, ownerID, name string) ([]Certificate, error) {
	var out []Certificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, owner_id::text, subject, sans, issuer, serial,
			        fingerprint, key_algorithm, not_before, not_after, deployment_location, source,
			        certificate_der, issuance_idempotency_key, created_at,
			        status, replaces_id::text, revoked_at, revocation_reason, renewed_at, alerted_at
			   FROM certificates
			  WHERE tenant_id = $1 AND owner_id = $2 AND $3 = ANY(sans)
			    AND source = 'issued' AND status = 'active'
			  ORDER BY created_at`,
			tenantID, ownerID, name)
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

// ListCertificatesByIssuanceIdempotencyKey returns certificates recorded by the
// same served issuance attempt. The key is projected from certificate.recorded
// events, so a retry after a crash can recover the already-minted result before
// reaching the signer again (CORRECT-001).
func (s *Store) ListCertificatesByIssuanceIdempotencyKey(ctx context.Context, tenantID, key string) ([]Certificate, error) {
	if key == "" {
		return nil, nil
	}
	var out []Certificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, owner_id::text, subject, sans, issuer, serial,
			        fingerprint, key_algorithm, not_before, not_after, deployment_location, source,
			        certificate_der, issuance_idempotency_key, created_at,
			        status, replaces_id::text, revoked_at, revocation_reason, renewed_at, alerted_at
			   FROM certificates
			  WHERE tenant_id = $1 AND issuance_idempotency_key = $2
			  ORDER BY created_at, id`,
			tenantID, key)
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

// ListCertificatesPage returns up to limit certificates using keyset pagination
// (SPINE-006). The cursor is (afterNotAfter, afterID); pass ZeroUUID/nil for the
// first page.
//
// When expiringBefore is non-nil it returns only certificates whose not_after is
// before it, ordered by (not_after, id) and keyset on that pair, so the query rides
// the (tenant_id, not_after, id) expiry index (migration 0022) instead of scanning
// the primary key and discarding non-matching rows. When expiringBefore is nil it
// returns all certificates ordered by id, keyset on id alone (the plain page rides
// the primary key). Tenant-scoped under RLS (AN-1).
func (s *Store) ListCertificatesPage(ctx context.Context, tenantID, afterID string, afterNotAfter *time.Time, limit int, expiringBefore *time.Time) ([]Certificate, error) {
	const cols = `id::text, tenant_id::text, owner_id::text, subject, sans, issuer, serial,
	        fingerprint, key_algorithm, not_before, not_after, deployment_location, source,
	        certificate_der, issuance_idempotency_key, created_at,
	        status, replaces_id::text, revoked_at, revocation_reason, renewed_at, alerted_at`
	var out []Certificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var rows pgx.Rows
		var qerr error
		switch {
		case expiringBefore != nil && afterNotAfter != nil:
			// Expiry-ordered keyset (subsequent pages): walk (not_after, id) in order so
			// the composite expiry index (tenant_id, not_after, id) serves both the
			// filter and the ordering. The row-value comparison (not_after, id) >
			// (afterNotAfter, afterID) is the keyset. not_after is nullable, but a NULL
			// never satisfies "< expiringBefore", so only non-NULL rows are returned and
			// the comparison is well-defined.
			rows, qerr = tx.Query(ctx,
				`SELECT `+cols+`
				   FROM certificates
				  WHERE tenant_id = $1 AND not_after < $2
				    AND (not_after, id) > ($3, $4)
				  ORDER BY not_after, id LIMIT $5`,
				tenantID, *expiringBefore, *afterNotAfter, afterID, limit)
		case expiringBefore != nil:
			// Expiry-ordered first page: no keyset lower bound yet, just the filter,
			// ordered by (not_after, id) so it rides the same composite index.
			rows, qerr = tx.Query(ctx,
				`SELECT `+cols+`
				   FROM certificates
				  WHERE tenant_id = $1 AND not_after < $2
				  ORDER BY not_after, id LIMIT $3`,
				tenantID, *expiringBefore, limit)
		default:
			// Plain page: keyset on id alone, riding the primary key.
			rows, qerr = tx.Query(ctx,
				`SELECT `+cols+`
				   FROM certificates
				  WHERE tenant_id = $1 AND id > $2
				  ORDER BY id LIMIT $3`,
				tenantID, afterID, limit)
		}
		if qerr != nil {
			return qerr
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
