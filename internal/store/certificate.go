// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"fmt"
	"strings"
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
	CertificatePEM         []byte
	IssuanceResponse       []byte
	IssuanceIdempotencyKey string
	IssuanceRequestBinding string
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

// IssuedCertificateRecovery is the durable public result and authenticated
// command binding for one external-CA issuance. The certificate chain is public;
// no key material is stored here.
type IssuedCertificateRecovery struct {
	CertificatePEM []byte
	Response       []byte
	Serial         string
	Issuer         string
	NotAfter       *time.Time
	RequestBinding string
}

// CertificateHealthSnapshot is the tenant-scoped estate-wide read model for
// certificate expiry and origin posture. It includes certificates recorded from
// served issuance, manual import, and discovery sources; callers should not treat
// source="issued" as the only inventory denominator.
type CertificateHealthSnapshot struct {
	GeneratedAt     time.Time
	Summary         CertificateHealthSummary
	ExpiryBuckets   []CertificateExpiryBucket
	SourceBreakdown []CertificateSourceHealth
	Expiring        []Certificate
}

type CertificateHealthSummary struct {
	Total       int
	Active      int
	Revoked     int
	Superseded  int
	Expired     int
	Expiring7d  int
	Expiring30d int
	Expiring90d int
	// Long-horizon counts (H5). The dashboard used to stop at 90 days and call
	// everything past it "later", which is the right resolution for a leaf and
	// useless for a CA: a root expiring in 30 months reads identically to one
	// expiring in 30 years. These are cumulative, like the shorter windows above.
	Expiring180d        int
	Expiring1y          int
	Expiring2y          int
	Expiring3y          int
	ExternalSourceCount int
	ImportedCount       int
	DiscoveredCount     int
	UnknownExpiryCount  int
}

type CertificateExpiryBucket struct {
	Name  string
	Count int
}

type CertificateSourceHealth struct {
	Source      string
	Count       int
	External    bool
	Expired     int
	Expiring30d int
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
	certPEM := c.CertificatePEM
	if certPEM == nil {
		certPEM = []byte{}
	}
	issuanceResponse := c.IssuanceResponse
	if issuanceResponse == nil {
		issuanceResponse = []byte{}
	}
	err := s.WithTenant(ctx, c.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO certificates
			        (id, tenant_id, owner_id, subject, sans, issuer, serial, fingerprint,
			         key_algorithm, not_before, not_after, deployment_location, source,
			         certificate_der, certificate_pem, issuance_response,
			         issuance_idempotency_key, issuance_request_binding)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
			 ON CONFLICT (tenant_id, fingerprint) DO UPDATE
			    SET owner_id = EXCLUDED.owner_id, subject = EXCLUDED.subject, sans = EXCLUDED.sans,
			        issuer = EXCLUDED.issuer, serial = EXCLUDED.serial, key_algorithm = EXCLUDED.key_algorithm,
			        not_before = EXCLUDED.not_before, not_after = EXCLUDED.not_after,
			        deployment_location = EXCLUDED.deployment_location, source = EXCLUDED.source,
			        certificate_der = CASE WHEN octet_length(EXCLUDED.certificate_der) > 0 THEN EXCLUDED.certificate_der ELSE certificates.certificate_der END,
			        certificate_pem = CASE WHEN octet_length(EXCLUDED.certificate_pem) > 0 THEN EXCLUDED.certificate_pem ELSE certificates.certificate_pem END,
			        issuance_response = CASE WHEN octet_length(EXCLUDED.issuance_response) > 0 THEN EXCLUDED.issuance_response ELSE certificates.issuance_response END,
			        issuance_idempotency_key = CASE WHEN EXCLUDED.issuance_idempotency_key <> '' THEN EXCLUDED.issuance_idempotency_key ELSE certificates.issuance_idempotency_key END,
			        issuance_request_binding = CASE WHEN EXCLUDED.issuance_request_binding <> '' THEN EXCLUDED.issuance_request_binding ELSE certificates.issuance_request_binding END
			 RETURNING id::text, created_at`,
			c.TenantID, c.OwnerID, c.Subject, sans, c.Issuer, c.Serial, c.Fingerprint,
			c.KeyAlgorithm, c.NotBefore, c.NotAfter, c.DeploymentLocation, c.Source,
			certDER, certPEM, issuanceResponse, c.IssuanceIdempotencyKey, c.IssuanceRequestBinding).
			Scan(&c.ID, &c.CreatedAt)
	})
	c.SANs = sans
	c.CertificateDER = certDER
	c.CertificatePEM = certPEM
	c.IssuanceResponse = issuanceResponse
	return c, err
}

// CertificateHealth returns a bounded estate-wide expiry/health dashboard. All
// counts are computed from tenant-scoped certificate inventory rows under RLS
// (AN-1); no source is excluded, so certificates issued elsewhere and later
// imported/discovered count in the same dashboard as trstctl-issued certificates.
func (s *Store) CertificateHealth(ctx context.Context, tenantID string, now time.Time, expiringLimit int) (CertificateHealthSnapshot, error) {
	if expiringLimit <= 0 || expiringLimit > 100 {
		expiringLimit = 25
	}
	now = now.UTC()
	soon7 := now.Add(7 * 24 * time.Hour)
	soon30 := now.Add(30 * 24 * time.Hour)
	soon90 := now.Add(90 * 24 * time.Hour)
	// The long-horizon boundaries (H5). "later" keeps its name and its place at
	// the end of the partition, but it now means "beyond three years" rather than
	// "beyond ninety days" — the 90-day ceiling is exactly what hid multi-year CA
	// expiry. The buckets remain a partition, so a consumer summing them still
	// gets the total.
	soon180 := now.Add(180 * 24 * time.Hour)
	soon1y := now.Add(365 * 24 * time.Hour)
	soon2y := now.Add(2 * 365 * 24 * time.Hour)
	soon3y := now.Add(3 * 365 * 24 * time.Hour)
	snap := CertificateHealthSnapshot{
		GeneratedAt: now,
		ExpiryBuckets: []CertificateExpiryBucket{
			{Name: "expired"},
			{Name: "expiring_7d"},
			{Name: "expiring_30d"},
			{Name: "expiring_90d"},
			{Name: "expiring_180d"},
			{Name: "expiring_1y"},
			{Name: "expiring_2y"},
			{Name: "expiring_3y"},
			{Name: "later"},
			{Name: "unknown"},
		},
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT
			    COUNT(*),
			    COUNT(*) FILTER (WHERE status = 'active'),
			    COUNT(*) FILTER (WHERE status = 'revoked'),
			    COUNT(*) FILTER (WHERE status = 'superseded'),
			    COUNT(*) FILTER (WHERE not_after IS NOT NULL AND not_after < $2),
			    COUNT(*) FILTER (WHERE not_after IS NOT NULL AND not_after >= $2 AND not_after < $3),
			    COUNT(*) FILTER (WHERE not_after IS NOT NULL AND not_after >= $2 AND not_after < $4),
			    COUNT(*) FILTER (WHERE not_after IS NOT NULL AND not_after >= $2 AND not_after < $5),
			    COUNT(*) FILTER (WHERE COALESCE(source, '') <> 'issued'),
			    COUNT(*) FILTER (WHERE COALESCE(source, '') IN ('import', 'manual', 'manual-ui')),
			    COUNT(*) FILTER (WHERE COALESCE(source, '') LIKE 'discovery:%'),
			    COUNT(*) FILTER (WHERE not_after IS NULL),
			    COUNT(*) FILTER (WHERE not_after IS NOT NULL AND not_after >= $2 AND not_after < $6),
			    COUNT(*) FILTER (WHERE not_after IS NOT NULL AND not_after >= $2 AND not_after < $7),
			    COUNT(*) FILTER (WHERE not_after IS NOT NULL AND not_after >= $2 AND not_after < $8),
			    COUNT(*) FILTER (WHERE not_after IS NOT NULL AND not_after >= $2 AND not_after < $9),
			    COUNT(*) FILTER (WHERE not_after IS NOT NULL AND not_after >= $9)
			   FROM certificates
			  WHERE tenant_id = $1`,
			tenantID, now, soon7, soon30, soon90, soon180, soon1y, soon2y, soon3y).
			Scan(
				&snap.Summary.Total,
				&snap.Summary.Active,
				&snap.Summary.Revoked,
				&snap.Summary.Superseded,
				&snap.Summary.Expired,
				&snap.Summary.Expiring7d,
				&snap.Summary.Expiring30d,
				&snap.Summary.Expiring90d,
				&snap.Summary.ExternalSourceCount,
				&snap.Summary.ImportedCount,
				&snap.Summary.DiscoveredCount,
				&snap.Summary.UnknownExpiryCount,
				&snap.Summary.Expiring180d,
				&snap.Summary.Expiring1y,
				&snap.Summary.Expiring2y,
				&snap.Summary.Expiring3y,
				&snap.ExpiryBuckets[8].Count,
			); err != nil {
			return err
		}
		// Each bucket is the slice between its boundary and the previous one, so
		// the partition sums to the total. Cumulative counts come off the summary.
		snap.ExpiryBuckets[0].Count = snap.Summary.Expired
		snap.ExpiryBuckets[1].Count = snap.Summary.Expiring7d
		snap.ExpiryBuckets[2].Count = snap.Summary.Expiring30d - snap.Summary.Expiring7d
		snap.ExpiryBuckets[3].Count = snap.Summary.Expiring90d - snap.Summary.Expiring30d
		snap.ExpiryBuckets[4].Count = snap.Summary.Expiring180d - snap.Summary.Expiring90d
		snap.ExpiryBuckets[5].Count = snap.Summary.Expiring1y - snap.Summary.Expiring180d
		snap.ExpiryBuckets[6].Count = snap.Summary.Expiring2y - snap.Summary.Expiring1y
		snap.ExpiryBuckets[7].Count = snap.Summary.Expiring3y - snap.Summary.Expiring2y
		snap.ExpiryBuckets[9].Count = snap.Summary.UnknownExpiryCount
		for i := 2; i <= 7; i++ {
			if snap.ExpiryBuckets[i].Count < 0 {
				snap.ExpiryBuckets[i].Count = 0
			}
		}

		rows, err := tx.Query(ctx,
			`SELECT COALESCE(NULLIF(source, ''), 'unknown') AS source,
			        COUNT(*),
			        COUNT(*) FILTER (WHERE not_after IS NOT NULL AND not_after < $2),
			        COUNT(*) FILTER (WHERE not_after IS NOT NULL AND not_after >= $2 AND not_after < $3)
			   FROM certificates
			  WHERE tenant_id = $1
			  GROUP BY COALESCE(NULLIF(source, ''), 'unknown')
			  ORDER BY COUNT(*) DESC, source`,
			tenantID, now, soon30)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row CertificateSourceHealth
			if err := rows.Scan(&row.Source, &row.Count, &row.Expired, &row.Expiring30d); err != nil {
				return err
			}
			row.External = certificateSourceExternal(row.Source)
			snap.SourceBreakdown = append(snap.SourceBreakdown, row)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		const cols = `id::text, tenant_id::text, owner_id::text, subject, sans, issuer, serial,
		        fingerprint, key_algorithm, not_before, not_after, deployment_location, source,
		        certificate_der, issuance_idempotency_key, created_at,
		        status, replaces_id::text, revoked_at, revocation_reason, renewed_at, alerted_at`
		expiringRows, err := tx.Query(ctx,
			`SELECT `+cols+`
			   FROM certificates
			  WHERE tenant_id = $1 AND not_after IS NOT NULL AND not_after < $2
			  ORDER BY not_after, id LIMIT $3`,
			tenantID, soon90, expiringLimit)
		if err != nil {
			return err
		}
		defer expiringRows.Close()
		for expiringRows.Next() {
			var c Certificate
			if err := scanCertificate(expiringRows, &c); err != nil {
				return err
			}
			snap.Expiring = append(snap.Expiring, c)
		}
		return expiringRows.Err()
	})
	return snap, err
}

func certificateSourceExternal(source string) bool {
	source = strings.TrimSpace(strings.ToLower(source))
	return source == "" || source != "issued"
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

// GetIssuedCertificateRecovery returns the single projected result for an
// issuance key. More than one row fails closed because a supposedly idempotent
// command cannot have two authoritative certificates.
func (s *Store) GetIssuedCertificateRecovery(ctx context.Context, tenantID, key string) (IssuedCertificateRecovery, error) {
	var out IssuedCertificateRecovery
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT certificate_pem, issuance_response, serial, issuer, not_after, issuance_request_binding
			   FROM certificates
			  WHERE tenant_id = $1 AND issuance_idempotency_key = $2
			  ORDER BY created_at, id
			  LIMIT 2`, tenantID, key)
		if err != nil {
			return err
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			count++
			if count > 1 {
				return fmt.Errorf("%w: issuance key has multiple certificate results", ErrIdempotencyConflict)
			}
			if err := rows.Scan(&out.CertificatePEM, &out.Response, &out.Serial, &out.Issuer, &out.NotAfter, &out.RequestBinding); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if count == 0 {
			return pgx.ErrNoRows
		}
		return nil
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
