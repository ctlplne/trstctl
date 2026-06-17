package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// This file holds the revocation repositories (F47, S4.16): the issued/revoked
// certificate records that back the OCSP responder, and the published CRLs. Every
// query is tenant-scoped under row-level security (AN-1).

// IssuedCert is an internally-issued certificate and its revocation status.
type IssuedCert struct {
	TenantID   string
	CAID       string
	Serial     string
	IssuedAt   time.Time
	RevokedAt  *time.Time
	ReasonCode int
}

// Revoked reports whether the certificate has been revoked.
func (c IssuedCert) Revoked() bool { return c.RevokedAt != nil }

// RecordIssuedCert records that the internal CA issued a certificate with the
// given serial (idempotent).
func (s *Store) RecordIssuedCert(ctx context.Context, tenantID, caID, serial string, issuedAt time.Time) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO ca_issued_certs (tenant_id, ca_id, serial, issued_at)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (tenant_id, ca_id, serial) DO NOTHING`,
			tenantID, caID, serial, issuedAt)
		return err
	})
}

// RevokeIssuedCert marks a serial revoked (recording it if not already known),
// keeping the first revocation time on a repeat (idempotent).
func (s *Store) RevokeIssuedCert(ctx context.Context, tenantID, caID, serial string, reasonCode int, at time.Time) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO ca_issued_certs (tenant_id, ca_id, serial, revoked_at, reason_code)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (tenant_id, ca_id, serial) DO UPDATE
			    SET revoked_at = EXCLUDED.revoked_at, reason_code = EXCLUDED.reason_code
			  WHERE ca_issued_certs.revoked_at IS NULL`,
			tenantID, caID, serial, at, reasonCode)
		return err
	})
}

// LookupIssuedCert returns the issued-certificate record for a serial and whether
// it was found.
func (s *Store) LookupIssuedCert(ctx context.Context, tenantID, caID, serial string) (IssuedCert, bool, error) {
	var c IssuedCert
	found := true
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT tenant_id::text, ca_id::text, serial, issued_at, revoked_at, reason_code
			   FROM ca_issued_certs WHERE tenant_id = $1 AND ca_id = $2 AND serial = $3`,
			tenantID, caID, serial)
		switch err := row.Scan(&c.TenantID, &c.CAID, &c.Serial, &c.IssuedAt, &c.RevokedAt, &c.ReasonCode); {
		case IsNotFound(err):
			found = false
			return nil
		default:
			return err
		}
	})
	return c, found, err
}

// HasIssuedCerts reports whether tenantID has any issued-certificate surface for
// caID. The served CRL code uses this as the public-read gate: a tenant path with
// no issued certs must not be able to mint CRL rows just by being requested.
func (s *Store) HasIssuedCerts(ctx context.Context, tenantID, caID string) (bool, error) {
	var ok bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			    SELECT 1 FROM ca_issued_certs WHERE tenant_id = $1 AND ca_id = $2
			)`,
			tenantID, caID).Scan(&ok)
	})
	return ok, err
}

// ListRevokedCerts returns a CA's revoked certificates (for CRL generation).
func (s *Store) ListRevokedCerts(ctx context.Context, tenantID, caID string) ([]IssuedCert, error) {
	var out []IssuedCert
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, ca_id::text, serial, issued_at, revoked_at, reason_code
			   FROM ca_issued_certs
			  WHERE tenant_id = $1 AND ca_id = $2 AND revoked_at IS NOT NULL
			  ORDER BY revoked_at`,
			tenantID, caID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c IssuedCert
			if err := rows.Scan(&c.TenantID, &c.CAID, &c.Serial, &c.IssuedAt, &c.RevokedAt, &c.ReasonCode); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// CRL is a published certificate revocation list.
type CRL struct {
	TenantID   string
	CAID       string
	Number     int64
	DER        []byte
	ThisUpdate time.Time
	NextUpdate time.Time
	CreatedAt  time.Time
}

// NextCRLNumber returns the next CRL number for a CA (1 + the highest published).
func (s *Store) NextCRLNumber(ctx context.Context, tenantID, caID string) (int64, error) {
	var n int64
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COALESCE(max(crl_number), 0) + 1 FROM ca_crls WHERE tenant_id = $1 AND ca_id = $2`,
			tenantID, caID).Scan(&n)
	})
	return n, err
}

// InsertCRL publishes a generated CRL.
func (s *Store) InsertCRL(ctx context.Context, c CRL) error {
	return s.WithTenant(ctx, c.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO ca_crls (tenant_id, ca_id, crl_number, crl_der, this_update, next_update)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			c.TenantID, c.CAID, c.Number, c.DER, c.ThisUpdate, c.NextUpdate)
		return err
	})
}

// TenantsWithIssuedCerts returns the distinct tenant IDs that have at least one
// certificate recorded under caID, so the served CRL freshness scheduler
// regenerates a CRL only for tenants that actually have a revocation surface (it
// does not mint empty CRLs for every registered tenant). It is a system
// (cross-tenant) operation, the same RLS-exempt pattern ListTenants uses: it
// enumerates which tenants exist for a shared issuing CA, not any tenant's data.
func (s *Store) TenantsWithIssuedCerts(ctx context.Context, caID string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates which tenants have rows under a shared issuing CA so the CRL scheduler can regenerate per tenant; runs on the pool, not under RLS (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM ca_issued_certs WHERE ca_id = $1 ORDER BY tenant_id`,
		caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CRLDueForRegeneration reports whether the CA's latest published CRL is missing
// or will expire within lead (so the scheduler regenerates ahead of nextUpdate,
// keeping the served CRL fresh). It is tenant-scoped under RLS (AN-1).
func (s *Store) CRLDueForRegeneration(ctx context.Context, tenantID, caID string, now time.Time, lead time.Duration) (bool, error) {
	crl, found, err := s.LatestCRL(ctx, tenantID, caID)
	if err != nil {
		return false, err
	}
	if !found {
		return true, nil
	}
	return !crl.NextUpdate.After(now.Add(lead)), nil
}

// LatestCRL returns the most recently published CRL for a CA and whether one
// exists.
func (s *Store) LatestCRL(ctx context.Context, tenantID, caID string) (CRL, bool, error) {
	var c CRL
	found := true
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT tenant_id::text, ca_id::text, crl_number, crl_der, this_update, next_update, created_at
			   FROM ca_crls WHERE tenant_id = $1 AND ca_id = $2
			  ORDER BY crl_number DESC LIMIT 1`,
			tenantID, caID)
		switch err := row.Scan(&c.TenantID, &c.CAID, &c.Number, &c.DER, &c.ThisUpdate, &c.NextUpdate, &c.CreatedAt); {
		case IsNotFound(err):
			found = false
			return nil
		default:
			return err
		}
	})
	return c, found, err
}
