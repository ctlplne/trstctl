package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

const (
	CRLKindFull  = "full"
	CRLKindShard = "shard"
	CRLKindDelta = "delta"
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
		return s.RecordIssuedCertTx(ctx, tx, tenantID, caID, serial, issuedAt)
	})
}

// RecordIssuedCertTx projects an issued-serial event into the OCSP/CRL read model
// on the caller's transaction. Replaying the same event is idempotent.
func (s *Store) RecordIssuedCertTx(ctx context.Context, tx pgx.Tx, tenantID, caID, serial string, issuedAt time.Time) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO ca_issued_certs (tenant_id, ca_id, serial, issued_at)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (tenant_id, ca_id, serial) DO NOTHING`,
		tenantID, caID, serial, issuedAt.UTC())
	return err
}

// RevokeIssuedCert marks a serial revoked (recording it if not already known),
// keeping the first revocation time on a repeat (idempotent).
func (s *Store) RevokeIssuedCert(ctx context.Context, tenantID, caID, serial string, reasonCode int, at time.Time) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return s.RevokeIssuedCertTx(ctx, tx, tenantID, caID, serial, reasonCode, at)
	})
}

// RevokeIssuedCertTx projects a serial revocation into the OCSP/CRL read model on
// the caller's transaction. A replay keeps the first revocation timestamp.
func (s *Store) RevokeIssuedCertTx(ctx context.Context, tx pgx.Tx, tenantID, caID, serial string, reasonCode int, at time.Time) error {
	if !crypto.ValidCRLReasonCode(reasonCode) {
		return fmt.Errorf("store: invalid RFC 5280 revocation reason code %d", reasonCode)
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO ca_issued_certs (tenant_id, ca_id, serial, issued_at, revoked_at, reason_code)
		 VALUES ($1, $2, $3, $4, $4, $5)
		 ON CONFLICT (tenant_id, ca_id, serial) DO UPDATE
		    SET revoked_at = EXCLUDED.revoked_at, reason_code = EXCLUDED.reason_code
		  WHERE ca_issued_certs.revoked_at IS NULL`,
		tenantID, caID, serial, at.UTC(), reasonCode)
	return err
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
	TenantID        string
	CAID            string
	Number          int64
	DER             []byte
	ThisUpdate      time.Time
	NextUpdate      time.Time
	CreatedAt       time.Time
	Kind            string
	ShardIndex      int
	ShardCount      int
	DeltaBaseNumber *int64
	ParentNumber    *int64
	RevokedCount    int
}

// OCSPResponder is the tenant-scoped active delegated OCSP responder certificate
// for a CA. It is a read-model projection of ca.ocsp_responder.rotated events;
// the event log is the rotation history.
type OCSPResponder struct {
	TenantID          string
	CAID              string
	Serial            string
	CertDER           []byte
	NotBefore         time.Time
	NotAfter          time.Time
	RotatedFromSerial string
	CreatedAt         time.Time
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
		return s.InsertCRLTx(ctx, tx, c)
	})
}

// InsertCRLTx projects a published-CRL event into the OCSP/CRL read model on the
// caller's transaction. Replaying the same CRL number is idempotent.
func (s *Store) InsertCRLTx(ctx context.Context, tx pgx.Tx, c CRL) error {
	c = normalizeCRL(c)
	createdAt := c.CreatedAt
	if createdAt.IsZero() {
		createdAt = c.ThisUpdate
	}
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO ca_crls (
		     tenant_id, ca_id, crl_number, crl_der, this_update, next_update, created_at,
		     crl_kind, shard_index, shard_count, delta_base_number, parent_crl_number, revoked_count
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 ON CONFLICT (tenant_id, ca_id, crl_number) DO UPDATE
		    SET crl_der = EXCLUDED.crl_der,
		        this_update = EXCLUDED.this_update,
		        next_update = EXCLUDED.next_update,
		        created_at = EXCLUDED.created_at,
		        crl_kind = EXCLUDED.crl_kind,
		        shard_index = EXCLUDED.shard_index,
		        shard_count = EXCLUDED.shard_count,
		        delta_base_number = EXCLUDED.delta_base_number,
		        parent_crl_number = EXCLUDED.parent_crl_number,
		        revoked_count = EXCLUDED.revoked_count`,
		c.TenantID, c.CAID, c.Number, c.DER, c.ThisUpdate.UTC(), c.NextUpdate.UTC(), createdAt.UTC(),
		c.Kind, c.ShardIndex, c.ShardCount, c.DeltaBaseNumber, c.ParentNumber, c.RevokedCount)
	return err
}

func normalizeCRL(c CRL) CRL {
	if c.Kind == "" {
		c.Kind = CRLKindFull
	}
	if c.ShardCount == 0 {
		c.ShardCount = 1
	}
	return c
}

// ActiveOCSPResponder returns the current delegated responder certificate for
// tenantID/caID, if one has been projected.
func (s *Store) ActiveOCSPResponder(ctx context.Context, tenantID, caID string) (OCSPResponder, bool, error) {
	var r OCSPResponder
	found := true
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT tenant_id::text, ca_id::text, serial, responder_cert_der, not_before, not_after, rotated_from_serial, created_at
			   FROM ca_ocsp_responders
			  WHERE tenant_id = $1 AND ca_id = $2`,
			tenantID, caID)
		switch err := row.Scan(&r.TenantID, &r.CAID, &r.Serial, &r.CertDER, &r.NotBefore, &r.NotAfter, &r.RotatedFromSerial, &r.CreatedAt); {
		case IsNotFound(err):
			found = false
			return nil
		default:
			return err
		}
	})
	return r, found, err
}

// UpsertOCSPResponder projects a responder-rotation event into the active
// responder read model.
func (s *Store) UpsertOCSPResponder(ctx context.Context, r OCSPResponder) error {
	return s.WithTenant(ctx, r.TenantID, func(tx pgx.Tx) error {
		return s.UpsertOCSPResponderTx(ctx, tx, r)
	})
}

// UpsertOCSPResponderTx is the transaction-scoped projection helper.
func (s *Store) UpsertOCSPResponderTx(ctx context.Context, tx pgx.Tx, r OCSPResponder) error {
	createdAt := r.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO ca_ocsp_responders (tenant_id, ca_id, serial, responder_cert_der, not_before, not_after, rotated_from_serial, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (tenant_id, ca_id) DO UPDATE
		    SET serial = EXCLUDED.serial,
		        responder_cert_der = EXCLUDED.responder_cert_der,
		        not_before = EXCLUDED.not_before,
		        not_after = EXCLUDED.not_after,
		        rotated_from_serial = EXCLUDED.rotated_from_serial,
		        created_at = EXCLUDED.created_at`,
		r.TenantID, r.CAID, r.Serial, r.CertDER, r.NotBefore.UTC(), r.NotAfter.UTC(), r.RotatedFromSerial, createdAt.UTC())
	return err
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
			`SELECT tenant_id::text, ca_id::text, crl_number, crl_der, this_update, next_update, created_at,
			        COALESCE(crl_kind, 'full'), COALESCE(shard_index, 0), COALESCE(shard_count, 1),
			        delta_base_number, parent_crl_number, COALESCE(revoked_count, 0)
			   FROM ca_crls
			  WHERE tenant_id = $1 AND ca_id = $2 AND COALESCE(crl_kind, 'full') = 'full'
			  ORDER BY crl_number DESC LIMIT 1`,
			tenantID, caID)
		switch err := scanCRL(row, &c); {
		case IsNotFound(err):
			found = false
			return nil
		default:
			return err
		}
	})
	return c, found, err
}

// LatestCRLShard returns the latest partitioned CRL artifact for shardIndex.
func (s *Store) LatestCRLShard(ctx context.Context, tenantID, caID string, shardIndex int) (CRL, bool, error) {
	var c CRL
	found := true
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT tenant_id::text, ca_id::text, crl_number, crl_der, this_update, next_update, created_at,
			        COALESCE(crl_kind, 'full'), COALESCE(shard_index, 0), COALESCE(shard_count, 1),
			        delta_base_number, parent_crl_number, COALESCE(revoked_count, 0)
			   FROM ca_crls
			  WHERE tenant_id = $1 AND ca_id = $2
			    AND crl_kind = 'shard'
			    AND shard_index = $3
			  ORDER BY parent_crl_number DESC NULLS LAST, crl_number DESC
			  LIMIT 1`,
			tenantID, caID, shardIndex)
		switch err := scanCRL(row, &c); {
		case IsNotFound(err):
			found = false
			return nil
		default:
			return err
		}
	})
	return c, found, err
}

// LatestDeltaCRL returns the newest delta CRL whose deltaCRLIndicator names
// baseNumber as its base CRL.
func (s *Store) LatestDeltaCRL(ctx context.Context, tenantID, caID string, baseNumber int64) (CRL, bool, error) {
	var c CRL
	found := true
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT tenant_id::text, ca_id::text, crl_number, crl_der, this_update, next_update, created_at,
			        COALESCE(crl_kind, 'full'), COALESCE(shard_index, 0), COALESCE(shard_count, 1),
			        delta_base_number, parent_crl_number, COALESCE(revoked_count, 0)
			   FROM ca_crls
			  WHERE tenant_id = $1 AND ca_id = $2
			    AND crl_kind = 'delta'
			    AND delta_base_number = $3
			  ORDER BY crl_number DESC
			  LIMIT 1`,
			tenantID, caID, baseNumber)
		switch err := scanCRL(row, &c); {
		case IsNotFound(err):
			found = false
			return nil
		default:
			return err
		}
	})
	return c, found, err
}

// ListLatestCRLArtifacts returns the latest full CRL plus the shard/delta
// artifacts published alongside it. It is the read side of the public CRL
// manifest and the authenticated API status endpoint.
func (s *Store) ListLatestCRLArtifacts(ctx context.Context, tenantID, caID string) ([]CRL, error) {
	var out []CRL
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, ca_id::text, crl_number, crl_der, this_update, next_update, created_at,
			        COALESCE(crl_kind, 'full'), COALESCE(shard_index, 0), COALESCE(shard_count, 1),
			        delta_base_number, parent_crl_number, COALESCE(revoked_count, 0)
			   FROM ca_crls
			  WHERE tenant_id = $1 AND ca_id = $2
			    AND (
			      crl_number = (
			        SELECT crl_number FROM ca_crls
			         WHERE tenant_id = $1 AND ca_id = $2 AND COALESCE(crl_kind, 'full') = 'full'
			         ORDER BY crl_number DESC LIMIT 1
			      )
			      OR parent_crl_number = (
			        SELECT crl_number FROM ca_crls
			         WHERE tenant_id = $1 AND ca_id = $2 AND COALESCE(crl_kind, 'full') = 'full'
			         ORDER BY crl_number DESC LIMIT 1
			      )
			    )
			  ORDER BY
			    CASE COALESCE(crl_kind, 'full') WHEN 'full' THEN 0 WHEN 'shard' THEN 1 ELSE 2 END,
			    shard_index NULLS FIRST,
			    crl_number DESC`,
			tenantID, caID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c CRL
			if err := scanCRL(rows, &c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// ListLatestCRLArtifactsForTenant returns each CA's latest full CRL and its
// sibling shard/delta artifacts for an authenticated tenant status/API view.
func (s *Store) ListLatestCRLArtifactsForTenant(ctx context.Context, tenantID string) ([]CRL, error) {
	var out []CRL
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT c.tenant_id::text, c.ca_id::text, c.crl_number, c.crl_der, c.this_update, c.next_update, c.created_at,
			        COALESCE(c.crl_kind, 'full'), COALESCE(c.shard_index, 0), COALESCE(c.shard_count, 1),
			        c.delta_base_number, c.parent_crl_number, COALESCE(c.revoked_count, 0)
			   FROM ca_crls c
			   JOIN (
			     SELECT DISTINCT ON (ca_id) ca_id, crl_number
			       FROM ca_crls
			      WHERE tenant_id = $1 AND COALESCE(crl_kind, 'full') = 'full'
			      ORDER BY ca_id, crl_number DESC
			   ) latest
			     ON latest.ca_id = c.ca_id
			    AND (
			      c.crl_number = latest.crl_number
			      OR c.parent_crl_number = latest.crl_number
			    )
			  WHERE c.tenant_id = $1
			  ORDER BY c.ca_id,
			    CASE COALESCE(c.crl_kind, 'full') WHEN 'full' THEN 0 WHEN 'shard' THEN 1 ELSE 2 END,
			    c.shard_index NULLS FIRST,
			    c.crl_number DESC`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c CRL
			if err := scanCRL(rows, &c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

type crlScanner interface {
	Scan(dest ...any) error
}

func scanCRL(row crlScanner, c *CRL) error {
	err := row.Scan(
		&c.TenantID, &c.CAID, &c.Number, &c.DER, &c.ThisUpdate, &c.NextUpdate, &c.CreatedAt,
		&c.Kind, &c.ShardIndex, &c.ShardCount, &c.DeltaBaseNumber, &c.ParentNumber, &c.RevokedCount,
	)
	if err != nil {
		return err
	}
	*c = normalizeCRL(*c)
	return nil
}
