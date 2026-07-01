package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrWorkloadAttesterTrustSourceNotFound is returned when a tenant-scoped
// workload attester trust source does not exist.
var ErrWorkloadAttesterTrustSourceNotFound = errors.New("store: workload attester trust source not found")

// WorkloadAttesterTrustSource is the tenant-owned read model for workload
// attestation trust material. It stores public roots/JWKS and policy metadata,
// never private keys or bearer tokens.
type WorkloadAttesterTrustSource struct {
	ID                  string
	TenantID            string
	Name                string
	Method              string
	Issuer              string
	Audience            string
	JWKS                json.RawMessage
	RootCertsPEM        []string
	ExpectedNonceBase64 string
	Enabled             bool
	RevokedAt           *time.Time
	RevokedReason       string
	RotationVersion     int
	LastRotatedAt       *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// ApplyWorkloadAttesterTrustSourceUpsertedTx projects a
// workload.attester_trust_source.upserted event.
func (s *Store) ApplyWorkloadAttesterTrustSourceUpsertedTx(ctx context.Context, tx pgx.Tx, ts WorkloadAttesterTrustSource) error {
	if len(ts.JWKS) == 0 {
		ts.JWKS = json.RawMessage(`{}`)
	}
	if ts.RootCertsPEM == nil {
		ts.RootCertsPEM = []string{}
	}
	if ts.RotationVersion <= 0 {
		ts.RotationVersion = 1
	}
	if ts.CreatedAt.IsZero() {
		ts.CreatedAt = time.Now().UTC()
	}
	if ts.UpdatedAt.IsZero() {
		ts.UpdatedAt = ts.CreatedAt
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO workload_attester_trust_sources
		    (id, tenant_id, name, method, issuer, audience, jwks, root_certs_pem,
		     expected_nonce_base64, enabled, rotation_version, created_at, updated_at)
		 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7::jsonb, $8,
		         $9, $10, $11, $12, $13)
		 ON CONFLICT (tenant_id, id) DO UPDATE SET
		     name = EXCLUDED.name,
		     method = EXCLUDED.method,
		     issuer = EXCLUDED.issuer,
		     audience = EXCLUDED.audience,
		     jwks = EXCLUDED.jwks,
		     root_certs_pem = EXCLUDED.root_certs_pem,
		     expected_nonce_base64 = EXCLUDED.expected_nonce_base64,
		     enabled = EXCLUDED.enabled,
		     revoked_at = NULL,
		     revoked_reason = '',
		     rotation_version = GREATEST(workload_attester_trust_sources.rotation_version, EXCLUDED.rotation_version),
		     created_at = workload_attester_trust_sources.created_at,
		     updated_at = EXCLUDED.updated_at`,
		ts.ID, ts.TenantID, ts.Name, ts.Method, ts.Issuer, ts.Audience, jsonbOrEmpty(ts.JWKS),
		ts.RootCertsPEM, ts.ExpectedNonceBase64, ts.Enabled, ts.RotationVersion, ts.CreatedAt, ts.UpdatedAt)
	return err
}

// ApplyWorkloadAttesterTrustSourceRotatedTx projects a
// workload.attester_trust_source.rotated event.
func (s *Store) ApplyWorkloadAttesterTrustSourceRotatedTx(ctx context.Context, tx pgx.Tx, ts WorkloadAttesterTrustSource, rotatedAt time.Time) error {
	if len(ts.JWKS) == 0 {
		ts.JWKS = json.RawMessage(`{}`)
	}
	if ts.RootCertsPEM == nil {
		ts.RootCertsPEM = []string{}
	}
	if ts.RotationVersion <= 0 {
		ts.RotationVersion = 1
	}
	if rotatedAt.IsZero() {
		rotatedAt = time.Now().UTC()
	}
	tag, err := tx.Exec(ctx,
		`UPDATE workload_attester_trust_sources
		    SET issuer = $3,
		        audience = $4,
		        jwks = $5::jsonb,
		        root_certs_pem = $6,
		        expected_nonce_base64 = $7,
		        enabled = true,
		        revoked_at = NULL,
		        revoked_reason = '',
		        rotation_version = GREATEST(rotation_version, $8),
		        last_rotated_at = $9,
		        updated_at = $9
		  WHERE tenant_id = $1 AND id = $2`,
		ts.TenantID, ts.ID, ts.Issuer, ts.Audience, jsonbOrEmpty(ts.JWKS), ts.RootCertsPEM,
		ts.ExpectedNonceBase64, ts.RotationVersion, rotatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrWorkloadAttesterTrustSourceNotFound
	}
	return nil
}

// ApplyWorkloadAttesterTrustSourceRevokedTx projects a
// workload.attester_trust_source.revoked event.
func (s *Store) ApplyWorkloadAttesterTrustSourceRevokedTx(ctx context.Context, tx pgx.Tx, tenantID, id, reason string, revokedAt time.Time) error {
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	tag, err := tx.Exec(ctx,
		`UPDATE workload_attester_trust_sources
		    SET enabled = false,
		        revoked_at = $3,
		        revoked_reason = $4,
		        updated_at = $3
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, revokedAt, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrWorkloadAttesterTrustSourceNotFound
	}
	return nil
}

// ApplyWorkloadAttesterTrustSourceDeletedTx projects a
// workload.attester_trust_source.deleted event.
func (s *Store) ApplyWorkloadAttesterTrustSourceDeletedTx(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	_, err := tx.Exec(ctx, `DELETE FROM workload_attester_trust_sources WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

// GetWorkloadAttesterTrustSource loads one tenant-scoped trust source.
func (s *Store) GetWorkloadAttesterTrustSource(ctx context.Context, tenantID, id string) (WorkloadAttesterTrustSource, error) {
	var out WorkloadAttesterTrustSource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanWorkloadAttesterTrustSource(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, method, issuer, audience, jwks,
			        root_certs_pem, expected_nonce_base64, enabled, revoked_at, revoked_reason,
			        rotation_version, last_rotated_at, created_at, updated_at
			   FROM workload_attester_trust_sources
			  WHERE tenant_id = $1 AND id = $2`,
			tenantID, id), &out)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return WorkloadAttesterTrustSource{}, ErrWorkloadAttesterTrustSourceNotFound
	}
	return out, err
}

// ListWorkloadAttesterTrustSources lists tenant-scoped trust sources.
func (s *Store) ListWorkloadAttesterTrustSources(ctx context.Context, tenantID string) ([]WorkloadAttesterTrustSource, error) {
	return s.listWorkloadAttesterTrustSources(ctx, tenantID, "")
}

// ListEnabledWorkloadAttesterTrustSources lists enabled trust sources for one
// attestation method.
func (s *Store) ListEnabledWorkloadAttesterTrustSources(ctx context.Context, tenantID, method string) ([]WorkloadAttesterTrustSource, error) {
	var out []WorkloadAttesterTrustSource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, method, issuer, audience, jwks,
			        root_certs_pem, expected_nonce_base64, enabled, revoked_at, revoked_reason,
			        rotation_version, last_rotated_at, created_at, updated_at
			   FROM workload_attester_trust_sources
			  WHERE tenant_id = $1 AND method = $2 AND enabled = true
			  ORDER BY name, id`,
			tenantID, method)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec WorkloadAttesterTrustSource
			if err := scanWorkloadAttesterTrustSource(rows, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Store) listWorkloadAttesterTrustSources(ctx context.Context, tenantID, method string) ([]WorkloadAttesterTrustSource, error) {
	var out []WorkloadAttesterTrustSource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		sql := `SELECT id::text, tenant_id::text, name, method, issuer, audience, jwks,
		               root_certs_pem, expected_nonce_base64, enabled, revoked_at, revoked_reason,
		               rotation_version, last_rotated_at, created_at, updated_at
		          FROM workload_attester_trust_sources
		         WHERE tenant_id = $1`
		args := []any{tenantID}
		if method != "" {
			sql += ` AND method = $2`
			args = append(args, method)
		}
		sql += ` ORDER BY name, id`
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec WorkloadAttesterTrustSource
			if err := scanWorkloadAttesterTrustSource(rows, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

func scanWorkloadAttesterTrustSource(row pgx.Row, ts *WorkloadAttesterTrustSource) error {
	return row.Scan(&ts.ID, &ts.TenantID, &ts.Name, &ts.Method, &ts.Issuer, &ts.Audience,
		&ts.JWKS, &ts.RootCertsPEM, &ts.ExpectedNonceBase64, &ts.Enabled, &ts.RevokedAt,
		&ts.RevokedReason, &ts.RotationVersion, &ts.LastRotatedAt, &ts.CreatedAt, &ts.UpdatedAt)
}
