// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// Attestation is the evidence chain that justified a credential issuance (F30) —
// for example a SPIFFE, TPM, or OIDC proof. It optionally references the Identity
// it justified.
type Attestation struct {
	ID         string
	TenantID   string
	IdentityID *string // the credential this evidence justified, if any
	Kind       string
	Evidence   json.RawMessage
	VerifiedAt *time.Time
	CreatedAt  time.Time
}

// UpsertAttestation inserts or updates an attestation in its tenant context.
func (s *Store) UpsertAttestation(ctx context.Context, a Attestation) error {
	return s.WithTenant(ctx, a.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO attestations (id, tenant_id, identity_id, kind, evidence, verified_at)
			 VALUES ($1, $2, $3, $4, $5::jsonb, $6)
			 ON CONFLICT (id) DO UPDATE
			    SET identity_id = EXCLUDED.identity_id, kind = EXCLUDED.kind,
			        evidence = EXCLUDED.evidence, verified_at = EXCLUDED.verified_at`,
			a.ID, a.TenantID, a.IdentityID, a.Kind, jsonbOrEmpty(a.Evidence), a.VerifiedAt)
		return err
	})
}

// GetAttestation loads an attestation in its tenant context.
func (s *Store) GetAttestation(ctx context.Context, tenantID, id string) (Attestation, error) {
	var (
		a  Attestation
		ev []byte
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, identity_id::text, kind, evidence, verified_at, created_at
			   FROM attestations WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&a.ID, &a.TenantID, &a.IdentityID, &a.Kind, &ev, &a.VerifiedAt, &a.CreatedAt)
	})
	a.Evidence = ev
	return a, err
}

// ListAttestations returns all attestations for a tenant.
func (s *Store) ListAttestations(ctx context.Context, tenantID string) ([]Attestation, error) {
	var out []Attestation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, identity_id::text, kind, evidence, verified_at, created_at
			   FROM attestations WHERE tenant_id = $1 ORDER BY created_at, id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				a  Attestation
				ev []byte
			)
			if err := rows.Scan(&a.ID, &a.TenantID, &a.IdentityID, &a.Kind, &ev, &a.VerifiedAt, &a.CreatedAt); err != nil {
				return err
			}
			a.Evidence = ev
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
