// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// ListAttestationsByKind returns newest-first immutable evidence history for one
// tenant and one closed evidence kind. The tenant predicate remains explicit
// even though RLS supplies the second isolation wall (AN-1).
func (s *Store) ListAttestationsByKind(ctx context.Context, tenantID, kind string, limit int) ([]Attestation, error) {
	if tenantID == "" || kind == "" {
		return nil, errors.New("store: tenant and attestation kind are required")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []Attestation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, identity_id::text, kind, evidence, verified_at, created_at
			   FROM attestations
			  WHERE tenant_id = $1 AND kind = $2
			  ORDER BY created_at DESC, id DESC LIMIT $3`, tenantID, kind, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row Attestation
			var evidence []byte
			if err := rows.Scan(&row.ID, &row.TenantID, &row.IdentityID, &row.Kind,
				&evidence, &row.VerifiedAt, &row.CreatedAt); err != nil {
				return err
			}
			row.Evidence = append(json.RawMessage(nil), evidence...)
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}

// ApplyRestoreDrillAttestationTx projects one immutable signed drill record and,
// when supplied, its notification intent in the SAME transaction (AN-6). Exact
// replay is a no-op; a reused id or alert key with different bytes fails closed.
func (s *Store) ApplyRestoreDrillAttestationTx(
	ctx context.Context,
	tx pgx.Tx,
	a Attestation,
	alertDestination string,
	alertPayload []byte,
	alertKey string,
) error {
	if a.ID == "" || a.TenantID == "" || a.Kind == "" || len(a.Evidence) == 0 ||
		a.CreatedAt.IsZero() || a.VerifiedAt == nil {
		return errors.New("store: restore-drill attestation is incomplete")
	}
	if (alertDestination == "") != (len(alertPayload) == 0) ||
		(alertDestination == "") != (alertKey == "") {
		return errors.New("store: restore-drill alert intent is incomplete")
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"restore-drill-attestation\x1f"+a.TenantID+"\x1f"+a.ID); err != nil {
		return fmt.Errorf("store: lock restore-drill attestation: %w", err)
	}
	var exact bool
	err := tx.QueryRow(ctx,
		`SELECT kind = $3 AND evidence = $4::jsonb AND verified_at = $5 AND created_at = $6
		   FROM attestations WHERE tenant_id = $1 AND id = $2`,
		a.TenantID, a.ID, a.Kind, a.Evidence, a.VerifiedAt.UTC(), a.CreatedAt.UTC()).Scan(&exact)
	if err == nil {
		if !exact {
			return fmt.Errorf("%w: restore-drill attestation id is already bound", ErrIdempotencyConflict)
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO attestations
		        (id, tenant_id, identity_id, kind, evidence, verified_at, created_at)
		 VALUES ($1, $2, NULL, $3, $4::jsonb, $5, $6)`,
		a.ID, a.TenantID, a.Kind, a.Evidence, a.VerifiedAt.UTC(), a.CreatedAt.UTC()); err != nil {
		return fmt.Errorf("store: insert restore-drill attestation: %w", err)
	}
	if alertDestination == "" {
		return nil
	}
	var existingDestination string
	var existingPayload []byte
	err = tx.QueryRow(ctx,
		`SELECT destination, payload FROM outbox
		  WHERE tenant_id = $1 AND idempotency_key = $2 ORDER BY id LIMIT 1`,
		a.TenantID, alertKey).Scan(&existingDestination, &existingPayload)
	if err == nil {
		if existingDestination != alertDestination || !bytes.Equal(existingPayload, alertPayload) {
			return fmt.Errorf("%w: restore-drill alert key is already bound", ErrIdempotencyConflict)
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
		 VALUES ($1, $2, $2, $3, $4)`, a.TenantID, alertDestination, alertPayload, alertKey); err != nil {
		return fmt.Errorf("store: enqueue restore-drill alert: %w", err)
	}
	return nil
}
