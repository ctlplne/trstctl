// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

// ProfileRecord is a stored certificate-profile version (S8.1). Spec is the
// serialized profile.CertificateProfile; the store keeps it opaque (jsonb) so the
// profile model stays in internal/profile, free of crypto/x509 (AN-3).
type ProfileRecord struct {
	ID        string
	TenantID  string
	Name      string
	Version   int
	Spec      json.RawMessage
	Active    bool
	CreatedBy string
	CreatedAt time.Time
}

// ProfileSpecDigest is the stable digest used by approval evidence and lifecycle
// commands. It canonicalizes valid JSON before hashing because PostgreSQL jsonb
// and the idempotency response cache may serialize object keys differently. The
// same rule therefore keeps one digest across HTTP, projection, replay, and
// approval. Invalid JSON retains a deterministic raw-byte digest so this helper
// remains total; served profile writes reject invalid specs before calling it.
func ProfileSpecDigest(spec json.RawMessage) string {
	decoder := json.NewDecoder(bytes.NewReader(spec))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err == nil {
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return "sha256:" + crypto.SHA256Hex(spec)
		}
		if canonical, marshalErr := json.Marshal(value); marshalErr == nil {
			return "sha256:" + crypto.SHA256Hex(canonical)
		}
	}
	return "sha256:" + crypto.SHA256Hex(spec)
}

// NextProfileVersion returns the next version number for tenant/name. The
// orchestrator calls it while holding the projection advisory lock, so concurrent
// served profile edits serialize around the append+project sequence.
func (s *Store) NextProfileVersion(ctx context.Context, tenantID, name string) (int, error) {
	var next int
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COALESCE(MAX(version), 0) + 1 FROM certificate_profiles WHERE tenant_id = $1 AND name = $2`,
			tenantID, name).Scan(&next)
	})
	return next, err
}

// CreateProfileVersion inserts a new version of a named profile and makes it the
// single active version (deactivating any prior active version), in one tenant-
// scoped transaction (AN-1). It is a low-level test/import helper only; served
// profile writes must go through orchestrator.CreateProfile so the profile event
// remains the source of truth (AN-2). The version is the next integer for that
// name, so prior versions remain resolvable. Returns the created record.
func (s *Store) CreateProfileVersion(ctx context.Context, r ProfileRecord) (ProfileRecord, error) {
	err := s.WithTenant(ctx, r.TenantID, func(tx pgx.Tx) error {
		var next int
		if err := tx.QueryRow(ctx,
			`SELECT COALESCE(MAX(version), 0) + 1 FROM certificate_profiles WHERE tenant_id = $1 AND name = $2`,
			r.TenantID, r.Name).Scan(&next); err != nil {
			return err
		}
		r.Version = next
		if _, err := tx.Exec(ctx,
			`UPDATE certificate_profiles SET active = false WHERE tenant_id = $1 AND name = $2 AND active`,
			r.TenantID, r.Name); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`INSERT INTO certificate_profiles (id, tenant_id, name, version, spec, active, created_by)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4, true, $5)
			 RETURNING id::text, created_at`,
			r.TenantID, r.Name, r.Version, []byte(r.Spec), r.CreatedBy).Scan(&r.ID, &r.CreatedAt)
	})
	if err != nil {
		return ProfileRecord{}, err
	}
	r.Active = true
	return r, nil
}

// GetActiveProfile returns the active version of a named profile, or
// pgx.ErrNoRows (see IsNotFound) if none exists. This is the version new issuance
// binds to.
func (s *Store) GetActiveProfile(ctx context.Context, tenantID, name string) (ProfileRecord, error) {
	var r ProfileRecord
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanProfile(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, version, spec, active, created_by, created_at
			   FROM certificate_profiles WHERE tenant_id = $1 AND name = $2 AND active`,
			tenantID, name), &r)
	})
	return r, err
}

// GetProfileVersion returns a specific (name, version) — so a prior version stays
// resolvable even after newer versions exist (S8.1 acceptance).
func (s *Store) GetProfileVersion(ctx context.Context, tenantID, name string, version int) (ProfileRecord, error) {
	var r ProfileRecord
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanProfile(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, version, spec, active, created_by, created_at
			   FROM certificate_profiles WHERE tenant_id = $1 AND name = $2 AND version = $3`,
			tenantID, name, version), &r)
	})
	return r, err
}

// GetProfileVersionByID loads one profile version row by its id (the id a
// closed dual-control request names as its profile_id).
func (s *Store) GetProfileVersionByID(ctx context.Context, tenantID, id string) (ProfileRecord, error) {
	var r ProfileRecord
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanProfile(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, version, spec, active, created_by, created_at
			   FROM certificate_profiles WHERE tenant_id = $1 AND id = $2`,
			tenantID, id), &r)
	})
	return r, err
}

// ValidateActiveProfileApprovalBindingTx locks the currently active profile row
// and proves it is still the exact revision reviewers authorized. The shared row
// lock serializes against deactivation by a concurrent same-name profile update.
func (s *Store) ValidateActiveProfileApprovalBindingTx(ctx context.Context, tx pgx.Tx, tenantID string, binding OperationApprovalIssuanceBinding) error {
	if binding.ProfileName == "" || binding.ProfileID == "" || binding.ProfileVersion <= 0 || binding.ProfileSpecDigest == "" {
		return ErrApprovalDrifted
	}
	var r ProfileRecord
	if err := scanProfile(tx.QueryRow(ctx,
		`SELECT id::text, tenant_id::text, name, version, spec, active, created_by, created_at
		   FROM certificate_profiles
		  WHERE tenant_id = $1 AND name = $2 AND active
		  FOR SHARE`, tenantID, binding.ProfileName), &r); err != nil {
		if err == pgx.ErrNoRows {
			return ErrApprovalDrifted
		}
		return err
	}
	if r.ID != binding.ProfileID || r.Version != binding.ProfileVersion ||
		ProfileSpecDigest(r.Spec) != binding.ProfileSpecDigest {
		return ErrApprovalDrifted
	}
	return nil
}

// ListProfiles returns the active profiles for a tenant (one row per name).
func (s *Store) ListProfiles(ctx context.Context, tenantID string) ([]ProfileRecord, error) {
	var out []ProfileRecord
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, version, spec, active, created_by, created_at
			   FROM certificate_profiles WHERE tenant_id = $1 AND active ORDER BY name`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r ProfileRecord
			if err := scanProfile(rows, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanProfile(row rowScanner, r *ProfileRecord) error {
	var spec []byte
	if err := row.Scan(&r.ID, &r.TenantID, &r.Name, &r.Version, &spec, &r.Active, &r.CreatedBy, &r.CreatedAt); err != nil {
		return err
	}
	r.Spec = json.RawMessage(spec)
	return nil
}
