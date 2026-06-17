package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
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
