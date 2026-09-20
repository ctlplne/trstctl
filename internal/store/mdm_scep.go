// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrMDMSCEPPolicyNotFound is returned when a tenant-scoped MDM SCEP enrollment
// policy does not exist.
var ErrMDMSCEPPolicyNotFound = errors.New("store: mdm scep policy not found")

// ErrMDMSCEPPolicyTenantCollision means a globally unique policy ID already
// belongs to another tenant. Replaying the same tenant's immutable event is
// safe; changing a foreign tenant's row is never allowed.
var ErrMDMSCEPPolicyTenantCollision = errors.New("store: mdm scep policy id belongs to another tenant")

// MDMSCEPPolicy is the tenant-owned read model for Intune/JAMF SCEP enrollment
// policy guidance. It stores reference names and policy metadata, never raw
// challenge values or provider credentials.
type MDMSCEPPolicy struct {
	ID               string
	TenantID         string
	Name             string
	Provider         string
	SCEPProfile      string
	SCEPEndpoint     string
	ExpectedAudience string
	ChallengeMode    string
	TrustAnchorRefs  json.RawMessage
	ProfileGuidance  json.RawMessage
	Enabled          bool
	RotationVersion  int
	LastRotatedAt    *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// ApplyMDMSCEPPolicyUpsertedTx projects an mdm.scep_policy.upserted event.
func (s *Store) ApplyMDMSCEPPolicyUpsertedTx(ctx context.Context, tx pgx.Tx, p MDMSCEPPolicy) error {
	if len(p.TrustAnchorRefs) == 0 {
		p.TrustAnchorRefs = json.RawMessage(`{}`)
	}
	if len(p.ProfileGuidance) == 0 {
		p.ProfileGuidance = json.RawMessage(`{}`)
	}
	if p.RotationVersion <= 0 {
		p.RotationVersion = 1
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = p.CreatedAt
	}
	// The legacy table has a global id primary key plus a redundant
	// (tenant_id, id) unique constraint. The request-time projector and durable
	// event-tail projector may race on the same immutable event. Serialize this
	// policy ID, then use the actual primary key as the conflict arbiter. The
	// tenant predicate makes a cross-tenant UUID collision fail closed.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"mdm-scep-policy:"+p.ID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO mdm_scep_policies
		    (id, tenant_id, name, provider, scep_profile, scep_endpoint, expected_audience,
		     challenge_mode, trust_anchor_refs, profile_guidance, enabled, rotation_version,
		     created_at, updated_at)
		 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb,
		         $11, $12, $13, $14)
		 ON CONFLICT (id) DO UPDATE SET
		     name = EXCLUDED.name,
		     provider = EXCLUDED.provider,
		     scep_profile = EXCLUDED.scep_profile,
		     scep_endpoint = EXCLUDED.scep_endpoint,
		     expected_audience = EXCLUDED.expected_audience,
		     challenge_mode = EXCLUDED.challenge_mode,
		     trust_anchor_refs = EXCLUDED.trust_anchor_refs,
		     profile_guidance = EXCLUDED.profile_guidance,
		     enabled = EXCLUDED.enabled,
		     rotation_version = GREATEST(mdm_scep_policies.rotation_version, EXCLUDED.rotation_version),
		     created_at = mdm_scep_policies.created_at,
		     updated_at = EXCLUDED.updated_at
		 WHERE mdm_scep_policies.tenant_id = EXCLUDED.tenant_id`,
		p.ID, p.TenantID, p.Name, p.Provider, p.SCEPProfile, p.SCEPEndpoint, p.ExpectedAudience,
		p.ChallengeMode, p.TrustAnchorRefs, p.ProfileGuidance, p.Enabled, p.RotationVersion,
		p.CreatedAt, p.UpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrMDMSCEPPolicyTenantCollision
	}
	return nil
}

// ApplyMDMSCEPPolicyDeletedTx projects an mdm.scep_policy.deleted event.
func (s *Store) ApplyMDMSCEPPolicyDeletedTx(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	_, err := tx.Exec(ctx, `DELETE FROM mdm_scep_policies WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

// ApplyMDMSCEPChallengeRotatedTx projects an mdm.scep_challenge.rotated event.
func (s *Store) ApplyMDMSCEPChallengeRotatedTx(ctx context.Context, tx pgx.Tx, tenantID, id string, rotationVersion int, rotatedAt time.Time) error {
	if rotatedAt.IsZero() {
		rotatedAt = time.Now().UTC()
	}
	tag, err := tx.Exec(ctx,
		`UPDATE mdm_scep_policies
		    SET rotation_version = GREATEST(rotation_version, $3),
		        last_rotated_at = $4,
		        updated_at = $4
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, rotationVersion, rotatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrMDMSCEPPolicyNotFound
	}
	return nil
}

// GetMDMSCEPPolicy loads one tenant-scoped MDM SCEP policy.
func (s *Store) GetMDMSCEPPolicy(ctx context.Context, tenantID, id string) (MDMSCEPPolicy, error) {
	var out MDMSCEPPolicy
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanMDMSCEPPolicy(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, provider, scep_profile, scep_endpoint,
			        expected_audience, challenge_mode, trust_anchor_refs, profile_guidance,
			        enabled, rotation_version, last_rotated_at, created_at, updated_at
			   FROM mdm_scep_policies
			  WHERE tenant_id = $1 AND id = $2`,
			tenantID, id), &out)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return MDMSCEPPolicy{}, ErrMDMSCEPPolicyNotFound
	}
	return out, err
}

// ListMDMSCEPPolicies lists tenant-scoped MDM SCEP policies.
func (s *Store) ListMDMSCEPPolicies(ctx context.Context, tenantID string) ([]MDMSCEPPolicy, error) {
	var out []MDMSCEPPolicy
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, provider, scep_profile, scep_endpoint,
			        expected_audience, challenge_mode, trust_anchor_refs, profile_guidance,
			        enabled, rotation_version, last_rotated_at, created_at, updated_at
			   FROM mdm_scep_policies
			  WHERE tenant_id = $1
			  ORDER BY name, id`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec MDMSCEPPolicy
			if err := scanMDMSCEPPolicy(rows, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

func scanMDMSCEPPolicy(row pgx.Row, p *MDMSCEPPolicy) error {
	return row.Scan(&p.ID, &p.TenantID, &p.Name, &p.Provider, &p.SCEPProfile, &p.SCEPEndpoint,
		&p.ExpectedAudience, &p.ChallengeMode, &p.TrustAnchorRefs, &p.ProfileGuidance,
		&p.Enabled, &p.RotationVersion, &p.LastRotatedAt, &p.CreatedAt, &p.UpdatedAt)
}
