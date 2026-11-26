// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrWorkloadAttesterTrustSourceNotFound is returned when a tenant-scoped
// workload attester trust source does not exist.
var ErrWorkloadAttesterTrustSourceNotFound = errors.New("store: workload attester trust source not found")

// ErrWorkloadAttesterTrustSourceTenantCollision means a globally unique source
// ID already belongs to a different tenant. A projector retry may safely update
// the same tenant's row, but must never turn an ID collision into a cross-tenant
// write.
var ErrWorkloadAttesterTrustSourceTenantCollision = errors.New("store: workload attester trust source id belongs to another tenant")

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
	// SelfAuthenticating (A84): the verified proof of this github_oidc source
	// is itself the bearer credential of attested issuance for the tenant.
	SelfAuthenticating bool
	// AllowedOwners adds an optional name condition to the GitHub ID pins.
	AllowedOwners        []string
	AllowedOwnerIDs      []string
	AllowedRepositoryIDs []string
	Enabled              bool
	ConfiguredEnabled    bool
	AdminReviewRequired  bool
	AuthorityPending     bool
	RevokedAt            *time.Time
	RevokedReason        string
	RotationVersion      int
	LastRotatedAt        *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func (s WorkloadAttesterTrustSource) HasImmutableGitHubPins() bool {
	return s.Method == "github_oidc" && (len(s.AllowedOwnerIDs) > 0 || len(s.AllowedRepositoryIDs) > 0)
}

// RequiresImmutableGitHubPin flags legacy authority that cannot verify proofs
// until an operator supplies a pin for this issuer.
func (s WorkloadAttesterTrustSource) RequiresImmutableGitHubPin() bool {
	return s.Method == "github_oidc" && (s.SelfAuthenticating || len(s.AllowedOwners) > 0) && !s.HasImmutableGitHubPins()
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
	if ts.AllowedOwners == nil {
		ts.AllowedOwners = []string{}
	}
	if len(ts.AllowedOwnerIDs) == 0 {
		ts.AllowedOwnerIDs = nil
	}
	if len(ts.AllowedRepositoryIDs) == 0 {
		ts.AllowedRepositoryIDs = nil
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
	// This legacy table has both a global id primary key, a redundant (tenant_id,
	// id) unique constraint, and a tenant/name unique index. PostgreSQL can choose
	// different arbiters while the synchronous request projector races the durable
	// tail projector, so lock both the aggregate ID and case-insensitive name.
	// Sorting the lock keys prevents a rename/create race from deadlocking. Older
	// releases could append two differently-IDed events for the same unique name;
	// the first event remains authoritative and the later invalid event becomes a
	// deterministic no-op instead of poisoning every future projection replay.
	lockKeys := []string{
		"workload-attester-trust-source:id:" + ts.ID,
		"workload-attester-trust-source:name:" + ts.TenantID + ":" + strings.ToLower(strings.TrimSpace(ts.Name)),
	}
	sort.Strings(lockKeys)
	for _, lockKey := range lockKeys {
		if _, err := tx.Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
			return err
		}
	}
	var nameOwnerID string
	err := tx.QueryRow(ctx,
		`SELECT id::text
		   FROM workload_attester_trust_sources
		  WHERE tenant_id = $1 AND lower(name) = lower($2)`,
		ts.TenantID, ts.Name).Scan(&nameOwnerID)
	if err == nil && nameOwnerID != ts.ID {
		return nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO workload_attester_trust_sources
		    (id, tenant_id, name, method, issuer, audience, jwks, root_certs_pem,
		     expected_nonce_base64, enabled, rotation_version, created_at, updated_at,
	     self_authenticating, allowed_owners, allowed_owner_ids, allowed_repository_ids,
	     admin_review_required)
		 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7::jsonb, $8,
	         $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		 ON CONFLICT (id) DO NOTHING`,
		ts.ID, ts.TenantID, ts.Name, ts.Method, ts.Issuer, ts.Audience, jsonbOrEmpty(ts.JWKS),
		ts.RootCertsPEM, ts.ExpectedNonceBase64, ts.Enabled, ts.RotationVersion, ts.CreatedAt, ts.UpdatedAt,
		ts.SelfAuthenticating, ts.AllowedOwners, ts.AllowedOwnerIDs, ts.AllowedRepositoryIDs,
		ts.AdminReviewRequired)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// The conflict may be a same-tenant replay or another tenant's row hidden
	// by RLS. The explicit tenant filter updates only the former; the latter
	// returns zero rows without granting read or write access to its contents.
	tag, err = tx.Exec(ctx,
		`UPDATE workload_attester_trust_sources SET
		     name = $3, method = $4, issuer = $5, audience = $6,
		     jwks = $7::jsonb, root_certs_pem = $8, expected_nonce_base64 = $9,
		     enabled = $10, rotation_version = GREATEST(rotation_version, $11),
		     updated_at = $12, self_authenticating = $13, allowed_owners = $14,
	     allowed_owner_ids = $15, allowed_repository_ids = $16,
	     admin_review_required = $17,
		     revoked_at = NULL, revoked_reason = ''
		 WHERE id = $1::uuid AND tenant_id = $2::uuid`,
		ts.ID, ts.TenantID, ts.Name, ts.Method, ts.Issuer, ts.Audience, jsonbOrEmpty(ts.JWKS),
		ts.RootCertsPEM, ts.ExpectedNonceBase64, ts.Enabled, ts.RotationVersion, ts.UpdatedAt,
		ts.SelfAuthenticating, ts.AllowedOwners, ts.AllowedOwnerIDs, ts.AllowedRepositoryIDs,
		ts.AdminReviewRequired)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrWorkloadAttesterTrustSourceTenantCollision
	}
	return nil
}

// GetWorkloadAttesterTrustSourceByName loads one case-insensitive tenant-owned
// display name. It is the command-side guard that prevents an invalid duplicate
// event from entering the immutable log during normal operation.
func (s *Store) GetWorkloadAttesterTrustSourceByName(ctx context.Context, tenantID, name string) (WorkloadAttesterTrustSource, error) {
	var out WorkloadAttesterTrustSource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanWorkloadAttesterTrustSource(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, method, issuer, audience, jwks,
			        root_certs_pem, expected_nonce_base64, enabled, revoked_at, revoked_reason,
			        rotation_version, last_rotated_at, created_at, updated_at,
		        self_authenticating, allowed_owners, allowed_owner_ids, allowed_repository_ids,
		        admin_review_required
			   FROM workload_attester_trust_sources
			  WHERE tenant_id = $1 AND lower(name) = lower($2)`,
			tenantID, strings.TrimSpace(name)), &out)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return WorkloadAttesterTrustSource{}, ErrWorkloadAttesterTrustSourceNotFound
	}
	return out, err
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

// WorkloadAttesterTrustSourceHasSecretSyncDependents checks the FK that would
// make a trust-source deletion unprojectable. Admission calls it while holding
// the same source fence used by secret-sync source creation.
func (s *Store) WorkloadAttesterTrustSourceHasSecretSyncDependents(ctx context.Context, tenantID, id string) (bool, error) {
	var dependent bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		dependent, err = s.WorkloadAttesterTrustSourceHasSecretSyncDependentsTx(ctx, tx, tenantID, id)
		return err
	})
	return dependent, err
}

func (s *Store) WorkloadAttesterTrustSourceHasSecretSyncDependentsTx(ctx context.Context, tx pgx.Tx, tenantID, id string) (bool, error) {
	var dependent bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM secret_sync_workload_identity_sources
		 WHERE tenant_id=$1 AND trust_source_id=$2)`, tenantID, id).Scan(&dependent)
	return dependent, err
}

// WorkloadAttesterTrustSourceExistsTx sees rows staged by an atomic rebuild.
func (s *Store) WorkloadAttesterTrustSourceExistsTx(ctx context.Context, tx pgx.Tx, tenantID, id string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM workload_attester_trust_sources
		 WHERE tenant_id=$1 AND id=$2)`, tenantID, id).Scan(&exists)
	return exists, err
}

// GetWorkloadAttesterTrustSource loads one tenant-scoped trust source.
func (s *Store) GetWorkloadAttesterTrustSource(ctx context.Context, tenantID, id string) (WorkloadAttesterTrustSource, error) {
	var out WorkloadAttesterTrustSource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanWorkloadAttesterTrustSource(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, method, issuer, audience, jwks,
			        root_certs_pem, expected_nonce_base64, enabled, revoked_at, revoked_reason,
			        rotation_version, last_rotated_at, created_at, updated_at,
		        self_authenticating, allowed_owners, allowed_owner_ids, allowed_repository_ids,
		        admin_review_required
			   FROM workload_attester_trust_sources
			  WHERE tenant_id = $1 AND id = $2`,
			tenantID, id), &out)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return WorkloadAttesterTrustSource{}, ErrWorkloadAttesterTrustSourceNotFound
	}
	return out, err
}

// GetEffectiveWorkloadAttesterTrustSource reports the admission posture, not
// just the potentially lagging event projection. A pending replacement denies
// old proof until its exact source event has been projected.
func (s *Store) GetEffectiveWorkloadAttesterTrustSource(ctx context.Context, tenantID, id string) (WorkloadAttesterTrustSource, error) {
	var out WorkloadAttesterTrustSource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanEffectiveWorkloadAttesterTrustSource(tx.QueryRow(ctx,
			`SELECT trust.id::text, trust.tenant_id::text, trust.name, trust.method,
			        trust.issuer, trust.audience, trust.jwks, trust.root_certs_pem,
			        trust.expected_nonce_base64,
		        CASE WHEN command.status='pending' OR command.target_disabled OR trust.admin_review_required
			             THEN false ELSE trust.enabled END,
			        trust.revoked_at, trust.revoked_reason, trust.rotation_version,
			        trust.last_rotated_at, trust.created_at, trust.updated_at,
		        trust.self_authenticating, trust.allowed_owners, trust.allowed_owner_ids, trust.allowed_repository_ids,
		        trust.enabled,
		        trust.admin_review_required,
			        COALESCE(command.status='pending', false)
			   FROM workload_attester_trust_sources AS trust
			   LEFT JOIN workload_attester_trust_commands AS command
			     ON command.tenant_id=trust.tenant_id AND command.source_id=trust.id
			  WHERE trust.tenant_id=$1 AND trust.id=$2`, tenantID, id), &out)
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
			        rotation_version, last_rotated_at, created_at, updated_at,
		        self_authenticating, allowed_owners, allowed_owner_ids, allowed_repository_ids,
		        admin_review_required
			   FROM workload_attester_trust_sources AS trust
		  WHERE trust.tenant_id = $1 AND trust.method = $2 AND trust.enabled = true
		    AND NOT trust.admin_review_required
			    AND NOT EXISTS (SELECT 1 FROM workload_attester_trust_commands AS command
			      WHERE command.tenant_id = trust.tenant_id AND command.source_id = trust.id
			        AND (command.status = 'pending' OR command.target_disabled))
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
		sql := `SELECT trust.id::text, trust.tenant_id::text, trust.name, trust.method,
		               trust.issuer, trust.audience, trust.jwks,
		               trust.root_certs_pem, trust.expected_nonce_base64,
		               CASE WHEN trust.admin_review_required OR EXISTS (SELECT 1 FROM workload_attester_trust_commands AS command
		                 WHERE command.tenant_id=trust.tenant_id AND command.source_id=trust.id
		                   AND (command.status='pending' OR command.target_disabled))
		                 THEN false ELSE trust.enabled END,
		               trust.revoked_at, trust.revoked_reason,
		               trust.rotation_version, trust.last_rotated_at, trust.created_at, trust.updated_at,
		               trust.self_authenticating, trust.allowed_owners, trust.allowed_owner_ids, trust.allowed_repository_ids,
		               trust.enabled,
		               trust.admin_review_required,
		               EXISTS (SELECT 1 FROM workload_attester_trust_commands AS pending
		                 WHERE pending.tenant_id=trust.tenant_id AND pending.source_id=trust.id
		                   AND pending.status='pending')
		          FROM workload_attester_trust_sources AS trust
		         WHERE trust.tenant_id = $1`
		args := []any{tenantID}
		if method != "" {
			sql += ` AND trust.method = $2`
			args = append(args, method)
		}
		sql += ` ORDER BY trust.name, trust.id`
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec WorkloadAttesterTrustSource
			if err := scanEffectiveWorkloadAttesterTrustSource(rows, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

func scanWorkloadAttesterTrustSource(row pgx.Row, ts *WorkloadAttesterTrustSource) error {
	err := row.Scan(&ts.ID, &ts.TenantID, &ts.Name, &ts.Method, &ts.Issuer, &ts.Audience,
		&ts.JWKS, &ts.RootCertsPEM, &ts.ExpectedNonceBase64, &ts.Enabled, &ts.RevokedAt,
		&ts.RevokedReason, &ts.RotationVersion, &ts.LastRotatedAt, &ts.CreatedAt, &ts.UpdatedAt,
		&ts.SelfAuthenticating, &ts.AllowedOwners, &ts.AllowedOwnerIDs, &ts.AllowedRepositoryIDs,
		&ts.AdminReviewRequired)
	if err == nil {
		ts.ConfiguredEnabled = ts.Enabled
	}
	return err
}

func scanEffectiveWorkloadAttesterTrustSource(row pgx.Row, ts *WorkloadAttesterTrustSource) error {
	return row.Scan(&ts.ID, &ts.TenantID, &ts.Name, &ts.Method, &ts.Issuer, &ts.Audience,
		&ts.JWKS, &ts.RootCertsPEM, &ts.ExpectedNonceBase64, &ts.Enabled, &ts.RevokedAt,
		&ts.RevokedReason, &ts.RotationVersion, &ts.LastRotatedAt, &ts.CreatedAt,
		&ts.UpdatedAt, &ts.SelfAuthenticating, &ts.AllowedOwners, &ts.AllowedOwnerIDs,
		&ts.AllowedRepositoryIDs, &ts.ConfiguredEnabled, &ts.AdminReviewRequired, &ts.AuthorityPending)
}
