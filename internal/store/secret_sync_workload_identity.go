// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrSecretSyncWorkloadIdentitySourceNotFound = errors.New("store: secret-sync workload identity source not found")

const (
	SecretSyncWorkloadIdentityReady           = "ready"
	SecretSyncWorkloadIdentityActive          = "active"
	SecretSyncWorkloadIdentityDisabled        = "disabled"
	SecretSyncWorkloadIdentityOfflineDisabled = "offline_disabled"
	SecretSyncWorkloadIdentityExchangeFailed  = "exchange_failed"
)

// SecretSyncWorkloadIdentitySource is the tenant-owned, non-secret policy that
// authorizes a bounded outbox delivery to exchange one workload proof for
// short-lived cloud credentials.
type SecretSyncWorkloadIdentitySource struct {
	ID                       string
	TenantID                 string
	Name                     string
	Provider                 string
	RoleARN                  string
	ServiceAccount           string
	AzureTenantID            string
	ClientID                 string
	TargetScope              string
	Audience                 string
	Subject                  string
	TargetID                 string
	AllowedRemoteKeyPrefixes []string
	WorkloadProofRef         string
	TrustSourceID            string
	Enabled                  bool
	Status                   string
	StatusReason             string
	LastExchangeAt           *time.Time
	TokenExpiresAt           *time.Time
	LastFailureAt            *time.Time
	CreatedAt                time.Time
	UpdatedAt                time.Time
}

func (s *Store) ApplySecretSyncWorkloadIdentitySourceUpsertedTx(ctx context.Context, tx pgx.Tx, source SecretSyncWorkloadIdentitySource) error {
	if source.AllowedRemoteKeyPrefixes == nil {
		source.AllowedRemoteKeyPrefixes = []string{}
	}
	if source.Status == "" {
		if source.Enabled {
			source.Status = SecretSyncWorkloadIdentityReady
		} else {
			source.Status = SecretSyncWorkloadIdentityDisabled
		}
	}
	if err := lockUpsertArbiterTx(ctx, tx, "secret_sync_workload_identity_sources", source.TenantID, source.ID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO secret_sync_workload_identity_sources
		    (tenant_id, id, name, provider, role_arn, service_account, azure_tenant_id, client_id,
		     target_scope, audience, subject, target_id,
		     allowed_remote_key_prefixes, workload_proof_ref, trust_source_id,
		     enabled, status, status_reason, created_at, updated_at)
		 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11,
		         $12, $13, $14, $15::uuid, $16, $17, $18, $19, $20)
		 ON CONFLICT (tenant_id, id) DO UPDATE SET
		     name = EXCLUDED.name,
		     provider = EXCLUDED.provider,
		     role_arn = EXCLUDED.role_arn,
		     service_account = EXCLUDED.service_account,
		     azure_tenant_id = EXCLUDED.azure_tenant_id,
		     client_id = EXCLUDED.client_id,
		     target_scope = EXCLUDED.target_scope,
		     audience = EXCLUDED.audience,
		     subject = EXCLUDED.subject,
		     target_id = EXCLUDED.target_id,
		     allowed_remote_key_prefixes = EXCLUDED.allowed_remote_key_prefixes,
		     workload_proof_ref = EXCLUDED.workload_proof_ref,
		     trust_source_id = EXCLUDED.trust_source_id,
		     enabled = EXCLUDED.enabled,
		     status = EXCLUDED.status,
		     status_reason = EXCLUDED.status_reason,
		     last_exchange_at = CASE WHEN EXCLUDED.enabled THEN secret_sync_workload_identity_sources.last_exchange_at ELSE NULL END,
		     token_expires_at = CASE WHEN EXCLUDED.enabled THEN secret_sync_workload_identity_sources.token_expires_at ELSE NULL END,
		     last_failure_at = CASE WHEN EXCLUDED.enabled THEN secret_sync_workload_identity_sources.last_failure_at ELSE NULL END,
		     created_at = secret_sync_workload_identity_sources.created_at,
		     updated_at = EXCLUDED.updated_at`,
		source.TenantID, source.ID, source.Name, source.Provider, source.RoleARN, source.ServiceAccount,
		source.AzureTenantID, source.ClientID, source.TargetScope, source.Audience, source.Subject,
		source.TargetID, source.AllowedRemoteKeyPrefixes,
		source.WorkloadProofRef, source.TrustSourceID, source.Enabled, source.Status,
		source.StatusReason, source.CreatedAt, source.UpdatedAt)
	return err
}

func (s *Store) ApplySecretSyncWorkloadIdentitySourceStatusTx(ctx context.Context, tx pgx.Tx, tenantID, id, status, reason string, expiresAt *time.Time, at time.Time) error {
	var lastExchangeAt, lastFailureAt *time.Time
	if status == SecretSyncWorkloadIdentityActive {
		lastExchangeAt = &at
	}
	if status == SecretSyncWorkloadIdentityExchangeFailed || status == SecretSyncWorkloadIdentityOfflineDisabled {
		lastFailureAt = &at
		expiresAt = nil
	}
	tag, err := tx.Exec(ctx,
		`UPDATE secret_sync_workload_identity_sources
		    SET status = $3,
		        status_reason = $4,
		        last_exchange_at = COALESCE($5, last_exchange_at),
		        token_expires_at = $6,
		        last_failure_at = COALESCE($7, last_failure_at)
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, status, reason, lastExchangeAt, expiresAt, lastFailureAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSecretSyncWorkloadIdentitySourceNotFound
	}
	return nil
}

func (s *Store) ApplySecretSyncWorkloadIdentitySourceDeletedTx(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	tag, err := tx.Exec(ctx,
		`DELETE FROM secret_sync_workload_identity_sources WHERE tenant_id = $1 AND id = $2`,
		tenantID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSecretSyncWorkloadIdentitySourceNotFound
	}
	return nil
}

func (s *Store) GetSecretSyncWorkloadIdentitySource(ctx context.Context, tenantID, id string) (SecretSyncWorkloadIdentitySource, error) {
	var out SecretSyncWorkloadIdentitySource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanSecretSyncWorkloadIdentitySource(tx.QueryRow(ctx,
			secretSyncWorkloadIdentitySourceSelect+` AND id = $2`,
			tenantID, id), &out)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SecretSyncWorkloadIdentitySource{}, ErrSecretSyncWorkloadIdentitySourceNotFound
	}
	return out, err
}

func (s *Store) ListSecretSyncWorkloadIdentitySources(ctx context.Context, tenantID string) ([]SecretSyncWorkloadIdentitySource, error) {
	var out []SecretSyncWorkloadIdentitySource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			secretSyncWorkloadIdentitySourceSelect+` ORDER BY name, id`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var source SecretSyncWorkloadIdentitySource
			if err := scanSecretSyncWorkloadIdentitySource(rows, &source); err != nil {
				return err
			}
			out = append(out, source)
		}
		return rows.Err()
	})
	return out, err
}

// FindSecretSyncWorkloadIdentitySourceForTarget selects the one enabled
// tenant/provider/target source whose key-prefix policy authorizes remoteKey.
func (s *Store) FindSecretSyncWorkloadIdentitySourceForTarget(ctx context.Context, tenantID, provider, targetID, remoteKey string) (SecretSyncWorkloadIdentitySource, error) {
	var out SecretSyncWorkloadIdentitySource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanSecretSyncWorkloadIdentitySource(tx.QueryRow(ctx,
			secretSyncWorkloadIdentitySourceSelect+
				`   AND provider = $2
				    AND target_id = $3
				    AND enabled = true
				    AND (
				        cardinality(allowed_remote_key_prefixes) = 0
				        OR EXISTS (
				            SELECT 1
				              FROM unnest(allowed_remote_key_prefixes) AS prefix
				             WHERE left($4, char_length(prefix)) = prefix
				        )
				    )`,
			tenantID, provider, targetID, remoteKey), &out)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SecretSyncWorkloadIdentitySource{}, ErrSecretSyncWorkloadIdentitySourceNotFound
	}
	return out, err
}

// #nosec G101 -- SQL column list matching the secret-name heuristic; a query, not a credential (CWE-798)
const secretSyncWorkloadIdentitySourceSelect = `
	SELECT id::text, tenant_id::text, name, provider, role_arn, service_account,
	       azure_tenant_id, client_id, target_scope, audience, subject,
	       target_id, allowed_remote_key_prefixes, workload_proof_ref,
	       trust_source_id::text, enabled, status, status_reason, last_exchange_at,
	       token_expires_at, last_failure_at, created_at, updated_at
	  FROM secret_sync_workload_identity_sources
	 WHERE tenant_id = $1`

func scanSecretSyncWorkloadIdentitySource(row pgx.Row, source *SecretSyncWorkloadIdentitySource) error {
	return row.Scan(
		&source.ID, &source.TenantID, &source.Name, &source.Provider, &source.RoleARN, &source.ServiceAccount,
		&source.AzureTenantID, &source.ClientID, &source.TargetScope,
		&source.Audience, &source.Subject, &source.TargetID, &source.AllowedRemoteKeyPrefixes,
		&source.WorkloadProofRef, &source.TrustSourceID, &source.Enabled, &source.Status,
		&source.StatusReason, &source.LastExchangeAt, &source.TokenExpiresAt,
		&source.LastFailureAt, &source.CreatedAt, &source.UpdatedAt,
	)
}
