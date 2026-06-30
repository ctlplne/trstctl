package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrACMEDNS01ProviderConfigNotFound is returned when a tenant-scoped ACME DNS-01
// provider config cannot be found.
var ErrACMEDNS01ProviderConfigNotFound = errors.New("store: acme dns-01 provider config not found")

// ACMEDNS01ProviderConfig is the tenant-owned DNS-01 provider configuration read
// model. It stores only provider metadata and secret references; provider tokens
// and passwords remain in the secret store (AN-8).
type ACMEDNS01ProviderConfig struct {
	ID               string
	TenantID         string
	Name             string
	Provider         string
	Zone             string
	ChallengeDomain  string
	DelegationTarget string
	CredentialRefs   json.RawMessage
	Config           json.RawMessage
	CAAIssuerDomain  string
	AllowedMethods   []string
	AllowWildcards   bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// ApplyACMEDNS01ProviderConfigUpsertedTx projects an
// acme.dns01.provider_config.upserted event. It is replay-idempotent and keeps
// the original created_at when a later update event changes the config.
func (s *Store) ApplyACMEDNS01ProviderConfigUpsertedTx(ctx context.Context, tx pgx.Tx, c ACMEDNS01ProviderConfig) error {
	if c.CredentialRefs == nil {
		c.CredentialRefs = json.RawMessage(`{}`)
	}
	if c.Config == nil {
		c.Config = json.RawMessage(`{}`)
	}
	if c.AllowedMethods == nil {
		c.AllowedMethods = []string{}
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = c.CreatedAt
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO acme_dns01_provider_configs
		        (id, tenant_id, name, provider, zone, challenge_domain, delegation_target,
		         credential_refs, config, caa_issuer_domain, allowed_methods, allow_wildcards,
		         created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		 ON CONFLICT (tenant_id, id) DO UPDATE SET
		     name = EXCLUDED.name,
		     provider = EXCLUDED.provider,
		     zone = EXCLUDED.zone,
		     challenge_domain = EXCLUDED.challenge_domain,
		     delegation_target = EXCLUDED.delegation_target,
		     credential_refs = EXCLUDED.credential_refs,
		     config = EXCLUDED.config,
		     caa_issuer_domain = EXCLUDED.caa_issuer_domain,
		     allowed_methods = EXCLUDED.allowed_methods,
		     allow_wildcards = EXCLUDED.allow_wildcards,
		     created_at = acme_dns01_provider_configs.created_at,
		     updated_at = EXCLUDED.updated_at`,
		c.ID, c.TenantID, c.Name, c.Provider, c.Zone, c.ChallengeDomain, c.DelegationTarget,
		jsonbOrEmpty(c.CredentialRefs), jsonbOrEmpty(c.Config), c.CAAIssuerDomain,
		c.AllowedMethods, c.AllowWildcards, c.CreatedAt, c.UpdatedAt)
	return err
}

// ApplyACMEDNS01ProviderConfigDeletedTx projects an
// acme.dns01.provider_config.deleted event.
func (s *Store) ApplyACMEDNS01ProviderConfigDeletedTx(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	_, err := tx.Exec(ctx,
		`DELETE FROM acme_dns01_provider_configs WHERE tenant_id = $1 AND id = $2`,
		tenantID, id)
	return err
}

// GetACMEDNS01ProviderConfig loads one tenant-scoped DNS-01 provider config.
func (s *Store) GetACMEDNS01ProviderConfig(ctx context.Context, tenantID, id string) (ACMEDNS01ProviderConfig, error) {
	var out ACMEDNS01ProviderConfig
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanACMEDNS01ProviderConfig(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, provider, zone, challenge_domain,
			        delegation_target, credential_refs, config, caa_issuer_domain,
			        allowed_methods, allow_wildcards, created_at, updated_at
			   FROM acme_dns01_provider_configs
			  WHERE tenant_id = $1 AND id = $2`,
			tenantID, id), &out)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ACMEDNS01ProviderConfig{}, ErrACMEDNS01ProviderConfigNotFound
	}
	return out, err
}

// ListACMEDNS01ProviderConfigs lists tenant-scoped DNS-01 provider configs.
func (s *Store) ListACMEDNS01ProviderConfigs(ctx context.Context, tenantID string) ([]ACMEDNS01ProviderConfig, error) {
	var out []ACMEDNS01ProviderConfig
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, provider, zone, challenge_domain,
			        delegation_target, credential_refs, config, caa_issuer_domain,
			        allowed_methods, allow_wildcards, created_at, updated_at
			   FROM acme_dns01_provider_configs
			  WHERE tenant_id = $1
			  ORDER BY name, id`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec ACMEDNS01ProviderConfig
			if err := scanACMEDNS01ProviderConfig(rows, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

func scanACMEDNS01ProviderConfig(row pgx.Row, c *ACMEDNS01ProviderConfig) error {
	return row.Scan(&c.ID, &c.TenantID, &c.Name, &c.Provider, &c.Zone, &c.ChallengeDomain,
		&c.DelegationTarget, &c.CredentialRefs, &c.Config, &c.CAAIssuerDomain,
		&c.AllowedMethods, &c.AllowWildcards, &c.CreatedAt, &c.UpdatedAt)
}
