// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrACMEDNS01ProviderConfigNotFound is returned when a tenant-scoped ACME DNS-01
// provider config cannot be found.
var ErrACMEDNS01ProviderConfigNotFound = errors.New("store: acme dns-01 provider config not found")

// ErrACMEDNS01ProviderConfigNameConflict means another config in the same
// tenant already owns the human-readable name. Callers must reject the command
// before appending its event; letting PostgreSQL discover this only while
// projecting would leave an impossible event blocking every later projection.
var ErrACMEDNS01ProviderConfigNameConflict = errors.New("store: acme dns-01 provider config name is already in use")

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
	// AllowUpstreamDV permits this config to publish records for UPSTREAM
	// domain validation against an external CA (epic B7). Off by default:
	// credentials supplied so trstctl could VERIFY a challenge are not consent
	// to PUBLISH into the zone whenever a public CA asks.
	AllowUpstreamDV bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
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
	// The request path now rejects duplicate tenant/name commands before it
	// appends an event. Older releases appended first and discovered the unique
	// name conflict only here, leaving one impossible event to block the entire
	// ordered projection tail forever. Lock the aggregate and tenant/name in a
	// stable order so concurrent replay converges. If a legacy event gives a
	// different ID an already-owned name, preserve the first projected row and
	// consume the later invalid event as a deterministic no-op. This is a replay
	// recovery rule only; EnsureACMEDNS01ProviderConfigNameAvailable remains the
	// command-side guard that prevents new conflicting events.
	lockKeys := []string{
		"acme-dns01-provider-config:id:" + c.ID,
		"acme-dns01-provider-config:name:" + c.TenantID + ":" + c.Name,
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
		   FROM acme_dns01_provider_configs
		  WHERE tenant_id = $1 AND name = $2`,
		c.TenantID, c.Name).Scan(&nameOwnerID)
	if err == nil && nameOwnerID != c.ID {
		return nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO acme_dns01_provider_configs
		        (id, tenant_id, name, provider, zone, challenge_domain, delegation_target,
		         credential_refs, config, caa_issuer_domain, allowed_methods, allow_wildcards,
		         allow_upstream_dv,
		         created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
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
		     allow_upstream_dv = EXCLUDED.allow_upstream_dv,
		     created_at = acme_dns01_provider_configs.created_at,
		     updated_at = EXCLUDED.updated_at`,
		c.ID, c.TenantID, c.Name, c.Provider, c.Zone, c.ChallengeDomain, c.DelegationTarget,
		jsonbOrEmpty(c.CredentialRefs), jsonbOrEmpty(c.Config), c.CAAIssuerDomain,
		c.AllowedMethods, c.AllowWildcards, c.AllowUpstreamDV, c.CreatedAt, c.UpdatedAt)
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
			        allowed_methods, allow_wildcards, allow_upstream_dv, created_at, updated_at
			   FROM acme_dns01_provider_configs
			  WHERE tenant_id = $1 AND id = $2`,
			tenantID, id), &out)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ACMEDNS01ProviderConfig{}, ErrACMEDNS01ProviderConfigNotFound
	}
	return out, err
}

// EnsureACMEDNS01ProviderConfigNameAvailable checks the tenant/name uniqueness
// invariant for a proposed config ID. The API calls it while holding the shared
// projection advisory lock, serializing the read -> event append -> projection
// sequence across control-plane replicas. The same ID may retain its own name.
func (s *Store) EnsureACMEDNS01ProviderConfigNameAvailable(ctx context.Context, tenantID, id, name string) error {
	var conflictingID string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text
			   FROM acme_dns01_provider_configs
			  WHERE tenant_id = $1 AND name = $2 AND id <> $3
			  LIMIT 1`, tenantID, name, id).Scan(&conflictingID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return ErrACMEDNS01ProviderConfigNameConflict
}

// ListACMEDNS01ProviderConfigs lists tenant-scoped DNS-01 provider configs.
func (s *Store) ListACMEDNS01ProviderConfigs(ctx context.Context, tenantID string) ([]ACMEDNS01ProviderConfig, error) {
	var out []ACMEDNS01ProviderConfig
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, provider, zone, challenge_domain,
			        delegation_target, credential_refs, config, caa_issuer_domain,
			        allowed_methods, allow_wildcards, allow_upstream_dv, created_at, updated_at
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
		&c.AllowedMethods, &c.AllowWildcards, &c.AllowUpstreamDV, &c.CreatedAt, &c.UpdatedAt)
}

// Upstream authorization staleness (epic B7).
//
// Solving DNS-01 upstream is half of what a compressing validation-reuse window
// demands; knowing whether you can still solve it is the other half. An
// authority that already considers an identifier authorized issues without a
// challenge, so an install whose validation path broke months ago keeps issuing
// happily until the window closes — at which point every identifier fails at
// once, because they were all authorized in the same original burst.

// ACMEUpstreamAuthorization is one identifier's authorization state at one
// authority.
type ACMEUpstreamAuthorization struct {
	TenantID   string
	Identifier string
	Issuer     string
	// ChallengeType is empty when the authorization was reused.
	ChallengeType string
	Reused        bool
	// LastValidatedAt is zero when trstctl has NEVER validated this identifier
	// here — every issuance so far rode a reuse this install did not earn and
	// cannot repeat.
	LastValidatedAt time.Time
	LastReusedAt    time.Time
	ExpiresAt       time.Time
	ReuseCount      int64
	ValidateCount   int64
	// EventSequence is the log position of the observation that produced this
	// row. It exists so the counters are replay-safe; see the Apply function.
	EventSequence uint64
	ObservedAt    time.Time
}

// ApplyACMEUpstreamAuthorizationObservedTx records one authorization outcome.
//
// A reuse and a real validation write different columns. Folding them into one
// "last seen" timestamp would erase the only signal here: the gap between when
// an identifier last issued and when it last actually proved control.
//
// The WHERE clause is what makes this replay-safe, and it is not optional. Boot
// replays the entire log without truncating, and the durable tailer can
// re-deliver an event the inline path already applied; the package contract
// requires that applying an already-projected event be an idempotent upsert.
// Timestamps are naturally idempotent because they are set to a fixed observed
// value — but "reuse_count + 1" is not, so without the sequence guard every
// restart would inflate the totals by the whole history and the console would
// report validations this deployment never performed.
func (s *Store) ApplyACMEUpstreamAuthorizationObservedTx(ctx context.Context, tx pgx.Tx, a ACMEUpstreamAuthorization) error {
	var validatedAt, reusedAt *time.Time
	observed := a.ObservedAt
	if observed.IsZero() {
		observed = time.Now().UTC()
	}
	if a.Reused {
		reusedAt = &observed
	} else {
		validatedAt = &observed
	}
	var expires *time.Time
	if !a.ExpiresAt.IsZero() {
		expires = &a.ExpiresAt
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO acme_upstream_authorizations
		        (tenant_id, identifier, issuer, challenge_type, last_validated_at,
		         last_reused_at, expires_at, reuse_count, validate_count, event_sequence, observed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (tenant_id, issuer, identifier) DO UPDATE SET
		     -- COALESCE keeps the previous value when this observation was the
		     -- other kind: a reuse must not erase the date of the last real
		     -- validation, because that date is the whole point of the row.
		     challenge_type    = CASE WHEN EXCLUDED.challenge_type = '' THEN acme_upstream_authorizations.challenge_type
		                              ELSE EXCLUDED.challenge_type END,
		     last_validated_at = COALESCE(EXCLUDED.last_validated_at, acme_upstream_authorizations.last_validated_at),
		     last_reused_at    = COALESCE(EXCLUDED.last_reused_at, acme_upstream_authorizations.last_reused_at),
		     expires_at        = COALESCE(EXCLUDED.expires_at, acme_upstream_authorizations.expires_at),
		     reuse_count       = acme_upstream_authorizations.reuse_count + EXCLUDED.reuse_count,
		     validate_count    = acme_upstream_authorizations.validate_count + EXCLUDED.validate_count,
		     event_sequence    = GREATEST(acme_upstream_authorizations.event_sequence, EXCLUDED.event_sequence),
		     observed_at       = EXCLUDED.observed_at
		 WHERE EXCLUDED.event_sequence > acme_upstream_authorizations.event_sequence`,
		a.TenantID, a.Identifier, a.Issuer, a.ChallengeType, validatedAt, reusedAt, expires,
		boolToCount(a.Reused), boolToCount(!a.Reused), int64(a.EventSequence), observed) // #nosec G115 -- event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190)
	return err
}

func boolToCount(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// ListACMEUpstreamAuthorizations returns the tenant's authorization rows,
// never-validated first, then soonest-to-expire.
//
// The two-key ordering is deliberate and the first key is not the obvious one.
// Sorting by expiry alone buries the rows that matter: an identifier this
// install has never once validated may carry a comfortable expiry date, because
// the authority keeps reissuing it from an authorization the install did not
// earn. It looks the healthiest right up to the moment the reuse window closes.
// So "never validated here" sorts above every expiry.
func (s *Store) ListACMEUpstreamAuthorizations(ctx context.Context, tenantID string) ([]ACMEUpstreamAuthorization, error) {
	var out []ACMEUpstreamAuthorization
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, identifier, issuer, challenge_type, last_validated_at,
			        last_reused_at, expires_at, reuse_count, validate_count, event_sequence, observed_at
			   FROM acme_upstream_authorizations
			  WHERE tenant_id = $1
			  ORDER BY (last_validated_at IS NULL) DESC, expires_at ASC NULLS FIRST, identifier, issuer`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				rec                        ACMEUpstreamAuthorization
				validated, reused, expires *time.Time
				seq                        int64
			)
			if err := rows.Scan(&rec.TenantID, &rec.Identifier, &rec.Issuer, &rec.ChallengeType,
				&validated, &reused, &expires, &rec.ReuseCount, &rec.ValidateCount,
				&seq, &rec.ObservedAt); err != nil {
				return err
			}
			rec.EventSequence = uint64(seq) // #nosec G115 -- non-negative by construction (CWE-190)
			if validated != nil {
				rec.LastValidatedAt = *validated
			}
			if reused != nil {
				rec.LastReusedAt = *reused
			}
			if expires != nil {
				rec.ExpiresAt = *expires
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}
