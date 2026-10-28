// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// SPIFFEUpstreamJWTKey is a JWT signing key a SPIRE server published through
// the trstctl upstream authority plugin (A205). Every server of the tenant
// receives every such key, so they verify each other's JWT-SVIDs.
type SPIFFEUpstreamJWTKey struct {
	TenantID string
	KeyID    string
	// PublicKeyDER is the PKIX public key.
	PublicKeyDER []byte
	// ExpiresAt is nil for a key published without an expiry.
	ExpiresAt     *time.Time
	Tainted       bool
	PublishedBy   string
	PublishedAt   time.Time
	UpdatedAt     time.Time
	EventSequence uint64
}

// ErrSPIFFEUpstreamJWTKeyConflict refuses a key ID already published with a
// different public key, or a change other than tainting.
var ErrSPIFFEUpstreamJWTKeyConflict = errors.New("store: that JWT key ID is published with a different key")

// ApplySPIFFEUpstreamJWTKeyPublishedTx projects spiffe.upstream_jwt_key.published.
// A key keeps its public key and expiry; a later event may only taint it, and a
// replay converges.
func (s *Store) ApplySPIFFEUpstreamJWTKeyPublishedTx(ctx context.Context, tx pgx.Tx, k SPIFFEUpstreamJWTKey) error {
	tag, err := tx.Exec(ctx,
		`INSERT INTO spiffe_upstream_jwt_keys (tenant_id, key_id, public_key_der, expires_at, tainted, published_by,
		                                       published_at, updated_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8)
		 ON CONFLICT (tenant_id, key_id) DO UPDATE
		    SET tainted = spiffe_upstream_jwt_keys.tainted OR EXCLUDED.tainted,
		        updated_at = EXCLUDED.updated_at, event_sequence = EXCLUDED.event_sequence
		  WHERE spiffe_upstream_jwt_keys.event_sequence < EXCLUDED.event_sequence
		    AND spiffe_upstream_jwt_keys.public_key_der = EXCLUDED.public_key_der
		    AND spiffe_upstream_jwt_keys.expires_at IS NOT DISTINCT FROM EXCLUDED.expires_at`,
		k.TenantID, k.KeyID, k.PublicKeyDER, k.ExpiresAt, k.Tainted, k.PublishedBy, k.PublishedAt,
		int64(k.EventSequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	if err != nil || tag.RowsAffected() == 1 {
		return err
	}
	// No row changed: either a replay of this or an earlier event, or a
	// different key under a published ID, which the command refuses first.
	var sequence int64
	var same bool
	err = tx.QueryRow(ctx,
		`SELECT event_sequence, public_key_der = $3 AND expires_at IS NOT DISTINCT FROM $4
		   FROM spiffe_upstream_jwt_keys WHERE tenant_id = $1 AND key_id = $2`,
		k.TenantID, k.KeyID, k.PublicKeyDER, k.ExpiresAt).Scan(&sequence, &same)
	if err != nil {
		return err
	}
	if !same && sequence < int64(k.EventSequence) { // #nosec G115 -- event sequences fit int64 (CWE-190)
		return ErrSPIFFEUpstreamJWTKeyConflict
	}
	return nil
}

const spiffeUpstreamJWTKeyColumns = `tenant_id::text, key_id, public_key_der, expires_at, tainted, published_by,
        published_at, updated_at, event_sequence`

func scanSPIFFEUpstreamJWTKey(row pgx.Row, k *SPIFFEUpstreamJWTKey) error {
	var seq int64
	if err := row.Scan(&k.TenantID, &k.KeyID, &k.PublicKeyDER, &k.ExpiresAt, &k.Tainted, &k.PublishedBy,
		&k.PublishedAt, &k.UpdatedAt, &seq); err != nil {
		return err
	}
	k.EventSequence = uint64(seq) // #nosec G115 -- non-negative by constraint (CWE-190)
	return nil
}

// GetSPIFFEUpstreamJWTKey returns one published key.
func (s *Store) GetSPIFFEUpstreamJWTKey(ctx context.Context, tenantID, keyID string) (SPIFFEUpstreamJWTKey, error) {
	var k SPIFFEUpstreamJWTKey
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanSPIFFEUpstreamJWTKey(tx.QueryRow(ctx,
			`SELECT `+spiffeUpstreamJWTKeyColumns+` FROM spiffe_upstream_jwt_keys WHERE tenant_id = $1 AND key_id = $2`,
			tenantID, keyID), &k)
	})
	return k, err
}

// ListSPIFFEUpstreamJWTKeys returns the tenant's published keys that have not
// expired at now, oldest first.
func (s *Store) ListSPIFFEUpstreamJWTKeys(ctx context.Context, tenantID string, now time.Time) ([]SPIFFEUpstreamJWTKey, error) {
	var out []SPIFFEUpstreamJWTKey
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+spiffeUpstreamJWTKeyColumns+` FROM spiffe_upstream_jwt_keys
			  WHERE tenant_id = $1 AND (expires_at IS NULL OR expires_at > $2)
			  ORDER BY published_at, key_id`, tenantID, now)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k SPIFFEUpstreamJWTKey
			if err := scanSPIFFEUpstreamJWTKey(rows, &k); err != nil {
				return err
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return out, err
}
