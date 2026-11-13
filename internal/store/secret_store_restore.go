// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// EachStoredSecretValue calls fn with every sealed application-secret value one
// tenant holds — the current value of each secret, every retained version and
// every version of a deleted secret still kept —
// for a restored deployment's consistency check (A246). fn sees sealed bytes
// only; opening them is the caller's. Tenant-scoped under RLS (AN-1).
func (s *Store) EachStoredSecretValue(ctx context.Context, tenantID string, fn func(name string, version int, sealed []byte) error) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for _, query := range []string{
			`SELECT name, version, sealed FROM secret_store
			  WHERE tenant_id = $1 AND octet_length(sealed) > 0 ORDER BY name`,
			`SELECT name, version, sealed FROM secret_store_versions
			  WHERE tenant_id = $1 AND octet_length(sealed) > 0 ORDER BY name, version`,
			// A236-L4: a deleted secret kept for the retention window must open
			// too, or a restore of it would bring back a value nobody can read.
			`SELECT name, version, sealed FROM secret_store_tombstone_versions
			  WHERE tenant_id = $1 AND octet_length(sealed) > 0 ORDER BY name, version`,
		} {
			rows, err := tx.Query(ctx, query, tenantID)
			if err != nil {
				return err
			}
			for rows.Next() {
				var name string
				var version int
				var sealed []byte
				if err := rows.Scan(&name, &version, &sealed); err != nil {
					rows.Close()
					return err
				}
				if err := fn(name, version, sealed); err != nil {
					rows.Close()
					return err
				}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		return nil
	})
}
