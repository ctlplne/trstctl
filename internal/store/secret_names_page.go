// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ListSecretNamesAfter returns up to limit secret names (no values) after the
// name after, in name order, leaving out every name under one of hidden
// ("<project>/<environment>/" prefixes): the graph's keyset read of the
// secret store (G1-L4).
func (s *Store) ListSecretNamesAfter(ctx context.Context, tenantID, after string, hidden []string, limit int) ([]Secret, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	exclude := make([]string, 0, len(hidden))
	for _, p := range hidden {
		exclude = append(exclude, strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(p)+"%")
	}
	var out []Secret
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, coalesce(owner_id::text, ''), version, created_at, updated_at
			   FROM secret_store
			  WHERE tenant_id = $1 AND name > $2 AND NOT (name LIKE ANY($3::text[]))
			  ORDER BY name
			  LIMIT $4`,
			tenantID, after, exclude, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m Secret
			if err := rows.Scan(&m.ID, &m.TenantID, &m.Name, &m.OwnerID, &m.Version, &m.CreatedAt, &m.UpdatedAt); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}
