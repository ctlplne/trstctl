// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// IdentityBinding names what an identity is bound to.
type IdentityBinding string

// The bindings CountIdentitiesBound counts by.
const (
	IdentitiesByIssuer           IdentityBinding = "issuer"
	IdentitiesByOwner            IdentityBinding = "owner"
	IdentitiesByDeploymentTarget IdentityBinding = "deployment_target"
)

var identityBindingCounts = map[IdentityBinding]string{
	IdentitiesByIssuer:           `SELECT count(*) FROM identities WHERE tenant_id = $1 AND issuer_id = $2::uuid`,
	IdentitiesByOwner:            `SELECT count(*) FROM identities WHERE tenant_id = $1 AND owner_id = $2::uuid`,
	IdentitiesByDeploymentTarget: `SELECT count(*) FROM identities WHERE tenant_id = $1 AND attributes->>'deployment_target_id' = $2`,
}

// CountIdentitiesBound counts a tenant's identities bound to one object: issued
// under an issuer, owned by an owner, or deploying to a deployment target. A
// reviewed change set's plan (A248) shows it for each object it would change.
func (s *Store) CountIdentitiesBound(ctx context.Context, tenantID string, by IdentityBinding, id string) (int, error) {
	sql, ok := identityBindingCounts[by]
	if !ok {
		return 0, fmt.Errorf("store: unknown identity binding %q", by)
	}
	var n int
	err := s.tenantQueryRow(ctx, tenantID, sql, []any{tenantID, id}, func(row pgx.Row) error { return row.Scan(&n) })
	return n, err
}
