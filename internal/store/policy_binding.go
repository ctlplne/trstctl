// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// PolicyBinding binds a policy to a scope (for example, all X.509 certificate
// issuance for a given owner). The policy itself is evaluated by internal/policy;
// this row records the binding.
type PolicyBinding struct {
	ID        string
	TenantID  string
	Name      string
	Policy    string          // policy module reference
	Scope     json.RawMessage // what the binding applies to
	CreatedAt time.Time
}

// UpsertPolicyBinding inserts or updates a binding in its tenant context.
func (s *Store) UpsertPolicyBinding(ctx context.Context, p PolicyBinding) error {
	return s.WithTenant(ctx, p.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO policy_bindings (id, tenant_id, name, policy, scope)
			 VALUES ($1, $2, $3, $4, $5::jsonb)
			 ON CONFLICT (id) DO UPDATE
			    SET name = EXCLUDED.name, policy = EXCLUDED.policy, scope = EXCLUDED.scope`,
			p.ID, p.TenantID, p.Name, p.Policy, jsonbOrEmpty(p.Scope))
		return err
	})
}

// GetPolicyBinding loads a binding in its tenant context.
func (s *Store) GetPolicyBinding(ctx context.Context, tenantID, id string) (PolicyBinding, error) {
	var (
		p     PolicyBinding
		scope []byte
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, policy, scope, created_at
			   FROM policy_bindings WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&p.ID, &p.TenantID, &p.Name, &p.Policy, &scope, &p.CreatedAt)
	})
	p.Scope = scope
	return p, err
}

// ListPolicyBindings returns all bindings for a tenant.
func (s *Store) ListPolicyBindings(ctx context.Context, tenantID string) ([]PolicyBinding, error) {
	var out []PolicyBinding
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, policy, scope, created_at
			   FROM policy_bindings WHERE tenant_id = $1 ORDER BY created_at, id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				p     PolicyBinding
				scope []byte
			)
			if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Policy, &scope, &p.CreatedAt); err != nil {
				return err
			}
			p.Scope = scope
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}
