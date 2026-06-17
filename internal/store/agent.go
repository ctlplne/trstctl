package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Agent is an in-network agent that performs discovery, deployment, and drift
// detection on behalf of the control plane.
type Agent struct {
	ID         string
	TenantID   string
	Name       string
	Status     string
	Version    string
	LastSeenAt *time.Time
	CreatedAt  time.Time
}

// UpsertAgent inserts or updates an agent in its tenant context.
func (s *Store) UpsertAgent(ctx context.Context, a Agent) error {
	return s.WithTenant(ctx, a.TenantID, func(tx pgx.Tx) error {
		return s.ApplyAgentHeartbeatTx(ctx, tx, a)
	})
}

// ApplyAgentHeartbeatTx projects an agent.heartbeat event into the agents read
// model on the caller's tenant-scoped transaction.
func (s *Store) ApplyAgentHeartbeatTx(ctx context.Context, tx pgx.Tx, a Agent) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO agents (id, tenant_id, name, status, version, last_seen_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		    SET name = EXCLUDED.name, status = EXCLUDED.status,
		        version = EXCLUDED.version, last_seen_at = EXCLUDED.last_seen_at`,
		a.ID, a.TenantID, a.Name, a.Status, a.Version, a.LastSeenAt)
	return err
}

// ApplyAgentCertRenewedTx projects an agent.cert.renewed event into the agents
// read model. A renewal proves the agent is alive and refreshes last_seen_at, but
// it preserves the health/version reported by the latest heartbeat when the row
// already exists.
func (s *Store) ApplyAgentCertRenewedTx(ctx context.Context, tx pgx.Tx, a Agent) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO agents (id, tenant_id, name, status, version, last_seen_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		    SET name = EXCLUDED.name,
		        last_seen_at = EXCLUDED.last_seen_at`,
		a.ID, a.TenantID, a.Name, a.Status, a.Version, a.LastSeenAt)
	return err
}

// GetAgent loads an agent in its tenant context.
func (s *Store) GetAgent(ctx context.Context, tenantID, id string) (Agent, error) {
	var a Agent
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, status, version, last_seen_at, created_at
			   FROM agents WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&a.ID, &a.TenantID, &a.Name, &a.Status, &a.Version, &a.LastSeenAt, &a.CreatedAt)
	})
	return a, err
}

// ListAgentsPage returns up to limit agents after the (created_at, id) cursor.
// Pass nil/ZeroUUID for the first page. The composite keyset matches
// agents_tenant_created_id_idx, so large fleets page without sorting or loading the
// full tenant inventory.
func (s *Store) ListAgentsPage(ctx context.Context, tenantID string, afterCreatedAt *time.Time, afterID string, limit int) ([]Agent, error) {
	var out []Agent
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var (
			rows pgx.Rows
			err  error
		)
		if afterCreatedAt != nil {
			rows, err = tx.Query(ctx,
				`SELECT id::text, tenant_id::text, name, status, version, last_seen_at, created_at
				   FROM agents
				  WHERE tenant_id = $1 AND (created_at, id) > ($2, $3)
				  ORDER BY created_at, id
				  LIMIT $4`,
				tenantID, *afterCreatedAt, afterID, limit)
		} else {
			rows, err = tx.Query(ctx,
				`SELECT id::text, tenant_id::text, name, status, version, last_seen_at, created_at
				   FROM agents
				  WHERE tenant_id = $1
				  ORDER BY created_at, id
				  LIMIT $2`,
				tenantID, limit)
		}
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a Agent
			if err := rows.Scan(&a.ID, &a.TenantID, &a.Name, &a.Status, &a.Version, &a.LastSeenAt, &a.CreatedAt); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
