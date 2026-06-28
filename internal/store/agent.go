package store

import (
	"context"
	"strings"
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

// AgentFleetHealth is a cross-tenant aggregate used only for ops telemetry. It
// carries counts, never agent identifiers, so Prometheus labels stay low-cardinality.
type AgentFleetHealth struct {
	Total int64
	Stale int64
}

// AgentCertRevocation is a projected deny-list selector for one agent mTLS
// certificate. SelectorType is "serial" or "fingerprint"; Selector is normalized
// lowercase hex. The source of truth is agent.cert.revoked, not this table.
type AgentCertRevocation struct {
	TenantID     string
	AgentID      string
	AgentName    string
	SelectorType string
	Selector     string
	Reason       string
	RevokedAt    time.Time
	CreatedAt    time.Time
}

const (
	AgentCertSelectorSerial      = "serial"
	AgentCertSelectorFingerprint = "fingerprint"
)

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

// ApplyAgentCertRevokedTx projects an agent.cert.revoked event into the served
// agent-channel deny-list. It is idempotent for replay: a later duplicate keeps
// the earliest revocation time and preserves the first non-empty reason/name.
func (s *Store) ApplyAgentCertRevokedTx(ctx context.Context, tx pgx.Tx, r AgentCertRevocation) error {
	r.SelectorType = normalizeAgentCertSelectorType(r.SelectorType)
	r.Selector = normalizeAgentCertSelector(r.SelectorType, r.Selector)
	if r.SelectorType == "" || r.Selector == "" {
		return nil
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO agent_cert_revocations
		        (tenant_id, agent_id, agent_name, selector_type, selector, reason, revoked_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (tenant_id, agent_id, selector_type, selector) DO UPDATE
		    SET agent_name = CASE
		            WHEN agent_cert_revocations.agent_name = '' THEN EXCLUDED.agent_name
		            ELSE agent_cert_revocations.agent_name
		        END,
		        reason = CASE
		            WHEN agent_cert_revocations.reason = '' THEN EXCLUDED.reason
		            ELSE agent_cert_revocations.reason
		        END,
		        revoked_at = LEAST(agent_cert_revocations.revoked_at, EXCLUDED.revoked_at)`,
		r.TenantID, r.AgentID, r.AgentName, r.SelectorType, r.Selector, r.Reason, r.RevokedAt)
	return err
}

// AgentCertRevoked reports whether the presented agent certificate is on the
// tenant-scoped revocation deny-list by serial or fingerprint.
func (s *Store) AgentCertRevoked(ctx context.Context, tenantID, agentID, serial, fingerprint string) (bool, error) {
	serial = normalizeAgentCertSelector(AgentCertSelectorSerial, serial)
	fingerprint = normalizeAgentCertSelector(AgentCertSelectorFingerprint, fingerprint)
	if serial == "" && fingerprint == "" {
		return false, nil
	}
	var revoked bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			    SELECT 1
			      FROM agent_cert_revocations
			     WHERE tenant_id = $1
			       AND agent_id = $2
			       AND (
			           (selector_type = 'serial' AND selector = $3 AND $3 <> '')
			            OR
			           (selector_type = 'fingerprint' AND selector = $4 AND $4 <> '')
			       )
			)`,
			tenantID, agentID, serial, fingerprint).Scan(&revoked)
	})
	return revoked, err
}

func normalizeAgentCertSelectorType(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case AgentCertSelectorSerial:
		return AgentCertSelectorSerial
	case AgentCertSelectorFingerprint:
		return AgentCertSelectorFingerprint
	default:
		return ""
	}
}

func normalizeAgentCertSelector(selectorType, v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch selectorType {
	case AgentCertSelectorSerial:
		return strings.ReplaceAll(v, ":", "")
	case AgentCertSelectorFingerprint:
		v = strings.TrimPrefix(v, "sha256:")
		return strings.ReplaceAll(v, ":", "")
	default:
		return ""
	}
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

// AgentFleetHealth counts all known agents and the subset whose last heartbeat is
// older than staleBefore. It is a system query because the operator alert needs one
// fleet-wide ratio; it returns only aggregate counts and does not expose tenant,
// agent, or host identifiers.
func (s *Store) AgentFleetHealth(ctx context.Context, staleBefore time.Time) (AgentFleetHealth, error) {
	var out AgentFleetHealth
	err := s.pool.QueryRow(ctx,
		//trstctl:system-query — cross-tenant by design: Prometheus fleet-health gauges need aggregate total/stale counts across ALL agents; the query returns counts only, no tenant/agent rows or labels (AN-1 exemption).
		`SELECT count(*)::bigint,
		        count(*) FILTER (WHERE last_seen_at IS NULL OR last_seen_at < $1)::bigint
		   FROM agents`,
		staleBefore).Scan(&out.Total, &out.Stale)
	return out, err
}
