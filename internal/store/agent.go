// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

// Agent is an in-network agent that performs discovery, deployment, and drift
// detection on behalf of the control plane.
type Agent struct {
	ID       string
	TenantID string
	Name     string
	Status   string
	Version  string
	// Roles is the capability grant projected from the agent's certificate SANs
	// (epic A2). Display only: the certificate is what the claim path reads, so
	// editing this column grants nothing.
	Roles      []string
	LastSeenAt *time.Time
	// WorkloadAPIServed, WorkloadAPISVIDs and WorkloadAPIReportedAt are this
	// host's SPIFFE Workload API posture (epic B3).
	//
	// ReportedAt nil means the agent has never said anything about it, which an
	// older build does. That is deliberately distinct from reporting "not
	// serving": one is a version gap an operator fixes by upgrading, the other
	// is a choice they made.
	WorkloadAPIServed     bool
	WorkloadAPISVIDs      int64
	WorkloadAPIReportedAt *time.Time
	CreatedAt             time.Time
	OffboardedAt          *time.Time
	OffboardedBy          string
	OffboardReason        string
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
		`INSERT INTO agents (id, tenant_id, name, status, version, roles, last_seen_at,
		                     workload_api_served, workload_api_svids, workload_api_reported_at)
		 VALUES ($1, $2, $3, $4, $5, $6::text[], $7, $8, $9, $10)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		    SET name = CASE WHEN agents.status = 'offboarded' THEN agents.name ELSE EXCLUDED.name END,
		        status = CASE WHEN agents.status = 'offboarded' THEN agents.status ELSE EXCLUDED.status END,
		        version = CASE WHEN agents.status = 'offboarded' THEN agents.version ELSE EXCLUDED.version END,
		        roles = CASE WHEN agents.status = 'offboarded' THEN agents.roles ELSE EXCLUDED.roles END,
		        last_seen_at = CASE WHEN agents.status = 'offboarded' THEN agents.last_seen_at ELSE EXCLUDED.last_seen_at END,
		        -- B3: only overwrite when this beat actually REPORTED posture.
		        -- An older agent sends nothing, and letting its beats reset the
		        -- columns to false/0 would make a downgrade look like an
		        -- operator disabling the Workload API.
		        workload_api_served = CASE
		            WHEN EXCLUDED.workload_api_reported_at IS NULL THEN agents.workload_api_served
		            WHEN agents.status = 'offboarded' THEN agents.workload_api_served
		            ELSE EXCLUDED.workload_api_served END,
		        workload_api_svids = CASE
		            WHEN EXCLUDED.workload_api_reported_at IS NULL THEN agents.workload_api_svids
		            WHEN agents.status = 'offboarded' THEN agents.workload_api_svids
		            ELSE EXCLUDED.workload_api_svids END,
		        workload_api_reported_at = CASE
		            WHEN EXCLUDED.workload_api_reported_at IS NULL THEN agents.workload_api_reported_at
		            WHEN agents.status = 'offboarded' THEN agents.workload_api_reported_at
		            ELSE EXCLUDED.workload_api_reported_at END`,
		a.ID, a.TenantID, a.Name, a.Status, a.Version, agentRoleArray(a.Roles), a.LastSeenAt,
		a.WorkloadAPIServed, a.WorkloadAPISVIDs, a.WorkloadAPIReportedAt)
	return err
}

// agentRoleArray keeps a nil grant out of a NOT NULL text[] column.
func agentRoleArray(roles []string) []string {
	if roles == nil {
		return []string{}
	}
	return roles
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
		    SET name = CASE WHEN agents.status = 'offboarded' THEN agents.name ELSE EXCLUDED.name END,
		        last_seen_at = CASE WHEN agents.status = 'offboarded' THEN agents.last_seen_at ELSE EXCLUDED.last_seen_at END`,
		a.ID, a.TenantID, a.Name, a.Status, a.Version, a.LastSeenAt)
	return err
}

// ApplyAgentOffboardedTx projects an agent.offboarded event into the agents read
// model as a terminal tombstone. The row remains visible for operators and API
// clients; future heartbeat/renewal projections do not resurrect it.
func (s *Store) ApplyAgentOffboardedTx(ctx context.Context, tx pgx.Tx, a Agent) error {
	if a.ID == "" {
		return nil
	}
	name := a.Name
	if strings.TrimSpace(name) == "" {
		name = a.ID
	}
	offboardedAt := a.OffboardedAt
	if offboardedAt == nil {
		ts := a.CreatedAt
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		offboardedAt = &ts
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO agents
		        (id, tenant_id, name, status, version, last_seen_at, offboarded_at, offboarded_by, offboard_reason)
		 VALUES ($1, $2, $3, 'offboarded', '', NULL, $4, $5, $6)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		    SET status = 'offboarded',
		        name = CASE WHEN agents.name = '' THEN EXCLUDED.name ELSE agents.name END,
		        offboarded_at = CASE
		            WHEN agents.offboarded_at IS NULL THEN EXCLUDED.offboarded_at
		            ELSE LEAST(agents.offboarded_at, EXCLUDED.offboarded_at)
		        END,
		        offboarded_by = CASE WHEN COALESCE(agents.offboarded_by, '') = '' THEN EXCLUDED.offboarded_by ELSE agents.offboarded_by END,
		        offboard_reason = CASE WHEN COALESCE(agents.offboard_reason, '') = '' THEN EXCLUDED.offboard_reason ELSE agents.offboard_reason END`,
		a.ID, a.TenantID, name, offboardedAt, a.OffboardedBy, a.OffboardReason)
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

// AgentOffboarded reports whether the tenant-scoped agent row is a terminal
// tombstone. The served mTLS channel checks this per RPC, so offboarding takes
// effect on existing connections before heartbeat, renewal, or inventory work.
func (s *Store) AgentOffboarded(ctx context.Context, tenantID, agentID string) (bool, error) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return false, nil
	}
	var offboarded bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			    SELECT 1
			      FROM agents
			     WHERE tenant_id = $1
			       AND id = $2
			       AND status = 'offboarded'
			)`, tenantID, agentID).Scan(&offboarded)
	})
	return offboarded, err
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
			`SELECT id::text, tenant_id::text, name, status, version, roles, last_seen_at, created_at,
			        offboarded_at, COALESCE(offboarded_by, ''), COALESCE(offboard_reason, ''),
			        workload_api_served, workload_api_svids, workload_api_reported_at
			   FROM agents WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&a.ID, &a.TenantID, &a.Name, &a.Status, &a.Version, &a.Roles, &a.LastSeenAt, &a.CreatedAt,
				&a.OffboardedAt, &a.OffboardedBy, &a.OffboardReason,
				&a.WorkloadAPIServed, &a.WorkloadAPISVIDs, &a.WorkloadAPIReportedAt)
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
				`SELECT id::text, tenant_id::text, name, status, version, roles, last_seen_at, created_at,
				        offboarded_at, COALESCE(offboarded_by, ''), COALESCE(offboard_reason, ''),
				        workload_api_served, workload_api_svids, workload_api_reported_at
				   FROM agents
				  WHERE tenant_id = $1 AND (created_at, id) > ($2, $3)
				  ORDER BY created_at, id
				  LIMIT $4`,
				tenantID, *afterCreatedAt, afterID, limit)
		} else {
			rows, err = tx.Query(ctx,
				`SELECT id::text, tenant_id::text, name, status, version, roles, last_seen_at, created_at,
				        offboarded_at, COALESCE(offboarded_by, ''), COALESCE(offboard_reason, ''),
				        workload_api_served, workload_api_svids, workload_api_reported_at
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
			if err := rows.Scan(&a.ID, &a.TenantID, &a.Name, &a.Status, &a.Version, &a.Roles, &a.LastSeenAt, &a.CreatedAt,
				&a.OffboardedAt, &a.OffboardedBy, &a.OffboardReason,
				&a.WorkloadAPIServed, &a.WorkloadAPISVIDs, &a.WorkloadAPIReportedAt); err != nil {
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

// TenantHasNetworkRelay reports whether this tenant has an active network relay
// enrolled (epic E1).
//
// It exists so the control-plane dispatcher can REFUSE an appliance deploy that
// a relay is supposed to run, without making a relay a hard prerequisite for
// every estate. Refusing unconditionally would turn "you have not deployed a
// relay yet" into "your appliance deploys no longer work"; refusing never means
// the control plane races the relay on a one-second ticker and wins, which
// makes the A3 role stamp decoration.
//
// Offboarded agents do not count. An estate that retired its last relay is one
// where the honest answer is that nothing will claim relay work, and blocking
// its deploys on an agent that no longer exists would be a silent outage.
func (s *Store) TenantHasNetworkRelay(ctx context.Context, tenantID string) (bool, error) {
	var present bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			     SELECT 1 FROM agents
			      WHERE tenant_id = $1
			        AND offboarded_at IS NULL
			        AND $2 = ANY(roles)
			 )`, tenantID, mtls.AgentRoleNetwork).Scan(&present)
	})
	if err != nil {
		return false, fmt.Errorf("store: check tenant network relay: %w", err)
	}
	return present, nil
}
