// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/plugincensus"
	"trstctl.com/trstctl/internal/revcacheposture"
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
	// EnrollmentProxy* is the latest measured relay topology plus durable
	// last-activity timestamps. ReportedAt nil means this agent predates the
	// report. Serving false with ReportedAt set is an explicit current answer.
	EnrollmentProxyServing            bool
	EnrollmentProxySegment            string
	EnrollmentProxyPublicURL          string
	EnrollmentProxyHealthyUpstreams   int
	EnrollmentProxyUnhealthyUpstreams int
	EnrollmentProxyUnknownUpstreams   int
	EnrollmentProxyUpstreamFailures   int64
	EnrollmentProxyForwarded          int64
	EnrollmentProxyRefused            int64
	EnrollmentProxyLastForwardedAt    *time.Time
	EnrollmentProxyLastFailoverAt     *time.Time
	EnrollmentProxyReportedAt         *time.Time
	// RelayPlugins* is the newest signed metadata-only module census projected
	// from this certificate-bound relay's heartbeat. ReportedAt nil means an
	// older build never reported it; an empty slice with ReportedAt set is an
	// explicit current empty census.
	RelayPlugins                  []plugincensus.Entry
	RelayPluginsStatement         string
	RelayPluginsSignature         []byte
	RelayPluginsSignerFingerprint string
	RelayPluginsReportedAt        *time.Time
	// RevocationCaches* is the newest signed metadata-only cache posture from
	// this certificate-bound relay. Protocol bytes and upstream URLs stay local.
	RevocationCaches                  []revcacheposture.Entry
	RevocationCachesStatement         string
	RevocationCachesSignature         []byte
	RevocationCachesSignerFingerprint string
	RevocationCachesReportedAt        *time.Time
	CreatedAt                         time.Time
	OffboardedAt                      *time.Time
	OffboardedBy                      string
	OffboardReason                    string
}

// AgentFleetHealth is a cross-tenant aggregate used only for ops telemetry. It
// carries counts, never agent identifiers, so Prometheus labels stay low-cardinality.
type AgentFleetHealth struct {
	Total int64
	Stale int64
}

// AgentRevocationCache is one signed per-cache row flattened from the newest
// accepted relay heartbeat. Signature bytes remain in the projection and are
// never returned by the API; SignerFingerprint and ReportedAt are safe proof.
type AgentRevocationCache struct {
	AgentID           string
	AgentName         string
	Entry             revcacheposture.Entry
	SignerFingerprint string
	ReportedAt        time.Time
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
	plugins := a.RelayPlugins
	if plugins == nil {
		plugins = []plugincensus.Entry{}
	}
	signature := a.RelayPluginsSignature
	if signature == nil {
		signature = []byte{}
	}
	relayPlugins, err := json.Marshal(plugins)
	if err != nil {
		return fmt.Errorf("store: encode relay plugin census: %w", err)
	}
	caches := a.RevocationCaches
	if caches == nil {
		caches = []revcacheposture.Entry{}
	}
	cacheSignature := a.RevocationCachesSignature
	if cacheSignature == nil {
		cacheSignature = []byte{}
	}
	revocationCaches, err := json.Marshal(caches)
	if err != nil {
		return fmt.Errorf("store: encode revocation cache posture: %w", err)
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO agents (id, tenant_id, name, status, version, roles, last_seen_at,
		                     workload_api_served, workload_api_svids, workload_api_reported_at,
		                     enrollment_proxy_serving, enrollment_proxy_segment, enrollment_proxy_public_url,
		                     enrollment_proxy_healthy_upstreams, enrollment_proxy_unhealthy_upstreams, enrollment_proxy_unknown_upstreams,
		                     enrollment_proxy_upstream_failures, enrollment_proxy_forwarded,
		                     enrollment_proxy_refused, enrollment_proxy_last_forwarded_at,
		                     enrollment_proxy_last_failover_at, enrollment_proxy_reported_at,
		                     relay_plugins, relay_plugins_statement, relay_plugins_signature,
		                     relay_plugins_signer_fingerprint, relay_plugins_reported_at,
		                     revocation_caches, revocation_caches_statement, revocation_caches_signature,
		                     revocation_caches_signer_fingerprint, revocation_caches_reported_at)
		 VALUES ($1, $2, $3, $4, $5, $6::text[], $7, $8, $9, $10,
		         $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22,
		         $23::jsonb, $24, $25, $26, $27,
		         $28::jsonb, $29, $30, $31, $32)
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
		            ELSE EXCLUDED.workload_api_reported_at END,
		        enrollment_proxy_serving = CASE
		            WHEN EXCLUDED.enrollment_proxy_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.enrollment_proxy_serving
		            ELSE EXCLUDED.enrollment_proxy_serving END,
		        enrollment_proxy_segment = CASE
		            WHEN EXCLUDED.enrollment_proxy_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.enrollment_proxy_segment
		            WHEN EXCLUDED.enrollment_proxy_segment = '' THEN agents.enrollment_proxy_segment
		            ELSE EXCLUDED.enrollment_proxy_segment END,
		        enrollment_proxy_public_url = CASE
		            WHEN EXCLUDED.enrollment_proxy_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.enrollment_proxy_public_url
		            WHEN EXCLUDED.enrollment_proxy_public_url = '' THEN agents.enrollment_proxy_public_url
		            ELSE EXCLUDED.enrollment_proxy_public_url END,
		        enrollment_proxy_healthy_upstreams = CASE
		            WHEN EXCLUDED.enrollment_proxy_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.enrollment_proxy_healthy_upstreams
		            ELSE EXCLUDED.enrollment_proxy_healthy_upstreams END,
		        enrollment_proxy_unhealthy_upstreams = CASE
		            WHEN EXCLUDED.enrollment_proxy_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.enrollment_proxy_unhealthy_upstreams
		            ELSE EXCLUDED.enrollment_proxy_unhealthy_upstreams END,
		        enrollment_proxy_unknown_upstreams = CASE
		            WHEN EXCLUDED.enrollment_proxy_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.enrollment_proxy_unknown_upstreams
		            ELSE EXCLUDED.enrollment_proxy_unknown_upstreams END,
		        enrollment_proxy_upstream_failures = CASE
		            WHEN EXCLUDED.enrollment_proxy_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.enrollment_proxy_upstream_failures
		            ELSE EXCLUDED.enrollment_proxy_upstream_failures END,
		        enrollment_proxy_forwarded = CASE
		            WHEN EXCLUDED.enrollment_proxy_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.enrollment_proxy_forwarded
		            ELSE EXCLUDED.enrollment_proxy_forwarded END,
		        enrollment_proxy_refused = CASE
		            WHEN EXCLUDED.enrollment_proxy_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.enrollment_proxy_refused
		            ELSE EXCLUDED.enrollment_proxy_refused END,
		        enrollment_proxy_last_forwarded_at = CASE
		            WHEN EXCLUDED.enrollment_proxy_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.enrollment_proxy_last_forwarded_at
		            WHEN EXCLUDED.enrollment_proxy_last_forwarded_at IS NULL THEN agents.enrollment_proxy_last_forwarded_at
		            ELSE GREATEST(agents.enrollment_proxy_last_forwarded_at, EXCLUDED.enrollment_proxy_last_forwarded_at) END,
		        enrollment_proxy_last_failover_at = CASE
		            WHEN EXCLUDED.enrollment_proxy_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.enrollment_proxy_last_failover_at
		            WHEN EXCLUDED.enrollment_proxy_last_failover_at IS NULL THEN agents.enrollment_proxy_last_failover_at
		            ELSE GREATEST(agents.enrollment_proxy_last_failover_at, EXCLUDED.enrollment_proxy_last_failover_at) END,
		        enrollment_proxy_reported_at = CASE
		            WHEN EXCLUDED.enrollment_proxy_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.enrollment_proxy_reported_at
		            ELSE EXCLUDED.enrollment_proxy_reported_at END,
		        relay_plugins = CASE
		            WHEN EXCLUDED.relay_plugins_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.relay_plugins
		            WHEN agents.relay_plugins_reported_at IS NOT NULL AND EXCLUDED.relay_plugins_reported_at <= agents.relay_plugins_reported_at THEN agents.relay_plugins
		            ELSE EXCLUDED.relay_plugins END,
		        relay_plugins_statement = CASE
		            WHEN EXCLUDED.relay_plugins_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.relay_plugins_statement
		            WHEN agents.relay_plugins_reported_at IS NOT NULL AND EXCLUDED.relay_plugins_reported_at <= agents.relay_plugins_reported_at THEN agents.relay_plugins_statement
		            ELSE EXCLUDED.relay_plugins_statement END,
		        relay_plugins_signature = CASE
		            WHEN EXCLUDED.relay_plugins_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.relay_plugins_signature
		            WHEN agents.relay_plugins_reported_at IS NOT NULL AND EXCLUDED.relay_plugins_reported_at <= agents.relay_plugins_reported_at THEN agents.relay_plugins_signature
		            ELSE EXCLUDED.relay_plugins_signature END,
		        relay_plugins_signer_fingerprint = CASE
		            WHEN EXCLUDED.relay_plugins_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.relay_plugins_signer_fingerprint
		            WHEN agents.relay_plugins_reported_at IS NOT NULL AND EXCLUDED.relay_plugins_reported_at <= agents.relay_plugins_reported_at THEN agents.relay_plugins_signer_fingerprint
		            ELSE EXCLUDED.relay_plugins_signer_fingerprint END,
		        relay_plugins_reported_at = CASE
		            WHEN EXCLUDED.relay_plugins_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.relay_plugins_reported_at
		            WHEN agents.relay_plugins_reported_at IS NOT NULL AND EXCLUDED.relay_plugins_reported_at <= agents.relay_plugins_reported_at THEN agents.relay_plugins_reported_at
		            ELSE EXCLUDED.relay_plugins_reported_at END,
		        revocation_caches = CASE
		            WHEN EXCLUDED.revocation_caches_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.revocation_caches
		            WHEN agents.revocation_caches_reported_at IS NOT NULL AND EXCLUDED.revocation_caches_reported_at <= agents.revocation_caches_reported_at THEN agents.revocation_caches
		            ELSE EXCLUDED.revocation_caches END,
		        revocation_caches_statement = CASE
		            WHEN EXCLUDED.revocation_caches_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.revocation_caches_statement
		            WHEN agents.revocation_caches_reported_at IS NOT NULL AND EXCLUDED.revocation_caches_reported_at <= agents.revocation_caches_reported_at THEN agents.revocation_caches_statement
		            ELSE EXCLUDED.revocation_caches_statement END,
		        revocation_caches_signature = CASE
		            WHEN EXCLUDED.revocation_caches_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.revocation_caches_signature
		            WHEN agents.revocation_caches_reported_at IS NOT NULL AND EXCLUDED.revocation_caches_reported_at <= agents.revocation_caches_reported_at THEN agents.revocation_caches_signature
		            ELSE EXCLUDED.revocation_caches_signature END,
		        revocation_caches_signer_fingerprint = CASE
		            WHEN EXCLUDED.revocation_caches_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.revocation_caches_signer_fingerprint
		            WHEN agents.revocation_caches_reported_at IS NOT NULL AND EXCLUDED.revocation_caches_reported_at <= agents.revocation_caches_reported_at THEN agents.revocation_caches_signer_fingerprint
		            ELSE EXCLUDED.revocation_caches_signer_fingerprint END,
		        revocation_caches_reported_at = CASE
		            WHEN EXCLUDED.revocation_caches_reported_at IS NULL OR agents.status = 'offboarded' THEN agents.revocation_caches_reported_at
		            WHEN agents.revocation_caches_reported_at IS NOT NULL AND EXCLUDED.revocation_caches_reported_at <= agents.revocation_caches_reported_at THEN agents.revocation_caches_reported_at
		            ELSE EXCLUDED.revocation_caches_reported_at END`,
		a.ID, a.TenantID, a.Name, a.Status, a.Version, agentRoleArray(a.Roles), a.LastSeenAt,
		a.WorkloadAPIServed, a.WorkloadAPISVIDs, a.WorkloadAPIReportedAt,
		a.EnrollmentProxyServing, a.EnrollmentProxySegment, a.EnrollmentProxyPublicURL,
		a.EnrollmentProxyHealthyUpstreams, a.EnrollmentProxyUnhealthyUpstreams, a.EnrollmentProxyUnknownUpstreams,
		a.EnrollmentProxyUpstreamFailures, a.EnrollmentProxyForwarded, a.EnrollmentProxyRefused,
		a.EnrollmentProxyLastForwardedAt, a.EnrollmentProxyLastFailoverAt, a.EnrollmentProxyReportedAt,
		relayPlugins, a.RelayPluginsStatement, signature,
		a.RelayPluginsSignerFingerprint, a.RelayPluginsReportedAt,
		revocationCaches, a.RevocationCachesStatement, cacheSignature,
		a.RevocationCachesSignerFingerprint, a.RevocationCachesReportedAt)
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
	var relayPlugins, revocationCaches []byte
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, status, version, roles, last_seen_at, created_at,
			        offboarded_at, COALESCE(offboarded_by, ''), COALESCE(offboard_reason, ''),
			        workload_api_served, workload_api_svids, workload_api_reported_at,
			        enrollment_proxy_serving, enrollment_proxy_segment, enrollment_proxy_public_url,
			        enrollment_proxy_healthy_upstreams, enrollment_proxy_unhealthy_upstreams, enrollment_proxy_unknown_upstreams,
			        enrollment_proxy_upstream_failures, enrollment_proxy_forwarded, enrollment_proxy_refused,
			        enrollment_proxy_last_forwarded_at, enrollment_proxy_last_failover_at, enrollment_proxy_reported_at,
			        relay_plugins, relay_plugins_statement, relay_plugins_signature,
			        relay_plugins_signer_fingerprint, relay_plugins_reported_at,
			        revocation_caches, revocation_caches_statement, revocation_caches_signature,
			        revocation_caches_signer_fingerprint, revocation_caches_reported_at
			   FROM agents WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&a.ID, &a.TenantID, &a.Name, &a.Status, &a.Version, &a.Roles, &a.LastSeenAt, &a.CreatedAt,
				&a.OffboardedAt, &a.OffboardedBy, &a.OffboardReason,
				&a.WorkloadAPIServed, &a.WorkloadAPISVIDs, &a.WorkloadAPIReportedAt,
				&a.EnrollmentProxyServing, &a.EnrollmentProxySegment, &a.EnrollmentProxyPublicURL,
				&a.EnrollmentProxyHealthyUpstreams, &a.EnrollmentProxyUnhealthyUpstreams, &a.EnrollmentProxyUnknownUpstreams,
				&a.EnrollmentProxyUpstreamFailures, &a.EnrollmentProxyForwarded, &a.EnrollmentProxyRefused,
				&a.EnrollmentProxyLastForwardedAt, &a.EnrollmentProxyLastFailoverAt, &a.EnrollmentProxyReportedAt,
				&relayPlugins, &a.RelayPluginsStatement, &a.RelayPluginsSignature,
				&a.RelayPluginsSignerFingerprint, &a.RelayPluginsReportedAt,
				&revocationCaches, &a.RevocationCachesStatement, &a.RevocationCachesSignature,
				&a.RevocationCachesSignerFingerprint, &a.RevocationCachesReportedAt)
	})
	if err == nil {
		err = json.Unmarshal(relayPlugins, &a.RelayPlugins)
	}
	if err == nil {
		err = json.Unmarshal(revocationCaches, &a.RevocationCaches)
	}
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
				        workload_api_served, workload_api_svids, workload_api_reported_at,
				        enrollment_proxy_serving, enrollment_proxy_segment, enrollment_proxy_public_url,
				        enrollment_proxy_healthy_upstreams, enrollment_proxy_unhealthy_upstreams, enrollment_proxy_unknown_upstreams,
				        enrollment_proxy_upstream_failures, enrollment_proxy_forwarded, enrollment_proxy_refused,
				        enrollment_proxy_last_forwarded_at, enrollment_proxy_last_failover_at, enrollment_proxy_reported_at,
				        relay_plugins, relay_plugins_statement, relay_plugins_signature,
				        relay_plugins_signer_fingerprint, relay_plugins_reported_at,
				        revocation_caches, revocation_caches_statement, revocation_caches_signature,
				        revocation_caches_signer_fingerprint, revocation_caches_reported_at
				   FROM agents
				  WHERE tenant_id = $1 AND (created_at, id) > ($2, $3)
				  ORDER BY created_at, id
				  LIMIT $4`,
				tenantID, *afterCreatedAt, afterID, limit)
		} else {
			rows, err = tx.Query(ctx,
				`SELECT id::text, tenant_id::text, name, status, version, roles, last_seen_at, created_at,
				        offboarded_at, COALESCE(offboarded_by, ''), COALESCE(offboard_reason, ''),
				        workload_api_served, workload_api_svids, workload_api_reported_at,
				        enrollment_proxy_serving, enrollment_proxy_segment, enrollment_proxy_public_url,
				        enrollment_proxy_healthy_upstreams, enrollment_proxy_unhealthy_upstreams, enrollment_proxy_unknown_upstreams,
				        enrollment_proxy_upstream_failures, enrollment_proxy_forwarded, enrollment_proxy_refused,
				        enrollment_proxy_last_forwarded_at, enrollment_proxy_last_failover_at, enrollment_proxy_reported_at,
				        relay_plugins, relay_plugins_statement, relay_plugins_signature,
				        relay_plugins_signer_fingerprint, relay_plugins_reported_at,
				        revocation_caches, revocation_caches_statement, revocation_caches_signature,
				        revocation_caches_signer_fingerprint, revocation_caches_reported_at
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
			var relayPlugins, revocationCaches []byte
			if err := rows.Scan(&a.ID, &a.TenantID, &a.Name, &a.Status, &a.Version, &a.Roles, &a.LastSeenAt, &a.CreatedAt,
				&a.OffboardedAt, &a.OffboardedBy, &a.OffboardReason,
				&a.WorkloadAPIServed, &a.WorkloadAPISVIDs, &a.WorkloadAPIReportedAt,
				&a.EnrollmentProxyServing, &a.EnrollmentProxySegment, &a.EnrollmentProxyPublicURL,
				&a.EnrollmentProxyHealthyUpstreams, &a.EnrollmentProxyUnhealthyUpstreams, &a.EnrollmentProxyUnknownUpstreams,
				&a.EnrollmentProxyUpstreamFailures, &a.EnrollmentProxyForwarded, &a.EnrollmentProxyRefused,
				&a.EnrollmentProxyLastForwardedAt, &a.EnrollmentProxyLastFailoverAt, &a.EnrollmentProxyReportedAt,
				&relayPlugins, &a.RelayPluginsStatement, &a.RelayPluginsSignature,
				&a.RelayPluginsSignerFingerprint, &a.RelayPluginsReportedAt,
				&revocationCaches, &a.RevocationCachesStatement, &a.RevocationCachesSignature,
				&a.RevocationCachesSignerFingerprint, &a.RevocationCachesReportedAt); err != nil {
				return err
			}
			if err := json.Unmarshal(relayPlugins, &a.RelayPlugins); err != nil {
				return fmt.Errorf("store: decode relay plugin census: %w", err)
			}
			if err := json.Unmarshal(revocationCaches, &a.RevocationCaches); err != nil {
				return fmt.Errorf("store: decode revocation cache posture: %w", err)
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// ListAgentRevocationCaches returns active relay cache rows in stable
// agent/cache/protocol order. The tenant filter is explicit even under RLS.
func (s *Store) ListAgentRevocationCaches(ctx context.Context, tenantID string, limit int) ([]AgentRevocationCache, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	var out []AgentRevocationCache
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, name, revocation_caches,
			        revocation_caches_signer_fingerprint, revocation_caches_reported_at
			   FROM agents
			  WHERE tenant_id = $1 AND status <> 'offboarded'
			    AND revocation_caches_reported_at IS NOT NULL
			  ORDER BY name, id
			  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var agentID, agentName, signerFingerprint string
			var raw []byte
			var reportedAt time.Time
			if err := rows.Scan(&agentID, &agentName, &raw, &signerFingerprint, &reportedAt); err != nil {
				return err
			}
			var entries []revcacheposture.Entry
			if err := json.Unmarshal(raw, &entries); err != nil {
				return fmt.Errorf("store: decode revocation cache posture: %w", err)
			}
			for _, entry := range entries {
				out = append(out, AgentRevocationCache{
					AgentID: agentID, AgentName: agentName, Entry: entry,
					SignerFingerprint: signerFingerprint, ReportedAt: reportedAt.UTC(),
				})
			}
		}
		return rows.Err()
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].AgentName != out[j].AgentName {
			return out[i].AgentName < out[j].AgentName
		}
		if out[i].Entry.Segment != out[j].Entry.Segment {
			return out[i].Entry.Segment < out[j].Entry.Segment
		}
		if out[i].Entry.CacheID != out[j].Entry.CacheID {
			return out[i].Entry.CacheID < out[j].Entry.CacheID
		}
		return out[i].Entry.Protocol < out[j].Entry.Protocol
	})
	if len(out) > limit {
		out = out[:limit]
	}
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
