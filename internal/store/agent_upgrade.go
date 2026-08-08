// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// AgentUpgradeCampaign is a staged rollout of an agent version (A5).
type AgentUpgradeCampaign struct {
	ID            string
	TenantID      string
	TargetVersion string
	Status        string
	CurrentRing   string
	// HaltedAtRing is the ring that stopped the rollout. Resume restarts THERE.
	HaltedAtRing string
	Reason       string
	CreatedBy    string
	// ArtifactsJSON is the operator-published per-platform download set, raw
	// from the jsonb column. nil means OBSERVE-ONLY: the campaign gates rings
	// on the versions it sees but dispatches nothing.
	ArtifactsJSON []byte
	// DispatchRound counts ring dispatches; DispatchedRing is the ring the
	// current round went to. The sweep dispatches whenever DispatchedRing
	// disagrees with the current ring, which is what makes dispatch
	// crash-safe: a crash between "ring entered" and "jobs enqueued" heals on
	// the next sweep.
	DispatchRound  int
	DispatchedRing string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

const campaignCols = `id::text, tenant_id::text, target_version, status, current_ring,
	halted_at_ring, reason, created_by, artifacts, coalesce(dispatch_round, 0),
	coalesce(dispatched_ring, ''), created_at, updated_at`

func scanCampaign(row pgx.Row) (AgentUpgradeCampaign, error) {
	var c AgentUpgradeCampaign
	err := row.Scan(&c.ID, &c.TenantID, &c.TargetVersion, &c.Status, &c.CurrentRing,
		&c.HaltedAtRing, &c.Reason, &c.CreatedBy, &c.ArtifactsJSON, &c.DispatchRound,
		&c.DispatchedRing, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

// ActiveAgentUpgradeCampaign returns the tenant's live campaign, if any.
func (s *Store) ActiveAgentUpgradeCampaign(ctx context.Context, tenantID string) (AgentUpgradeCampaign, bool, error) {
	var out AgentUpgradeCampaign
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		c, err := scanCampaign(tx.QueryRow(ctx,
			`SELECT `+campaignCols+` FROM agent_upgrade_campaigns
			  WHERE tenant_id = $1 AND status IN ('pending','running','halted','paused')
			  ORDER BY created_at DESC LIMIT 1`, tenantID))
		if err != nil {
			if pgx.ErrNoRows.Error() == err.Error() {
				return nil
			}
			return err
		}
		out, found = c, true
		return nil
	})
	return out, found, err
}

// AgentRingCounts reports how many agents sit in each ring, and how many are
// UNASSIGNED.
//
// Unassigned is counted separately and never folded into broad: an agent nobody
// deliberately placed must not join the largest ring by default, and an operator
// needs to see that the fleet is not fully triaged before starting a rollout.
func (s *Store) AgentRingCounts(ctx context.Context, tenantID string) (map[string]int, error) {
	out := map[string]int{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT coalesce(nullif(upgrade_ring, ''), 'unassigned'), count(*)
			   FROM agents WHERE tenant_id = $1 GROUP BY 1`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ring string
			var n int
			if err := rows.Scan(&ring, &n); err != nil {
				return err
			}
			out[ring] = n
		}
		return rows.Err()
	})
	return out, err
}

// AgentVersionHistogram reports how many agents run each version.
//
// The fleet's version spread is what tells an operator whether a rollout
// actually landed. A campaign that reports "complete" while the histogram still
// shows the old version is the disagreement worth surfacing.
func (s *Store) AgentVersionHistogram(ctx context.Context, tenantID string) (map[string]int, error) {
	out := map[string]int{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT coalesce(nullif(version, ''), 'unknown'), count(*)
			   FROM agents WHERE tenant_id = $1 GROUP BY 1`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v string
			var n int
			if err := rows.Scan(&v, &n); err != nil {
				return err
			}
			out[v] = n
		}
		return rows.Err()
	})
	return out, err
}

// AgentsInRing lists the agents a ring would dispatch to.
//
// last_seen_at is scanned because the sweep's grace logic reads it. It was not,
// originally, which made the "seen recently, still mid-upgrade" branch dead
// code: every LastSeenAt came back nil, so a live heartbeating fleet was scored
// silent on the first sweep and every observe-mode campaign halted instantly.
func (s *Store) AgentsInRing(ctx context.Context, tenantID, ring string) ([]Agent, error) {
	var out []Agent
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, name, coalesce(version, ''), last_seen_at FROM agents
			  WHERE tenant_id = $1 AND coalesce(upgrade_ring, '') = $2 ORDER BY id`, tenantID, ring)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a Agent
			if err := rows.Scan(&a.ID, &a.Name, &a.Version, &a.LastSeenAt); err != nil {
				return err
			}
			a.TenantID = tenantID
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// UpgradeDispatchStatus is one dispatched agent's progress through a round, as
// the sweep reads it: the dispatch, the latest verified receipt for its job (if
// any), and the agent's currently observed state.
type UpgradeDispatchStatus struct {
	AgentID      string
	DispatchedAt time.Time
	// ReceiptOutcome is the outcome field of the newest signature-verified
	// receipt for the dispatched job: 'executed', 'failed', or '' when no
	// verified receipt exists. Rejected receipts are excluded on purpose — a
	// claim whose signature did not check out is not evidence of anything.
	ReceiptOutcome string
	AgentVersion   string
	AgentLastSeen  *time.Time
}

// AgentUpgradeDispatchStatuses reads one round's dispatches joined to their
// receipts and to the agents' live state. The dispatch rows are the
// denominator: an agent moved into the ring after dispatch is not scored, and
// one moved out is still scored — it was told to upgrade.
func (s *Store) AgentUpgradeDispatchStatuses(ctx context.Context, tenantID, campaignID string, round int) ([]UpgradeDispatchStatus, error) {
	var out []UpgradeDispatchStatus
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT d.agent_id::text, d.dispatched_at,
			        coalesce(r.outcome, ''), coalesce(a.version, ''), a.last_seen_at
			   FROM agent_upgrade_dispatches d
			   LEFT JOIN outbox o
			     ON o.tenant_id = d.tenant_id
			    AND o.idempotency_key = d.job_key
			    AND o.destination = 'agent.upgrade'
			   LEFT JOIN LATERAL (
			        SELECT outcome FROM agent_job_receipts r
			         WHERE r.tenant_id = d.tenant_id AND r.job_id = o.id
			           AND r.state = 'verified'
			         ORDER BY r.attempt DESC, r.observed_at DESC
			         LIMIT 1
			   ) r ON true
			   LEFT JOIN agents a ON a.tenant_id = d.tenant_id AND a.id = d.agent_id
			  WHERE d.tenant_id = $1 AND d.campaign_id = $2 AND d.round = $3
			  ORDER BY d.agent_id`,
			tenantID, campaignID, round)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var st UpgradeDispatchStatus
			if err := rows.Scan(&st.AgentID, &st.DispatchedAt, &st.ReceiptOutcome,
				&st.AgentVersion, &st.AgentLastSeen); err != nil {
				return err
			}
			out = append(out, st)
		}
		return rows.Err()
	})
	return out, err
}
