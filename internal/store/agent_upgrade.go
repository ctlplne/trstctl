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
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

const campaignCols = `id::text, tenant_id::text, target_version, status, current_ring,
	halted_at_ring, reason, created_by, created_at, updated_at`

func scanCampaign(row pgx.Row) (AgentUpgradeCampaign, error) {
	var c AgentUpgradeCampaign
	err := row.Scan(&c.ID, &c.TenantID, &c.TargetVersion, &c.Status, &c.CurrentRing,
		&c.HaltedAtRing, &c.Reason, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt)
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
func (s *Store) AgentsInRing(ctx context.Context, tenantID, ring string) ([]Agent, error) {
	var out []Agent
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, name, coalesce(version, '') FROM agents
			  WHERE tenant_id = $1 AND coalesce(upgrade_ring, '') = $2 ORDER BY id`, tenantID, ring)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a Agent
			if err := rows.Scan(&a.ID, &a.Name, &a.Version); err != nil {
				return err
			}
			a.TenantID = tenantID
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
