// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrPAMGatewayPoolNotFound is a gateway pool that does not exist or was
// deleted.
var ErrPAMGatewayPoolNotFound = errors.New("store: PAM gateway pool not found")

// PAMGatewayMember is one gateway of a pool (A278): the agent and the
// address requesters reach it at. A draining member takes no new sessions.
type PAMGatewayMember struct {
	AgentID  string `json:"agent_id"`
	Address  string `json:"address"`
	Draining bool   `json:"draining,omitempty"`
}

// PAMGatewayPool is a set of gateways that share sessions (A278): a target
// bound to any member is served by whichever healthy member a session
// starts on, and that member owns the session.
type PAMGatewayPool struct {
	Name      string
	Members   []PAMGatewayMember
	Revision  int64
	SavedBy   string
	SavedAt   time.Time
	DeletedAt *time.Time
}

const pamGatewayPoolColumns = `name, members, revision, saved_by, saved_at, deleted_at`

func scanPAMGatewayPool(row pgx.Row) (PAMGatewayPool, error) {
	var p PAMGatewayPool
	var members []byte
	if err := row.Scan(&p.Name, &members, &p.Revision, &p.SavedBy, &p.SavedAt, &p.DeletedAt); err != nil {
		return p, err
	}
	err := json.Unmarshal(members, &p.Members)
	return p, err
}

// ApplyPAMGatewayPoolSavedTx projects pam.gateway_pool.saved at its
// revision; saving a deleted pool's name again brings it back.
func (s *Store) ApplyPAMGatewayPoolSavedTx(ctx context.Context, tx pgx.Tx, tenantID string, p PAMGatewayPool) error {
	members := p.Members
	if members == nil {
		members = []PAMGatewayMember{}
	}
	raw, err := json.Marshal(members)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO pam_gateway_pools AS cur (tenant_id, name, members, revision, saved_by, saved_at)
		VALUES ($1, $2, $3::jsonb, $4, $5, $6)
		ON CONFLICT (tenant_id, name) DO UPDATE SET
		    members = EXCLUDED.members, revision = EXCLUDED.revision, saved_by = EXCLUDED.saved_by,
		    saved_at = EXCLUDED.saved_at, deleted_at = NULL
		  WHERE cur.revision < EXCLUDED.revision`,
		tenantID, p.Name, raw, p.Revision, p.SavedBy, p.SavedAt.UTC())
	return err
}

// ApplyPAMGatewayPoolDeletedTx projects pam.gateway_pool.deleted at its
// revision.
func (s *Store) ApplyPAMGatewayPoolDeletedTx(ctx context.Context, tx pgx.Tx, tenantID, name string, revision int64, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE pam_gateway_pools SET deleted_at = $4, revision = $3
		WHERE tenant_id = $1 AND name = $2 AND revision < $3`, tenantID, name, revision, at.UTC())
	return err
}

// GetPAMGatewayPoolAny returns a pool by name, deleted or not, so a save can
// continue its revisions.
func (s *Store) GetPAMGatewayPoolAny(ctx context.Context, tenantID, name string) (PAMGatewayPool, error) {
	var p PAMGatewayPool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		p, err = scanPAMGatewayPool(tx.QueryRow(ctx, `SELECT `+pamGatewayPoolColumns+` FROM pam_gateway_pools
			WHERE tenant_id = $1 AND name = $2`, tenantID, name))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PAMGatewayPool{}, ErrPAMGatewayPoolNotFound
	}
	return p, err
}

// GetPAMGatewayPool returns a live pool.
func (s *Store) GetPAMGatewayPool(ctx context.Context, tenantID, name string) (PAMGatewayPool, error) {
	p, err := s.GetPAMGatewayPoolAny(ctx, tenantID, name)
	if err == nil && p.DeletedAt != nil {
		return PAMGatewayPool{}, ErrPAMGatewayPoolNotFound
	}
	return p, err
}

// ListPAMGatewayPools returns a tenant's live pools by name.
func (s *Store) ListPAMGatewayPools(ctx context.Context, tenantID string) ([]PAMGatewayPool, error) {
	out := []PAMGatewayPool{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pamGatewayPoolColumns+` FROM pam_gateway_pools
			WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY name`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanPAMGatewayPool(rows)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// PAMGatewayPoolFor returns the live pool a gateway agent is a member of.
func (s *Store) PAMGatewayPoolFor(ctx context.Context, tenantID, agentID string) (PAMGatewayPool, bool, error) {
	var p PAMGatewayPool
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		p, err = scanPAMGatewayPool(tx.QueryRow(ctx, `SELECT `+pamGatewayPoolColumns+` FROM pam_gateway_pools
			WHERE tenant_id = $1 AND deleted_at IS NULL AND members @> jsonb_build_array(jsonb_build_object('agent_id', $2::text))
			ORDER BY name LIMIT 1`, tenantID, agentID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	return p, found, err
}

// CountLiveGatewaySessions counts each gateway's active, gateway-delivered
// sessions that have not ended, for choosing the least loaded member.
func (s *Store) CountLiveGatewaySessions(ctx context.Context, tenantID string, agentIDs []string, now time.Time) (map[string]int, error) {
	out := map[string]int{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT gateway_agent_id::text, count(*) FROM pam_sessions
			WHERE tenant_id = $1 AND delivery = 'gateway' AND status = 'active' AND gateway_ended_at IS NULL
			  AND expires_at > $2 AND gateway_agent_id::text = ANY($3)
			GROUP BY gateway_agent_id`, tenantID, now.UTC(), agentIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var n int
			if err := rows.Scan(&id, &n); err != nil {
				return err
			}
			out[id] = n
		}
		return rows.Err()
	})
	return out, err
}

// PendingAgentUpgrade reports whether an agent has a self-upgrade job queued
// or in flight (A278: a pooled gateway drains before it upgrades).
func (s *Store) PendingAgentUpgrade(ctx context.Context, tenantID, agentID string) (bool, error) {
	var pending bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM outbox
			WHERE tenant_id = $1 AND destination = 'agent.upgrade' AND required_agent_id::text = $2
			  AND status IN ('pending', 'processing'))`, tenantID, agentID).Scan(&pending)
	})
	return pending, err
}
