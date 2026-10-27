// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// A191: operator-granted agent roles, projected from agent.roles.granted and
// marked applied by the agent.cert.renewed (schema 2) that signs them. The
// certificate stays what the claim path reads; a grant row grants nothing until
// a renewal has put its roles into a signed SAN. Who granted the roles and why
// stay in the event, where subject erasure reaches them; the row holds no
// names or free text.

// AgentRoleGrant is the newest role grant recorded for one agent.
type AgentRoleGrant struct {
	TenantID      string
	AgentID       string
	Roles         []string
	GrantedAt     time.Time
	EventID       string
	EventSeq      uint64
	AppliedSerial string
	AppliedAt     *time.Time
}

// Pending reports whether no renewal has signed the grant yet.
func (g AgentRoleGrant) Pending() bool { return g.AppliedAt == nil }

// ApplyAgentRolesGrantedTx projects a grant. A newer grant replaces the row and
// starts pending again; an older or repeated one (a replay, or two grants
// projected out of their stream order) changes nothing.
func (s *Store) ApplyAgentRolesGrantedTx(ctx context.Context, tx pgx.Tx, g AgentRoleGrant) error {
	if g.EventSeq == 0 || g.EventSeq > math.MaxInt64 {
		return errors.New("store: an agent role grant needs its event's stream sequence")
	}
	if len(g.Roles) == 0 {
		return errors.New("store: an agent role grant names at least one role")
	}
	_, err := tx.Exec(ctx, `INSERT INTO agent_role_grants
		(tenant_id, agent_id, roles, granted_at, event_id, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, agent_id) DO UPDATE
		   SET roles = EXCLUDED.roles, granted_at = EXCLUDED.granted_at,
		       event_id = EXCLUDED.event_id, event_sequence = EXCLUDED.event_sequence,
		       applied_serial = '', applied_at = NULL
		 WHERE agent_role_grants.tenant_id = EXCLUDED.tenant_id
		   AND agent_role_grants.event_sequence < EXCLUDED.event_sequence`,
		g.TenantID, g.AgentID, g.Roles, g.GrantedAt.UTC(), g.EventID, int64(g.EventSeq))
	return err
}

// ApplyAgentRoleGrantAppliedTx marks the grant recorded by grantEventID as
// signed into the certificate with serial. A grant replaced since that renewal
// began keeps waiting: the renewal signed the older roles, not the newer ones.
func (s *Store) ApplyAgentRoleGrantAppliedTx(ctx context.Context, tx pgx.Tx, tenantID, agentID, grantEventID, serial string, appliedAt time.Time) error {
	if grantEventID == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE agent_role_grants
		   SET applied_serial = $4, applied_at = $5
		 WHERE tenant_id = $1 AND agent_id = $2 AND event_id = $3 AND applied_at IS NULL`,
		tenantID, agentID, grantEventID, serial, appliedAt.UTC())
	return err
}

const agentRoleGrantColumns = `tenant_id::text, agent_id::text, roles, granted_at, event_id,
	event_sequence, applied_serial, applied_at`

func scanAgentRoleGrant(row pgx.Row) (AgentRoleGrant, error) {
	var (
		g   AgentRoleGrant
		seq int64
	)
	err := row.Scan(&g.TenantID, &g.AgentID, &g.Roles, &g.GrantedAt, &g.EventID,
		&seq, &g.AppliedSerial, &g.AppliedAt)
	if seq > 0 {
		g.EventSeq = uint64(seq)
	}
	return g, err
}

// AgentRoleGrant returns the newest grant recorded for the agent; found is
// false when an operator never granted it roles after enrollment.
func (s *Store) AgentRoleGrant(ctx context.Context, tenantID, agentID string) (AgentRoleGrant, bool, error) {
	var (
		g     AgentRoleGrant
		found bool
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		g, err = scanAgentRoleGrant(tx.QueryRow(ctx, `SELECT `+agentRoleGrantColumns+`
			  FROM agent_role_grants WHERE tenant_id = $1 AND agent_id = $2`, tenantID, agentID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	return g, found, err
}

// AgentRoleGrants returns, by agent ID, the newest grant for each of agentIDs
// that has one.
func (s *Store) AgentRoleGrants(ctx context.Context, tenantID string, agentIDs []string) (map[string]AgentRoleGrant, error) {
	out := make(map[string]AgentRoleGrant, len(agentIDs))
	if len(agentIDs) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+agentRoleGrantColumns+`
			  FROM agent_role_grants WHERE tenant_id = $1 AND agent_id = ANY($2::uuid[])`, tenantID, agentIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g, err := scanAgentRoleGrant(rows)
			if err != nil {
				return err
			}
			out[g.AgentID] = g
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
