// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CanReleasePAMDatabaseGatewayTicket checks the live projected session and
// its exact, unrecalled job in one database snapshot. The job key alone does
// not authorize a ticket.
func (s *Store) CanReleasePAMDatabaseGatewayTicket(ctx context.Context, session PAMSession,
	destination, key, agentRole string, payload []byte, now time.Time) (bool, error) {
	var live bool
	err := s.WithTenant(ctx, session.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (
		    SELECT 1 FROM pam_sessions p
		    WHERE p.tenant_id = $1 AND p.id = $2 AND p.delivery = 'gateway' AND p.status = 'active'
		      AND p.gateway_agent_id = $4::uuid AND p.gateway_ticket_digest = $5
		      AND p.requested_by = $6 AND p.idempotency_key = $7 AND p.expires_at > $8
		      AND p.ended_at IS NULL AND p.gateway_ended_at IS NULL AND p.revocation_requested_at IS NULL
		      AND (SELECT count(*) = 1 AND COALESCE(bool_and(
		          o.destination = $9 AND o.required_agent_role = $10 AND o.required_agent_id = $4::uuid
		          AND o.payload = $11 AND o.status IN ('pending', 'processing')
		          AND o.agent_recalled_at IS NULL AND o.delivered_at IS NULL AND o.claim_completed_at IS NULL
		      ), false)
		      FROM outbox o WHERE o.tenant_id = $1 AND o.idempotency_key = $3)
		    )`, session.TenantID, session.ID, key, session.GatewayAgentID, session.GatewayTicketDigest,
			session.RequestedBy, session.IdempotencyKey, now.UTC(), destination, agentRole, payload).Scan(&live)
	})
	return live, err
}

// ApplyPAMDatabaseGatewayStartedTx projects a start and its immutable agent job
// in the same tenant transaction. Exact replay never reopens an ended session.
func (s *Store) ApplyPAMDatabaseGatewayStartedTx(ctx context.Context, tx pgx.Tx, session PAMSession,
	destination, key, agentRole string, payload []byte) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"outbox-enqueue-if-absent\x1f"+session.TenantID+"\x1f"+key); err != nil {
		return err
	}
	var ready, matches bool
	err := tx.QueryRow(ctx, `SELECT status = 'active' AND gateway_ended_at IS NULL AND expires_at > now(),
			      target_type = $3 AND target_id = $4 AND role = $5 AND backend_ref = $6 AND
			      expires_at = $7 AND gateway_agent_id = $8::uuid AND delivery = 'gateway' AND
			      gateway_ticket_digest = $9 AND idempotency_key = $10
			 FROM pam_sessions WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		session.TenantID, session.ID, session.TargetType, session.TargetID, session.Role, session.BackendRef,
		session.ExpiresAt, session.GatewayAgentID, session.GatewayTicketDigest, session.IdempotencyKey).Scan(&ready, &matches)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if err := s.ApplyPAMSessionStartedTx(ctx, tx, session); err != nil {
			return err
		}
		ready = session.Status == "active" && time.Now().Before(session.ExpiresAt)
	case err != nil:
		return err
	case !matches:
		return fmt.Errorf("%w: database gateway start differs from the retained session", ErrIdempotencyConflict)
	}
	if !ready || effectsAlreadyQueued(ctx) {
		return nil
	}
	var oldDestination, oldRole, oldAgent string
	var oldPayload []byte
	err = tx.QueryRow(ctx, `SELECT destination, required_agent_role, COALESCE(required_agent_id::text, ''), payload
		 FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2 ORDER BY id LIMIT 1`,
		session.TenantID, key).Scan(&oldDestination, &oldRole, &oldAgent, &oldPayload)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		_, err = tx.Exec(ctx, `INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key,
			 required_agent_role, required_agent_id) VALUES ($1, $2, $2, $3, $4, $5, $6::uuid)`,
			session.TenantID, destination, payload, key, agentRole, session.GatewayAgentID)
		return err
	case err != nil:
		return err
	case oldDestination != destination || oldRole != agentRole || oldAgent != session.GatewayAgentID || !bytes.Equal(oldPayload, payload):
		return fmt.Errorf("%w: database gateway job differs from the retained start", ErrIdempotencyConflict)
	default:
		return nil
	}
}
