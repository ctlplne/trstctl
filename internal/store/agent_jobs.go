// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// The agent job ledger (epic A1).
//
// Work that touches a customer's estate is decided here and executed there. The
// control plane has no route into a host — that is the whole topology — so the
// agent comes and takes the work over the connection it opened.
//
// The ledger underneath is the outbox, unchanged: an entry is committed in the
// same transaction as the state change that caused it (AN-6), carries an
// idempotency key (AN-5), and is at-least-once. What changes is the consumer.
//
// A claim is a lease. An agent that dies mid-job stops extending it and the entry
// returns to the queue instead of being stuck to a machine that is gone. Claiming
// uses SKIP LOCKED, so two agents polling at the same instant take different
// work rather than blocking on each other or both taking the same job. Every
// query here is tenant-scoped under RLS (AN-1); the one cross-tenant call is the
// leader's lease sweep and is marked as such.

// AgentJob is one claimable unit of estate-touching work.
type AgentJob struct {
	ID             int64
	TenantID       string
	Destination    string
	Payload        []byte
	IdempotencyKey string
	Attempts       int
	ClaimAttempts  int
	ClaimExpiresAt time.Time
	CreatedAt      time.Time
}

// ClaimAgentJobs leases up to limit pending entries on the given destinations to
// one agent, returning what it took.
//
// SKIP LOCKED is the important word: a fleet polling in lockstep must fan out
// across the queue, not serialize on its head. An entry whose lease has expired
// is claimable again, which is how a dead agent's work comes back without anyone
// intervening.
func (s *Store) ClaimAgentJobs(ctx context.Context, tenantID, agentID string, destinations []string, limit int, lease time.Duration, now time.Time) ([]AgentJob, error) {
	if limit <= 0 || len(destinations) == 0 || lease <= 0 {
		return nil, nil
	}
	now = now.UTC()
	expires := now.Add(lease)

	var out []AgentJob
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// The canonical claim: pick the batch under FOR UPDATE SKIP LOCKED in a
		// CTE, then update exactly those rows. Written as `IN (SELECT ... LIMIT)`
		// the planner is free to re-evaluate the subquery per row, which silently
		// claims the whole queue instead of one batch — a fleet-wide thundering
		// herd hiding behind correct-looking SQL.
		rows, err := tx.Query(ctx,
			`WITH claimable AS (
			        SELECT c.id
			          FROM outbox AS c
			         WHERE c.tenant_id = $1
			           AND c.destination = ANY($3::text[])
			           AND c.status = 'pending'
			           AND c.delivered_at IS NULL
			           AND (c.claimed_by_agent_id IS NULL OR c.claim_expires_at < $5)
			         ORDER BY c.id
			         LIMIT $4
			         FOR UPDATE SKIP LOCKED
			 )
			 UPDATE outbox AS o
			    SET claimed_by_agent_id = $2::uuid,
			        claim_expires_at    = $6,
			        claim_attempts      = o.claim_attempts + 1
			   FROM claimable AS k
			  WHERE o.id = k.id
			  RETURNING o.id, o.tenant_id::text, o.destination, o.payload, o.idempotency_key,
			            o.attempts, o.claim_attempts, o.claim_expires_at, o.created_at`,
			tenantID, agentID, destinations, limit, now, expires)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var job AgentJob
			if err := rows.Scan(&job.ID, &job.TenantID, &job.Destination, &job.Payload,
				&job.IdempotencyKey, &job.Attempts, &job.ClaimAttempts, &job.ClaimExpiresAt, &job.CreatedAt); err != nil {
				return err
			}
			out = append(out, job)
		}
		return rows.Err()
	})
	return out, err
}

// ExtendAgentJobClaim pushes a lease out while the agent is still working. It
// only moves a lease the caller actually holds: an agent cannot extend another
// agent's claim, which is what keeps "the holder is alive" a real statement.
func (s *Store) ExtendAgentJobClaim(ctx context.Context, tenantID, agentID string, jobID int64, until time.Time) (bool, error) {
	var extended bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE outbox
			    SET claim_expires_at = $4
			  WHERE tenant_id = $1
			    AND id = $3
			    AND claimed_by_agent_id = $2::uuid
			    AND claim_completed_at IS NULL`,
			tenantID, agentID, jobID, until.UTC())
		if err != nil {
			return err
		}
		extended = tag.RowsAffected() == 1
		return nil
	})
	return extended, err
}

// CompleteAgentJob records that the claiming agent finished the work. The entry
// leaves the queue the same way a control-plane delivery would, so the outbox's
// existing accounting, GC and observability keep working unchanged.
//
// Completing is idempotent on the claim: a replayed report from the same agent
// finds the entry already delivered and changes nothing, which is what makes an
// at-least-once report safe to send twice.
func (s *Store) CompleteAgentJob(ctx context.Context, tenantID, agentID string, jobID int64, at time.Time) (bool, error) {
	var completed bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE outbox
			    SET status             = 'delivered',
			        delivered_at       = $4,
			        claim_completed_at = $4,
			        attempts           = attempts + 1
			  WHERE tenant_id = $1
			    AND id = $3
			    AND claimed_by_agent_id = $2::uuid
			    AND claim_completed_at IS NULL`,
			tenantID, agentID, jobID, at.UTC())
		if err != nil {
			return err
		}
		completed = tag.RowsAffected() == 1
		return nil
	})
	return completed, err
}

// ReleaseAgentJob hands a job back after a failed attempt, recording why. The
// entry becomes claimable again immediately — by this agent or another — because
// a failure on one host is not evidence the work is impossible.
func (s *Store) ReleaseAgentJob(ctx context.Context, tenantID, agentID string, jobID int64, reason string) (bool, error) {
	var released bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE outbox
			    SET claimed_by_agent_id = NULL,
			        claim_expires_at    = NULL,
			        attempts            = attempts + 1,
			        last_error          = NULLIF($4, '')
			  WHERE tenant_id = $1
			    AND id = $3
			    AND claimed_by_agent_id = $2::uuid
			    AND claim_completed_at IS NULL`,
			tenantID, agentID, jobID, reason)
		if err != nil {
			return err
		}
		released = tag.RowsAffected() == 1
		return nil
	})
	return released, err
}

// ReclaimExpiredAgentJobs returns lapsed leases to the queue and reports how many
// it freed. An agent that is killed, partitioned, or simply stops calling home
// leaves work behind; without this the work waits for a machine that is never
// coming back.
func (s *Store) ReclaimExpiredAgentJobs(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.SystemPool().Exec(ctx,
		//trstctl:system-query — cross-tenant by design: the leader sweeps lapsed agent claims for every tenant so a dead agent's work returns to its own tenant's queue. It reads and clears lease bookkeeping only, never payloads.
		`UPDATE outbox
		    SET claimed_by_agent_id = NULL,
		        claim_expires_at    = NULL
		  WHERE claimed_by_agent_id IS NOT NULL
		    AND claim_completed_at IS NULL
		    AND claim_expires_at < $1`, now.UTC())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// AgentJobQueueDepth is per-destination claim health for the operations surface:
// how much work is waiting, how much is in flight, and how old the oldest
// unclaimed entry is. Counts only — never payloads, never tenant identifiers.
type AgentJobQueueDepth struct {
	Destination       string
	Pending           int
	Claimed           int
	OldestUnclaimedAt *time.Time
}

// AgentJobQueueDepths reports process-wide job-ledger health across every tenant.
// It is deliberately shaped like the existing bulkhead surface: an operator needs
// to know the fabric is moving without being handed anyone's data to know it.
func (s *Store) AgentJobQueueDepths(ctx context.Context, destinations []string) ([]AgentJobQueueDepth, error) {
	if len(destinations) == 0 {
		return nil, nil
	}
	rows, err := s.SystemPool().Query(ctx,
		//trstctl:system-query — cross-tenant by design: process-wide queue depth for the operations surface. It aggregates counts and one timestamp per destination; no tenant id, payload or credential leaves this query.
		`SELECT destination,
		        count(*) FILTER (WHERE claimed_by_agent_id IS NULL)::int,
		        count(*) FILTER (WHERE claimed_by_agent_id IS NOT NULL)::int,
		        min(created_at) FILTER (WHERE claimed_by_agent_id IS NULL)
		   FROM outbox
		  WHERE destination = ANY($1::text[])
		    AND status = 'pending'
		    AND delivered_at IS NULL
		  GROUP BY destination
		  ORDER BY destination`, destinations)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentJobQueueDepth
	for rows.Next() {
		var d AgentJobQueueDepth
		if err := rows.Scan(&d.Destination, &d.Pending, &d.Claimed, &d.OldestUnclaimedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
