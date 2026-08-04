// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Which agent last performed a host-generated renewal for a target (epic B2).
//
// The console asks "who executes this endpoint", and the honest answer in this
// design is "whichever host-role agent claimed the work", because a target is
// not bound to a named agent — claiming is by role and vantage, not by
// assignment. So the truthful thing to show is not an assignment but an
// OBSERVATION: the agent that last actually did it, read from the signed
// receipt it produced.
//
// That distinction is worth keeping. An assignment column would suggest a
// binding an operator could rely on and this system does not enforce; a
// last-executed-by column says exactly what happened and nothing more.

// EndpointRenewalExecutor is the last agent observed renewing a target.
type EndpointRenewalExecutor struct {
	// TargetID is the deployment target's id, taken from the job payload.
	//
	// The ID, not the routing string. An earlier version keyed on
	// payload->>'target', which enqueueHostRenewal fills from the identity's
	// routing attribute and only falls back to the target's name — so the
	// console, which keys by target name, missed the join whenever an identity
	// carried an explicit route. The id is the same value on both sides by
	// construction.
	TargetID string
	// Agent is the common name from the receipt the agent signed.
	Agent string
	// Outcome is what that attempt reported.
	Outcome string
	// ObservedAt is when the receipt was recorded.
	ObservedAt string
}

// LastRenewalExecutors returns, per target, the most recent signed renewal
// receipt.
//
// Reads receipts rather than outbox rows because a receipt is SIGNED: the agent
// name on it was verified against the certificate the connection presented, so
// it is an attested fact rather than a field somebody wrote.
func (s *Store) LastRenewalExecutors(ctx context.Context, tenantID string) ([]EndpointRenewalExecutor, error) {
	var out []EndpointRenewalExecutor
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			// The tenant predicate sits on both sides of the join, not just the
			// outer query: AN-1 is enforced by RLS, and a join that reached a
			// second table without its own scope would be relying on the outer
			// filter to carry it.
			`WITH scoped_receipts AS (
			     SELECT job_id, agent, outcome, observed_at
			       FROM agent_job_receipts
			      WHERE tenant_id = $1 AND state = 'verified' AND kind = $2
			 ), scoped_jobs AS (
			     -- convert_from(...)::jsonb, not payload->>'target'.
			     --
			     -- outbox.payload is bytea (migrations/0003_outbox.sql), and
			     -- PostgreSQL has no ->> operator with a bytea left operand: the
			     -- earlier form failed at plan time on EVERY call, and because
			     -- the caller treats this read as best-effort the console's
			     -- "Last renewed by" column was simply always empty. A query
			     -- that cannot run is indistinguishable from an estate that has
			     -- never renewed, which is the reading an operator would take.
			     SELECT id, convert_from(payload, 'UTF8')::jsonb->>'target_id' AS target_id
			       FROM outbox
			      WHERE tenant_id = $1 AND destination = $2
			 )
			 SELECT DISTINCT ON (j.target_id)
			        coalesce(j.target_id, ''), r.agent, r.outcome,
			        to_char(r.observed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
			   FROM scoped_receipts r
			   JOIN scoped_jobs j ON j.id = r.job_id
			  WHERE j.target_id IS NOT NULL AND j.target_id <> ''
			  ORDER BY j.target_id, r.observed_at DESC`,
			tenantID, "endpoint.renew")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec EndpointRenewalExecutor
			if err := rows.Scan(&rec.TargetID, &rec.Agent, &rec.Outcome, &rec.ObservedAt); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}
