// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// IdentityWorkStop is authority already recorded by an identity lifecycle event.
// Operational lease expiry can delay applying that authority to a job; it must
// never manufacture a new lifecycle transition or erase the original attempt.
type IdentityWorkStop struct {
	IdentityID string
	Sequence   uint64
	OccurredAt time.Time
}

// TerminalIdentityWorkStopsTx locks a bounded set of terminal identities before
// their jobs, matching lifecycle command lock order. A manually edited status
// without a retained terminal transition supplies no cancellation authority.
func (s *Store) TerminalIdentityWorkStopsTx(ctx context.Context, tx pgx.Tx, tenantID, identityID string, now time.Time) ([]IdentityWorkStop, error) {
	rows, err := tx.Query(ctx, `SELECT i.id::text, stop.seq, stop.occurred_at
	 FROM identities i
	 JOIN LATERAL (
	   SELECT tr.seq, tr.occurred_at FROM identity_transitions tr
	   WHERE tr.tenant_id=$1 AND tr.identity_id=i.id AND tr.to_state=i.status
	     AND tr.event_type IN ('identity.revoked','identity.retired')
	   ORDER BY tr.seq DESC LIMIT 1
	 ) stop ON true
	 WHERE i.tenant_id=$1 AND i.status IN ('revoked','retired')
	   AND ($2='' OR i.id::text=$2)
	   AND (EXISTS (
	     SELECT 1 FROM outbox job WHERE job.tenant_id=$1
	       AND job.status IN ('pending','processing') AND job.delivered_at IS NULL AND job.claim_completed_at IS NULL
	       AND (job.status <> 'processing' OR job.lease_until IS NULL OR job.lease_until <= $3)
	       AND (job.claimed_by_agent_id IS NULL OR job.claim_expires_at <= $3)
	       AND CASE WHEN job.destination IN ('ca.issue','ca.renew','endpoint.renew')
	         THEN convert_from(job.payload,'UTF8')::jsonb->>'identity_id'=i.id::text ELSE false END)
	     OR EXISTS (
	       SELECT 1 FROM lifecycle_rotation_runs run JOIN outbox job ON job.tenant_id=$1
	         AND CASE WHEN job.destination IN ('ca.renew','endpoint.renew')
	           THEN convert_from(job.payload,'UTF8')::jsonb->>'identity_id'=i.id::text
	             AND (job.id=run.outbox_id OR convert_from(job.payload,'UTF8')::jsonb->>'rotation_run_id'=run.id::text)
	           ELSE false END
       WHERE run.tenant_id=$1 AND run.identity_id=i.id AND run.status='running' AND job.status='cancelled'
         AND NOT EXISTS (
           SELECT 1 FROM outbox active WHERE active.tenant_id=$1 AND active.status IN ('pending','processing')
             AND CASE WHEN active.destination IN ('ca.issue','ca.renew','endpoint.renew')
               THEN convert_from(active.payload,'UTF8')::jsonb->>'identity_id'=i.id::text
                 AND (active.id=run.outbox_id OR convert_from(active.payload,'UTF8')::jsonb->>'rotation_run_id'=run.id::text)
               ELSE false END)))
	 ORDER BY i.id LIMIT 100 FOR UPDATE OF i SKIP LOCKED`, tenantID, identityID, now.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var stops []IdentityWorkStop
	for rows.Next() {
		var stop IdentityWorkStop
		if err := rows.Scan(&stop.IdentityID, &stop.Sequence, &stop.OccurredAt); err != nil {
			return nil, err
		}
		stops = append(stops, stop)
	}
	return stops, rows.Err()
}

// ApplyIdentityWorkStopTx is called only by the projector. Cancellation stops
// future issue/renew attempts, never claims delivery or remote compensation.
// Live executor leases and completed effects retain their original state.
func (s *Store) ApplyIdentityWorkStopTx(ctx context.Context, tx pgx.Tx, tenantID string, stop IdentityWorkStop, now time.Time) (int64, error) {
	tag, err := tx.Exec(ctx, `WITH idle AS (
	 SELECT job.id FROM outbox job
	 WHERE job.tenant_id=$1 AND job.status IN ('pending','processing')
	   AND job.delivered_at IS NULL AND job.claim_completed_at IS NULL
	   AND (job.status <> 'processing' OR job.lease_until IS NULL OR job.lease_until <= $3)
	   AND (job.claimed_by_agent_id IS NULL OR job.claim_expires_at <= $3)
	   AND CASE WHEN job.destination IN ('ca.issue','ca.renew','endpoint.renew')
	     THEN convert_from(job.payload,'UTF8')::jsonb->>'identity_id'=$2 ELSE false END
	 ORDER BY job.id LIMIT 100 FOR UPDATE SKIP LOCKED
	) UPDATE outbox job SET status='cancelled'
	 FROM idle WHERE job.tenant_id=$1 AND job.id=idle.id`, tenantID, stop.IdentityID, now.UTC())
	if err != nil {
		return 0, err
	}
	// The parent ca.renew may already be delivered because it handed the work
	// to an endpoint.renew job. Only close its running rotation when that exact
	// child (or the parent itself) was canceled and no related work remains.
	_, err = tx.Exec(ctx, `UPDATE lifecycle_rotation_runs run
	 SET status='cancelled', completed_at=$3, updated_at=GREATEST(updated_at,$3),
	     latest_event_sequence=GREATEST(COALESCE(latest_event_sequence,0),$4)
	 WHERE run.tenant_id=$1 AND run.identity_id=$2 AND run.status='running'
	   AND EXISTS (
	     SELECT 1 FROM outbox job WHERE job.tenant_id=$1 AND job.status='cancelled'
	       AND CASE WHEN job.destination IN ('ca.issue','ca.renew','endpoint.renew')
	         THEN convert_from(job.payload,'UTF8')::jsonb->>'identity_id'=$2::text
	           AND (job.id=run.outbox_id OR convert_from(job.payload,'UTF8')::jsonb->>'rotation_run_id'=run.id::text)
	         ELSE false END)
	   AND NOT EXISTS (
	     SELECT 1 FROM outbox job WHERE job.tenant_id=$1 AND job.status IN ('pending','processing')
	       AND CASE WHEN job.destination IN ('ca.issue','ca.renew','endpoint.renew')
	         THEN convert_from(job.payload,'UTF8')::jsonb->>'identity_id'=$2::text
	           AND (job.id=run.outbox_id OR convert_from(job.payload,'UTF8')::jsonb->>'rotation_run_id'=run.id::text)
	         ELSE false END)`, tenantID, stop.IdentityID, stop.OccurredAt, stop.Sequence)
	return tag.RowsAffected(), err
}

// TenantsWithStoppedIdentityWork enumerates a bounded maintenance batch. Each
// actual cancellation re-enters the tenant's RLS context and checks its events.
func (s *Store) TenantsWithStoppedIdentityWork(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.SystemPool().Query(ctx,
		//trstctl:system-query — cross-tenant system maintenance returns at most 100 tenant_id values with event-derived stopped work; no command payload leaves PostgreSQL, and cancellation re-enters each tenant's RLS context.
		`SELECT DISTINCT i.tenant_id::text FROM identities i JOIN outbox job
		 ON job.tenant_id=i.tenant_id
		 AND CASE WHEN job.destination IN ('ca.issue','ca.renew','endpoint.renew')
		   THEN convert_from(job.payload,'UTF8')::jsonb->>'identity_id'=i.id::text ELSE false END
		 WHERE i.status IN ('revoked','retired')
		   AND EXISTS (SELECT 1 FROM identity_transitions tr
		     WHERE tr.tenant_id=i.tenant_id AND tr.identity_id=i.id AND tr.to_state=i.status
		       AND tr.event_type IN ('identity.revoked','identity.retired'))
		   AND ((job.status IN ('pending','processing')
		     AND job.delivered_at IS NULL AND job.claim_completed_at IS NULL
		     AND (job.status <> 'processing' OR job.lease_until IS NULL OR job.lease_until <= $1)
		     AND (job.claimed_by_agent_id IS NULL OR job.claim_expires_at <= $1))
		   OR (job.status='cancelled' AND EXISTS (
		     SELECT 1 FROM lifecycle_rotation_runs run
		     WHERE run.tenant_id=i.tenant_id AND run.identity_id=i.id AND run.status='running'
		       AND (job.id=run.outbox_id OR convert_from(job.payload,'UTF8')::jsonb->>'rotation_run_id'=run.id::text)
		       AND NOT EXISTS (
		         SELECT 1 FROM outbox active WHERE active.tenant_id=i.tenant_id AND active.status IN ('pending','processing')
		           AND CASE WHEN active.destination IN ('ca.issue','ca.renew','endpoint.renew')
		             THEN convert_from(active.payload,'UTF8')::jsonb->>'identity_id'=i.id::text
		               AND (active.id=run.outbox_id OR convert_from(active.payload,'UTF8')::jsonb->>'rotation_run_id'=run.id::text)
		             ELSE false END))))
		 ORDER BY 1 LIMIT 100`, now.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenant string
		if err := rows.Scan(&tenant); err != nil {
			return nil, err
		}
		tenants = append(tenants, tenant)
	}
	return tenants, rows.Err()
}
