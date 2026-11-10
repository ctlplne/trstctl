// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// OutboxLastErrorSupersededByRetry is the closed last_error class of a host
// renewal job, and of the certificate authority request it left waiting, that
// a renewal retry ended (A36 heal).
const OutboxLastErrorSupersededByRetry = "superseded_by_retry"

// SupersedeFailedHostRenewalTx ends, for a renewal retry, the identity's host
// renewal jobs that already failed and that no agent holds right now. Each is
// cancelled and recalled, so its claim, signing and result are refused from
// here on, and a certificate authority request it left waiting is withdrawn
// before it can mint a certificate nobody will install. The next job for the
// target says it has ended, which is the authority its agent needs to wipe the
// ended job's unsigned key. A job an agent is working on, and one never
// attempted, is left alone: the retry then waits for it. The caller holds the
// identity row lock. It returns the ended job IDs.
func (s *Store) SupersedeFailedHostRenewalTx(ctx context.Context, tx pgx.Tx, tenantID, identityID string, at time.Time) ([]int64, error) {
	at = at.UTC()
	rows, err := tx.Query(ctx,
		`SELECT id FROM outbox
		  WHERE tenant_id = $1 AND destination = 'endpoint.renew'
		    AND status = 'pending' AND delivered_at IS NULL AND claim_completed_at IS NULL
		    AND attempts >= 1
		    AND (claimed_by_agent_id IS NULL OR claim_expires_at <= $3)
		    AND convert_from(payload, 'UTF8')::jsonb ->> 'identity_id' = $2
		  ORDER BY id
		    FOR UPDATE`, tenantID, identityID, at)
	if err != nil {
		return nil, err
	}
	var ended []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ended = append(ended, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(ended) == 0 {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE outbox
		    SET status = $3,
		        agent_recalled_at = COALESCE(agent_recalled_at, $4),
		        last_error = $5,
		        worker_id = NULL,
		        lease_until = NULL
		  WHERE tenant_id = $1 AND id = ANY($2::bigint[])
		    AND status = 'pending' AND delivered_at IS NULL AND claim_completed_at IS NULL`,
		tenantID, ended, OutboxStatusCancelled, at, OutboxLastErrorSupersededByRetry); err != nil {
		return nil, err
	}
	// The signing request of an agent CSR is keyed agentcsr:<job>:...; one
	// still waiting for a worker is withdrawn. One a worker holds is left to
	// finish: it may already be at the certificate authority.
	jobs := make([]string, len(ended))
	for i, id := range ended {
		jobs[i] = strconv.FormatInt(id, 10)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE outbox
		    SET status = $3, last_error = $4, worker_id = NULL, lease_until = NULL
		  WHERE tenant_id = $1 AND destination = 'external-ca.issue'
		    AND status = 'pending' AND delivered_at IS NULL
		    AND split_part(idempotency_key, ':', 1) = 'agentcsr'
		    AND split_part(idempotency_key, ':', 2) = ANY($2::text[])`,
		tenantID, jobs, OutboxStatusCancelled, OutboxLastErrorSupersededByRetry); err != nil {
		return nil, err
	}
	return ended, nil
}

// HostRenewalJobsEndedThroughTx is the largest host renewal job ID for the
// target such that every host renewal job for the target up to it has ended
// (completed, failed or cancelled), or 0. It stops below the oldest job still
// pending or processing, so a key an open job holds is never released. A new
// job carries it so its agent may wipe a key an ended job left unsigned,
// including a target stuck behind an older job before this check existed.
func (s *Store) HostRenewalJobsEndedThroughTx(ctx context.Context, tx pgx.Tx, tenantID, targetID string) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx,
		`WITH target_jobs AS (
		   SELECT id, status FROM outbox
		    WHERE tenant_id = $1 AND destination = 'endpoint.renew'
		      AND convert_from(payload, 'UTF8')::jsonb ->> 'target_id' = $2)
		 SELECT COALESCE(MAX(id), 0) FROM target_jobs
		  WHERE status IN ('delivered', 'failed', 'cancelled')
		    AND id < COALESCE((SELECT MIN(id) FROM target_jobs WHERE status IN ('pending', 'processing')), 9223372036854775807)`,
		tenantID, targetID).Scan(&id)
	return id, err
}
