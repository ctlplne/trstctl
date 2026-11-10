// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// ADCSRelayRevocationWait is one AD CS revocation still waiting on its relay
// (A162-L5): its newest attempt is queued for, or held by, the issuer's relay,
// and no attempt has closed it. The revocation's delivery re-checks it every
// few seconds without spending its retry budget, so without this read a relay
// that never connects leaves the revocation waiting with nothing to show why.
type ADCSRelayRevocationWait struct {
	RevocationID string
	CAConfig     string
	Serial       string
	// AgentID is the exact relay the attempt is pinned to.
	AgentID string
	// Held: the relay holds a live lease on the attempt, so it is running it.
	Held bool
	// Attempt is this attempt's number: one more than the failed ones before it.
	Attempt int
	// LastError is the newest failed attempt's reason, if one failed.
	LastError string
	// FirstQueuedAt is when the first attempt was queued; AttemptQueuedAt when
	// this one was.
	FirstQueuedAt   time.Time
	AttemptQueuedAt time.Time
}

// ListADCSRelayRevocationWaits returns the tenant's AD CS revocations whose
// newest attempt is still open, oldest first, read from the queued attempts
// themselves.
func (s *Store) ListADCSRelayRevocationWaits(ctx context.Context, tenantID string, limit int) ([]ADCSRelayRevocationWait, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	var out []ADCSRelayRevocationWait
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`WITH attempts AS (
			     SELECT id, status, COALESCE(last_error, '') AS last_error, created_at,
			            claimed_by_agent_id, claim_expires_at, claim_completed_at,
			            convert_from(payload, 'UTF8')::jsonb AS intent
			       FROM outbox
			      WHERE tenant_id = $1 AND destination = 'adcs.revoke'
			 )
			 SELECT COALESCE(o.intent ->> 'id', ''), COALESCE(o.intent ->> 'ca_config', ''),
			        COALESCE(o.intent ->> 'serial', ''), COALESCE(o.intent ->> 'required_agent_id', ''),
			        o.claimed_by_agent_id IS NOT NULL AND o.claim_expires_at > now(),
			        (SELECT count(*) FROM attempts f
			          WHERE f.intent ->> 'id' = o.intent ->> 'id' AND f.status = 'failed'),
			        COALESCE((SELECT f.last_error FROM attempts f
			                   WHERE f.intent ->> 'id' = o.intent ->> 'id' AND f.status = 'failed'
			                   ORDER BY f.id DESC LIMIT 1), ''),
			        (SELECT min(f.created_at) FROM attempts f WHERE f.intent ->> 'id' = o.intent ->> 'id'),
			        o.created_at
			   FROM attempts o
			  WHERE o.status IN ('pending', 'processing') AND o.claim_completed_at IS NULL
			    AND NOT EXISTS (SELECT 1 FROM attempts d
			                     WHERE d.intent ->> 'id' = o.intent ->> 'id' AND d.status = 'delivered')
			  ORDER BY o.created_at, o.id
			  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var w ADCSRelayRevocationWait
			var failed int
			if err := rows.Scan(&w.RevocationID, &w.CAConfig, &w.Serial, &w.AgentID, &w.Held, &failed,
				&w.LastError, &w.FirstQueuedAt, &w.AttemptQueuedAt); err != nil {
				return err
			}
			w.Attempt = failed + 1
			out = append(out, w)
		}
		return rows.Err()
	})
	return out, err
}
