// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

// AgentJobResultClaim is the server-authoritative binding for one reported
// result. Destination and key come from the durable job, not agent input.
type AgentJobResultClaim struct {
	Destination    string
	IdempotencyKey string
	Payload        []byte
}

// HostDeployEvidence is the public routing half of the latest completed host
// deploy. It contains no PEM or key bytes.
type HostDeployEvidence struct {
	AgentID     string
	IdentityID  string
	Fingerprint string
}

// LastSuccessfulHostDeployEvidence returns the exact host agent and public
// successor identity for targetID. That agent owns the encrypted predecessor;
// the fingerprint follows the certificate replacement edge even when the bad
// successor's SAN no longer matches its identity.
//
// Two jobs can install a host certificate. connector.deploy carries an already
// issued fingerprint in its immutable payload. endpoint.renew generates the key
// on the host and therefore learns its fingerprint only after the control plane
// signs that exact job attempt's CSR. For the second path, the certificate row's
// agentcsr:<job>:<attempt>:... issuance key is the durable public join. Treating
// only connector.deploy as a host deploy makes every host-generated renewal
// impossible to roll back even though the same agent retained its predecessor.
func (s *Store) LastSuccessfulHostDeployEvidence(ctx context.Context, tenantID, targetID string) (HostDeployEvidence, bool, error) {
	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return HostDeployEvidence{}, false, nil
	}
	var out HostDeployEvidence
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`WITH host_jobs AS (
			     SELECT job.id, job.destination, job.payload, job.claim_attempts,
			            job.claimed_by_agent_id, job.delivered_at
			       FROM outbox job
			      WHERE job.tenant_id = $1
			        AND job.destination IN ('connector.deploy', 'endpoint.renew')
			        AND job.status = 'delivered'
			        AND job.delivered_at IS NOT NULL
			        AND job.required_agent_role = 'host'
			        AND job.claimed_by_agent_id IS NOT NULL
			        AND convert_from(job.payload, 'UTF8')::jsonb ->> 'target_id' = $2
			 ), routed AS (
			     SELECT job.id, job.claimed_by_agent_id,
			            COALESCE(convert_from(job.payload, 'UTF8')::jsonb ->> 'identity_id', '') AS identity_id,
			            CASE
			              WHEN job.destination = 'connector.deploy' THEN
			                COALESCE(convert_from(job.payload, 'UTF8')::jsonb ->> 'fingerprint', '')
			              ELSE COALESCE((
			                SELECT cert.fingerprint
			                  FROM certificates cert
			                 WHERE cert.tenant_id = $1
			                   AND cert.issuance_idempotency_key LIKE
			                       format('agentcsr:%s:%s:%%', job.id, job.claim_attempts)
			                 ORDER BY cert.created_at DESC, cert.id DESC
			                 LIMIT 1
			              ), '')
			            END AS fingerprint,
			            job.delivered_at
			       FROM host_jobs job
			 )
			 SELECT claimed_by_agent_id::text, identity_id, fingerprint
			   FROM routed
			  ORDER BY delivered_at DESC, id DESC
			  LIMIT 1`, tenantID, targetID).Scan(&out.AgentID, &out.IdentityID, &out.Fingerprint)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	return out, found, err
}

// LastSuccessfulHostDeployAgentID is the narrow routing-only view retained for
// callers that do not need certificate replacement evidence.
func (s *Store) LastSuccessfulHostDeployAgentID(ctx context.Context, tenantID, targetID string) (string, bool, error) {
	evidence, found, err := s.LastSuccessfulHostDeployEvidence(ctx, tenantID, targetID)
	return evidence.AgentID, found, err
}

// AgentJobClaimForResult proves that this exact claim generation is still held
// and unexpired before any reported observation is projected.
func (s *Store) AgentJobClaimForResult(ctx context.Context, tenantID, agentID string, jobID int64, attempt int, now time.Time) (AgentJobResultClaim, bool, error) {
	var out AgentJobResultClaim
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`SELECT destination, idempotency_key, payload
			   FROM outbox
			  WHERE tenant_id = $1 AND id = $3
			    AND claimed_by_agent_id = $2::uuid
			    AND claim_attempts = $4
			    AND claim_completed_at IS NULL
			    AND claim_expires_at >= $5`,
			tenantID, agentID, jobID, attempt, now.UTC()).Scan(&out.Destination, &out.IdempotencyKey, &out.Payload)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	return out, found, err
}

// ClaimAgentJobs leases up to limit pending entries on the given destinations to
// one agent, returning what it took.
//
// SKIP LOCKED is the important word: a fleet polling in lockstep must fan out
// across the queue, not serialize on its head. An entry whose lease has expired
// is claimable again, which is how a dead agent's work comes back without anyone
// intervening.
// ClaimAgentJobs leases up to limit pending jobs of the given kinds to agentID.
// roles is the capability set from the agent's CERTIFICATE (epic A2/A3): a row
// stamped with a required_agent_role is handed out only to an agent holding that
// role, a row stamped 'control_plane' is handed to no agent ever, and a row with
// the empty demand follows kind-level rules alone — which is every row enqueued
// before the vantage census existed.
func (s *Store) ClaimAgentJobs(ctx context.Context, tenantID, agentID string, destinations, roles []string, limit int, lease time.Duration, now time.Time) ([]AgentJob, error) {
	if limit <= 0 || len(destinations) == 0 || lease <= 0 {
		return nil, nil
	}
	if roles == nil {
		roles = []string{}
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
		//
		// A blank/legacy lane (or the old destination-wide default) is made unique
		// per job here. Only an explicitly narrower lane serializes work. This
		// preserves batch claiming for pre-lane rows while making modern
		// connector.bind:target:<id> deploy/rollback pairs mutually exclusive.
		rows, err := tx.Query(ctx,
			`WITH eligible AS (
			        SELECT c.id,
			               CASE
			                 WHEN c.effect_lane <> '' AND c.effect_lane <> c.destination THEN c.effect_lane
			                 ELSE 'agent-job:' || c.id::text
			               END AS effective_lane
			          FROM outbox AS c
			         WHERE c.tenant_id = $1
			           AND c.destination = ANY($3::text[])
			           AND c.status = 'pending'
			           AND c.delivered_at IS NULL
			           AND c.claim_completed_at IS NULL
			           AND (c.claimed_by_agent_id IS NULL OR c.claim_expires_at < $5)
			           AND (c.required_agent_role = '' OR c.required_agent_role = ANY($7::text[]))
			           AND (c.required_agent_id IS NULL OR c.required_agent_id = $2::uuid)
			           AND NOT EXISTS (
			                 SELECT 1
			                   FROM outbox AS held
			                  WHERE held.tenant_id = c.tenant_id
			                    AND CASE
			                          WHEN held.effect_lane <> '' AND held.effect_lane <> held.destination THEN held.effect_lane
			                          ELSE 'agent-job:' || held.id::text
			                        END =
			                        CASE
			                          WHEN c.effect_lane <> '' AND c.effect_lane <> c.destination THEN c.effect_lane
			                          ELSE 'agent-job:' || c.id::text
			                        END
			                    AND held.status = 'pending'
			                    AND held.delivered_at IS NULL
			                    AND held.claim_completed_at IS NULL
			                    AND held.claimed_by_agent_id IS NOT NULL
			                    AND held.claim_expires_at >= $5
			           )
			 ), lane_heads AS (
			        SELECT DISTINCT ON (effective_lane) id, effective_lane
			          FROM eligible
			         ORDER BY effective_lane, id
			 ), claimable AS (
			        SELECT c.id
			          FROM outbox AS c
			          JOIN lane_heads AS h ON h.id = c.id
			         ORDER BY c.id
			         LIMIT $4
			         FOR UPDATE OF c SKIP LOCKED
			 )
			 UPDATE outbox AS o
			    SET claimed_by_agent_id = $2::uuid,
			        claim_expires_at    = $6,
			        claim_attempts      = o.claim_attempts + 1
			   FROM claimable AS k
			  WHERE o.id = k.id
			  RETURNING o.id, o.tenant_id::text, o.destination, o.payload, o.idempotency_key,
			            o.attempts, o.claim_attempts, o.claim_expires_at, o.created_at`,
			tenantID, agentID, destinations, limit, now, expires, roles)
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

// ReleaseAgentJob hands a job back after a failed attempt, recording why. The
// entry becomes claimable again immediately — by this agent or another — because
// a failure on one host is not evidence the work is impossible.
//
// The persisted reason is a closed-set marker, never the agent's own words. An
// agent executes against systems that may echo the credential it was just given
// back in an error string; persisting arbitrary agent text here would turn that
// into a durable, unwipeable secret in PostgreSQL (AN-8) — the same reason the
// dispatcher's own delivery errors are a closed set.
func (s *Store) ReleaseAgentJob(ctx context.Context, tenantID, agentID string, jobID int64, reason string) (bool, error) {
	var released bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE outbox
			    SET claimed_by_agent_id = NULL,
			        claim_expires_at    = NULL,
			        attempts            = attempts + 1,
			        last_error          = $4
			  WHERE tenant_id = $1
			    AND id = $3
			    AND claimed_by_agent_id = $2::uuid
			    AND claim_completed_at IS NULL`,
			tenantID, agentID, jobID, agentFailureReason(reason))
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

// AgentFailureReason values are the only failure strings persisted on an outbox
// row from an agent report. The agent's own description travels to the operator
// through the event log, where it is attributable to a named agent and a job, and
// never becomes an unbounded string on the queue itself.
const (
	AgentFailureReported = "agent_reported_failure"
	AgentFailureUnstated = "agent_reported_failure_no_detail"
)

func agentFailureReason(detail string) string {
	if detail == "" {
		return AgentFailureUnstated
	}
	return AgentFailureReported
}

// AgentJobRedemption is the record of one just-in-time credential hand-over
// (epic A3): which agent redeemed which job attempt, when it expires, and the
// public reference the console shows. Never the material itself.
type AgentJobRedemption struct {
	AuditRef  string
	ExpiresAt time.Time
}

// RedeemAgentJobCredential authorizes exactly one credential hand-over for one
// job attempt. In a single statement it (a) verifies the caller CURRENTLY holds
// the job's claim lease at the presented attempt, and (b) inserts the redemption
// row keyed (tenant, job, attempt) — so a replay, a raced lease steal, or a
// stale attempt all insert nothing and return ok=false with no distinguishing
// detail. The row is the audit trail: append-only, RLS-confined, its expiry
// bound to the claim lease so redeemed material can never outlive the claim.
//
// binding is the caller-computed, non-secret digest tying this redemption to
// the exact work it authorizes; it is stored as evidence, not consulted as a
// key.
func (s *Store) RedeemAgentJobCredential(
	ctx context.Context,
	tenantID, agentID string,
	jobID int64,
	attempt int,
	binding []byte,
	now time.Time,
) (AgentJobRedemption, bool, error) {
	var out AgentJobRedemption
	ok := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		scanErr := tx.QueryRow(ctx,
			`WITH held AS (
			        SELECT o.id, o.claim_attempts, o.claim_expires_at
			          FROM outbox AS o
			         WHERE o.tenant_id = $1
			           AND o.id = $2
			           AND o.claimed_by_agent_id = $3::uuid
			           AND o.claim_completed_at IS NULL
			           AND o.claim_expires_at > $6
			           AND o.claim_attempts = $4
			 ), ins AS (
			    INSERT INTO agent_job_credential_redemptions
			           (tenant_id, job_id, attempt, agent_id, binding, expires_at)
			    SELECT $1, held.id, held.claim_attempts, $3::uuid, $5, held.claim_expires_at
			      FROM held
			    ON CONFLICT (tenant_id, job_id, attempt) DO NOTHING
			    RETURNING audit_ref::text, expires_at
			 )
			 SELECT audit_ref, expires_at FROM ins`,
			tenantID, jobID, agentID, attempt, binding, now.UTC()).
			Scan(&out.AuditRef, &out.ExpiresAt)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		ok = true
		return nil
	})
	return out, ok, err
}

// AgentJobRedemptionRefusalReason classifies, AFTER a refused redemption, why it
// was refused — for the audit event only. The wire answer is always the same
// coarse denial; these reasons never reach the agent, so an attacker probing the
// endpoint cannot map the claim table's state from refusal shapes.
func (s *Store) AgentJobRedemptionRefusalReason(
	ctx context.Context,
	tenantID, agentID string,
	jobID int64,
	attempt int,
	now time.Time,
) (string, error) {
	reason := AgentRedemptionRefusedLeaseNotHeld
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var redeemed bool
		if scanErr := tx.QueryRow(ctx,
			`SELECT EXISTS (
			    SELECT 1 FROM agent_job_credential_redemptions
			     WHERE tenant_id = $1 AND job_id = $2 AND attempt = $3
			 )`, tenantID, jobID, attempt).Scan(&redeemed); scanErr != nil {
			return scanErr
		}
		if redeemed {
			reason = AgentRedemptionRefusedReplayed
			return nil
		}
		var held bool
		if scanErr := tx.QueryRow(ctx,
			`SELECT EXISTS (
			    SELECT 1 FROM outbox
			     WHERE tenant_id = $1 AND id = $2
			       AND claimed_by_agent_id = $3::uuid
			       AND claim_completed_at IS NULL
			       AND claim_expires_at > $4
			 )`, tenantID, jobID, agentID, now.UTC()).Scan(&held); scanErr != nil {
			return scanErr
		}
		if held {
			// The lease is held but the attempt number does not match: the
			// caller presented a stale claim generation.
			reason = AgentRedemptionRefusedAttemptStale
		}
		return nil
	})
	return reason, err
}

// Closed-set refusal reasons for the redemption audit event. Like the job
// failure markers, these are the only strings that may describe a refusal in
// durable state.
const (
	AgentRedemptionRefusedReplayed     = "redemption_replayed"
	AgentRedemptionRefusedLeaseNotHeld = "redemption_lease_not_held"
	AgentRedemptionRefusedAttemptStale = "redemption_attempt_stale"
)

// AgentJobForRedemption is the row material the redemption handler needs to
// resolve a claimed job's credential references: never handed to the agent —
// the payload here is still sealed.
type AgentJobForRedemption struct {
	Destination    string
	IdempotencyKey string
	Payload        []byte
	ClaimAttempts  int
}

// GetAgentJobForRedemption loads a job's sealed payload if — at this instant —
// agentID holds its live claim. This is a fail-fast PREcheck and a data read;
// the atomic single-use authorization is RedeemAgentJobCredential, which
// re-verifies holdership in the same statement as the redemption insert.
func (s *Store) GetAgentJobForRedemption(
	ctx context.Context,
	tenantID, agentID string,
	jobID int64,
	now time.Time,
) (AgentJobForRedemption, bool, error) {
	var out AgentJobForRedemption
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		scanErr := tx.QueryRow(ctx,
			`SELECT destination, idempotency_key, payload, claim_attempts
			   FROM outbox
			  WHERE tenant_id = $1 AND id = $2
			    AND claimed_by_agent_id = $3::uuid
			    AND claim_completed_at IS NULL
			    AND claim_expires_at > $4`,
			tenantID, jobID, agentID, now.UTC()).
			Scan(&out.Destination, &out.IdempotencyKey, &out.Payload, &out.ClaimAttempts)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		found = true
		return nil
	})
	return out, found, err
}

// AgentJobAttemptRedeemedCredential reports whether ANY attempt of this job has
// redeemed credential material. It is what decides whether an agent's own words
// may enter the tenant's permanent history: an agent that has held a credential
// can echo it back, and no redactor recognizes a short appliance password.
func (s *Store) AgentJobAttemptRedeemedCredential(ctx context.Context, tenantID string, jobID int64) (bool, error) {
	redeemed := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			    SELECT 1 FROM agent_job_credential_redemptions
			     WHERE tenant_id = $1 AND job_id = $2
			 )`, tenantID, jobID).Scan(&redeemed)
	})
	return redeemed, err
}

// AgentJobRedemptionPosture is process-wide credential-redemption health for the
// operations surface (epic A3). Counts and one age only — never a tenant, an
// agent, a job, a reference name or a value.
type AgentJobRedemptionPosture struct {
	// Live is the number of redemptions whose authorization has not yet lapsed.
	// Each one is a credential currently held by some relay: the single most
	// operationally interesting number this epic produces.
	Live int
	// Total is every redemption ever recorded.
	Total int
	// OldestLiveAt is when the oldest still-live redemption was granted. A
	// redemption older than the maximum lease means a relay is holding material
	// past a claim that should have lapsed — the shape of a stuck attempt.
	OldestLiveAt *time.Time
}

// AgentJobRedemptions reads redemption posture for the operations surface.
func (s *Store) AgentJobRedemptions(ctx context.Context, now time.Time) (AgentJobRedemptionPosture, error) {
	var out AgentJobRedemptionPosture
	err := s.SystemPool().QueryRow(ctx,
		//trstctl:system-query — cross-tenant by design: process-wide credential-redemption health for the operations surface. It returns two counts and one timestamp; no tenant id, agent id, job id, reference name or credential value leaves this query.
		`SELECT count(*) FILTER (WHERE expires_at > $1)::int,
		        count(*)::int,
		        min(redeemed_at) FILTER (WHERE expires_at > $1)
		   FROM agent_job_credential_redemptions`, now.UTC()).
		Scan(&out.Live, &out.Total, &out.OldestLiveAt)
	return out, err
}

// AgentJobAttemptSignedOtherCSR reports whether this job attempt has already had
// a DIFFERENT CSR signed (epic B2).
//
// It reads the certificates table rather than a new ledger, because the
// certificate IS the record: every issuance against an agent's CSR is stamped
// with an idempotency key of the form `agentcsr:<jobID>:<attempt>:<digest>`, so
// the existence of such a row is the fact we need and there is nothing to keep
// in sync.
//
// DIFFERENT is the load-bearing word. Two cases look alike and must not be
// treated alike:
//
//   - The same CSR arriving twice is a RETRY — the agent's first call timed out
//     and it is asking again for the certificate belonging to the key it still
//     holds. Refusing that would lose the certificate for a live key over a
//     network blip, so it must replay the cached issuance.
//   - A different CSR on the same attempt is the abuse: the CSR-derived
//     idempotency key makes every new key a new issuance, so one claim could
//     otherwise mint certificates without limit.
//
// The bound is per ATTEMPT rather than per job because a genuine retry re-claims
// the work and gets a new attempt number, which should be allowed to sign again.
func (s *Store) AgentJobAttemptSignedOtherCSR(ctx context.Context, tenantID string, jobID int64, attempt int, idempotencyKey string) (bool, error) {
	signed := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			    SELECT 1 FROM certificates
			     WHERE tenant_id = $1
			       AND issuance_idempotency_key LIKE $2
			       AND issuance_idempotency_key <> $3
			 )`, tenantID, fmt.Sprintf("agentcsr:%d:%d:%%", jobID, attempt), idempotencyKey).Scan(&signed)
	})
	return signed, err
}

// HasPendingAgentJob reports whether an unfinished job of this kind is already
// queued for the tenant. The CMDB relay scheduler uses it to keep ONE sync in
// flight: stacking identical reads behind an unclaimed job would have the
// eventual relay replay a backlog against the instance (I2).
func (s *Store) HasPendingAgentJob(ctx context.Context, tenantID, destination string) (bool, error) {
	var pending bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			    SELECT 1 FROM outbox
			     WHERE tenant_id = $1 AND destination = $2
			       AND status IN ('pending', 'processing')
			       AND claim_completed_at IS NULL
			)`, tenantID, destination).Scan(&pending)
	})
	return pending, err
}

// HasPendingMDMSyncJob reports whether this provider already has unfinished
// estate-read work. Intune and Jamf share the mdm.sync destination so network
// relays can advertise one closed capability, but they are separate bulkhead
// lanes: an unavailable Intune tenant must not stop a healthy Jamf read.
//
// The provider comes from the durable outbox intent, not a mutable schedule or
// an agent report. The producer controls this JSON, so a row that cannot decode
// is a broken mdm.sync intent and fails the scheduler closed instead of silently
// stacking more work behind it.
func (s *Store) HasPendingMDMSyncJob(ctx context.Context, tenantID, provider string) (bool, error) {
	if tenantID == "" || provider == "" {
		return false, errors.New("store: pending MDM sync lookup requires tenant and provider")
	}
	var pending bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			    SELECT 1 FROM outbox
			     WHERE tenant_id = $1
			       AND destination = 'mdm.sync'
			       AND status IN ('pending', 'processing')
			       AND claim_completed_at IS NULL
			       AND convert_from(payload, 'UTF8')::jsonb ->> 'mdm' = $2
			)`, tenantID, provider).Scan(&pending)
	})
	return pending, err
}

// HasPendingTicketSyncJob keeps one page in flight per ITSM system. Jira and
// ServiceNow intentionally share the agent capability but not the queue lane.
func (s *Store) HasPendingTicketSyncJob(ctx context.Context, tenantID, system string) (bool, error) {
	if tenantID == "" || (system != "servicenow" && system != "jira") {
		return false, errors.New("store: pending ticket sync lookup requires tenant and known system")
	}
	var pending bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			    SELECT 1 FROM outbox
			     WHERE tenant_id = $1
			       AND destination = 'ticket.sync'
			       AND status IN ('pending', 'processing')
			       AND claim_completed_at IS NULL
			       AND convert_from(payload, 'UTF8')::jsonb ->> 'system' = $2
			)`, tenantID, system).Scan(&pending)
	})
	return pending, err
}
