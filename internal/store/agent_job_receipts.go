// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// The signed job receipt ledger (epic A1).
//
// The event log holds every receipt. This read model exists so an operator can
// see the state of the fabric without replaying it, and so the one number that
// signals trouble — receipts being refused — is a query rather than a stream
// scan.

// Receipt states. Closed set, matched by a database constraint.
const (
	// AgentJobReceiptVerified: the agent's signature checked out against the
	// certificate on its connection.
	AgentJobReceiptVerified = "verified"
	// AgentJobReceiptRejected: it did not, and the report was refused. This is
	// the state worth an operator's attention — somebody's agent believes it
	// did work that the ledger will not record.
	AgentJobReceiptRejected = "rejected"
)

// AgentJobReceipt is one recorded receipt or refusal.
type AgentJobReceipt struct {
	JobID   int64
	Attempt int
	Agent   string
	Kind    string
	Outcome string
	State   string
	// Reason is set only for a rejection, and only from the server's own closed
	// set — never from anything the reporting agent supplied.
	Reason            string
	SignerFingerprint string
	Statement         string
	Signature         string
	ObservedAt        time.Time
}

// RecordAgentJobReceipt stores one receipt or refusal.
//
// Upsert on (job, attempt, state) rather than insert: an agent that retries a
// report it already sent should not multiply the ledger, and a rejection
// repeated because the agent keeps retrying with the same bad clock is one
// ongoing condition rather than a hundred incidents. Re-recording refreshes the
// timestamp, so "when did this last happen" stays true.
func (s *Store) RecordAgentJobReceipt(ctx context.Context, tenantID string, r AgentJobReceipt) error {
	if r.ObservedAt.IsZero() {
		r.ObservedAt = time.Now().UTC()
	}
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO agent_job_receipts
			     (tenant_id, job_id, attempt, agent, kind, outcome, state, reason,
			      signer_fingerprint, statement, signature, observed_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			 ON CONFLICT (tenant_id, job_id, attempt, state) DO UPDATE
			    SET agent = EXCLUDED.agent, kind = EXCLUDED.kind, outcome = EXCLUDED.outcome,
			        reason = EXCLUDED.reason, signer_fingerprint = EXCLUDED.signer_fingerprint,
			        statement = EXCLUDED.statement, signature = EXCLUDED.signature,
			        observed_at = EXCLUDED.observed_at`,
			tenantID, r.JobID, r.Attempt, r.Agent, r.Kind, r.Outcome, r.State, r.Reason,
			r.SignerFingerprint, r.Statement, r.Signature, r.ObservedAt.UTC())
		return err
	})
}

// AgentJobReceiptPosture is the served summary of the receipt ledger.
type AgentJobReceiptPosture struct {
	Verified int
	Rejected int
	// LastRejectedReason and LastRejectedAt describe the most recent refusal.
	// A count alone tells an operator something is wrong without telling them
	// which of the two very different things it is — a drifting clock or a key
	// that is not the one the certificate names.
	LastRejectedReason string
	LastRejectedAt     *time.Time
}

// AgentJobReceiptSummary reads process-wide receipt health for the operations
// surface.
//
// Cross-tenant like the credential-redemption counters beside it, and for the
// same reason: this answers "is the fabric's evidence intact on this control
// plane", which is an operator question about the deployment rather than a
// question about one tenant's certificates. What crosses the boundary is two
// counts, one closed-set reason string this server itself wrote, and one
// timestamp — no tenant, no agent, no job.
func (s *Store) AgentJobReceiptSummary(ctx context.Context) (AgentJobReceiptPosture, error) {
	var out AgentJobReceiptPosture
	if err := s.SystemPool().QueryRow(ctx,
		//trstctl:system-query — cross-tenant by design: process-wide agent receipt-verification health for the operations surface. Two counts only; no tenant id, agent id, job id, statement or signature leaves this query.
		`SELECT count(*) FILTER (WHERE state = 'verified')::int,
		        count(*) FILTER (WHERE state = 'rejected')::int
		   FROM agent_job_receipts`).Scan(&out.Verified, &out.Rejected); err != nil {
		return out, err
	}
	if out.Rejected == 0 {
		return out, nil
	}
	var reason string
	var at time.Time
	if err := s.SystemPool().QueryRow(ctx,
		//trstctl:system-query — cross-tenant by design: the most recent receipt refusal reason for the operations surface. reason is one of this server's own closed-set values ("unsigned", "signature ...", "issued-at ...") and names nothing about the tenant or agent it came from.
		`SELECT reason, observed_at FROM agent_job_receipts
		  WHERE state = 'rejected' ORDER BY observed_at DESC LIMIT 1`).Scan(&reason, &at); err != nil {
		return out, err
	}
	out.LastRejectedReason = reason
	utc := at.UTC()
	out.LastRejectedAt = &utc
	return out, nil
}

// AgentJobIsClaimedBy reports whether the named agent currently holds a claim on
// this job.
//
// It bounds what can enter the receipt ledger. Every caller reaching the report
// handler is an enrolled agent with a valid certificate, so a refusal is always
// worth an AUDIT EVENT — the append-only log is the security record and it
// takes everything. But the ledger drives a counter an operator reads as "how
// much refused work is out there", and an agent naming job ids it never held
// would inflate that number with work that does not exist. The event log keeps
// the whole story; the counter counts real jobs.
func (s *Store) AgentJobIsClaimedBy(ctx context.Context, tenantID, agentID string, jobID int64) (bool, error) {
	var held bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			     SELECT 1 FROM outbox
			      WHERE tenant_id = $1 AND id = $3 AND claimed_by_agent_id = $2::uuid
			 )`, tenantID, agentID, jobID).Scan(&held)
	})
	return held, err
}
