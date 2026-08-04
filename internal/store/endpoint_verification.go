// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Observed endpoint identity (epic D2).
//
// This read model answers a question the platform previously could not: not
// "what did we deploy" but "what is the listener serving". The two diverge
// silently — a connector's reload can fail while every delivery record stays
// truthfully green — and the gap between last_checked_at and last_good_at is
// how long that has been going on.

// EndpointVerification is one endpoint's state from one vantage.
type EndpointVerification struct {
	TenantID   string
	EndpointID string
	Address    string
	// Vantage is "local" (the serving host's own agent) or "relay" (a network
	// agent, as a client would see it). Two rows per endpoint, never merged:
	// they answer different questions and an appliance has no local vantage.
	Vantage string
	Reached bool
	// Mismatch is the divergence class, empty when the identity matched.
	Mismatch            string
	ExpectedFingerprint string
	ObservedFingerprint string
	// CheckedSANs and CheckedChain say which comparisons ran, so "verified"
	// always carries what was verified.
	CheckedSANs  bool
	CheckedChain bool
	NotBefore    time.Time
	NotAfter     time.Time
	Detail       string
	// EvidenceDigest is the probe transcript digest from the agent's signed
	// receipt — what makes the verdict evidence rather than an assertion.
	EvidenceDigest  string
	AgentCommonName string
	LastCheckedAt   time.Time
	// LastGoodAt is the last time this endpoint was observed serving what it
	// should. Zero means never — which is a much stronger statement than "not
	// recently" and the console renders it as such.
	LastGoodAt    time.Time
	EventSequence uint64
}

// Verified reports whether the last observation from this vantage was clean.
//
// Reachability is part of it. An endpoint nobody could connect to is not
// verified, and a helper that returned true for one would let every consumer
// reintroduce the same false assurance independently.
func (e EndpointVerification) Verified() bool { return e.Reached && e.Mismatch == "" }

// ApplyEndpointVerificationTx records one observation.
//
// The sequence guard is not optional. Boot replays the entire event log without
// truncating, and the durable tailer can re-deliver an event the inline path
// already applied; without the guard an out-of-order replay could move an
// endpoint's state BACKWARDS — resurrecting a stale divergence over a good
// observation, or worse, a stale good observation over a live divergence.
//
// last_good_at uses GREATEST rather than assignment so a failing observation
// never erases the last time the endpoint was known good. That date is what
// tells an operator how long this has been broken, and losing it on the first
// failure would destroy the only measure of the outage's age.
func (s *Store) ApplyEndpointVerificationTx(ctx context.Context, tx pgx.Tx, v EndpointVerification) error {
	var notBefore, notAfter, lastGood *time.Time
	if !v.NotBefore.IsZero() {
		notBefore = &v.NotBefore
	}
	if !v.NotAfter.IsZero() {
		notAfter = &v.NotAfter
	}
	if v.Verified() {
		at := v.LastCheckedAt
		lastGood = &at
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO endpoint_verifications
		        (tenant_id, endpoint_id, address, vantage, reached, mismatch,
		         expected_fingerprint, observed_fingerprint, checked_sans, checked_chain,
		         not_before, not_after, detail, evidence_digest, agent_common_name,
		         last_checked_at, last_good_at, event_sequence)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		 ON CONFLICT (tenant_id, endpoint_id, vantage) DO UPDATE SET
		     address              = EXCLUDED.address,
		     reached              = EXCLUDED.reached,
		     mismatch             = EXCLUDED.mismatch,
		     expected_fingerprint = EXCLUDED.expected_fingerprint,
		     observed_fingerprint = EXCLUDED.observed_fingerprint,
		     checked_sans         = EXCLUDED.checked_sans,
		     checked_chain        = EXCLUDED.checked_chain,
		     not_before           = EXCLUDED.not_before,
		     not_after            = EXCLUDED.not_after,
		     detail               = EXCLUDED.detail,
		     evidence_digest      = EXCLUDED.evidence_digest,
		     agent_common_name    = EXCLUDED.agent_common_name,
		     last_checked_at      = EXCLUDED.last_checked_at,
		     -- Never lose the last-known-good date on a failure.
		     last_good_at         = GREATEST(endpoint_verifications.last_good_at, EXCLUDED.last_good_at),
		     event_sequence       = GREATEST(endpoint_verifications.event_sequence, EXCLUDED.event_sequence)
		 WHERE EXCLUDED.event_sequence > endpoint_verifications.event_sequence`,
		v.TenantID, v.EndpointID, v.Address, v.Vantage, v.Reached, v.Mismatch,
		v.ExpectedFingerprint, v.ObservedFingerprint, v.CheckedSANs, v.CheckedChain,
		notBefore, notAfter, v.Detail, v.EvidenceDigest, v.AgentCommonName,
		v.LastCheckedAt, lastGood, int64(v.EventSequence)) // #nosec G115 -- event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190)
	return err
}

// ListEndpointVerifications returns the tenant's endpoint state, divergences
// first, then whatever has gone longest without a good observation.
func (s *Store) ListEndpointVerifications(ctx context.Context, tenantID string) ([]EndpointVerification, error) {
	var out []EndpointVerification
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, endpoint_id, address, vantage, reached, mismatch,
			        expected_fingerprint, observed_fingerprint, checked_sans, checked_chain,
			        not_before, not_after, detail, evidence_digest, agent_common_name,
			        last_checked_at, last_good_at, event_sequence
			   FROM endpoint_verifications
			  WHERE tenant_id = $1
			  ORDER BY (mismatch <> '') DESC, last_good_at ASC NULLS FIRST, endpoint_id, vantage`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				rec                           EndpointVerification
				notBefore, notAfter, lastGood *time.Time
				seq                           int64
			)
			if err := rows.Scan(&rec.TenantID, &rec.EndpointID, &rec.Address, &rec.Vantage,
				&rec.Reached, &rec.Mismatch, &rec.ExpectedFingerprint, &rec.ObservedFingerprint,
				&rec.CheckedSANs, &rec.CheckedChain, &notBefore, &notAfter, &rec.Detail,
				&rec.EvidenceDigest, &rec.AgentCommonName, &rec.LastCheckedAt, &lastGood,
				&seq); err != nil {
				return err
			}
			if notBefore != nil {
				rec.NotBefore = *notBefore
			}
			if notAfter != nil {
				rec.NotAfter = *notAfter
			}
			if lastGood != nil {
				rec.LastGoodAt = *lastGood
			}
			rec.EventSequence = uint64(seq) // #nosec G115 -- non-negative by construction (CWE-190)
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

// EndpointVerificationSummary is the estate-wide roll-up behind the dashboard
// tile.
type EndpointVerificationSummary struct {
	// Endpoints is the number of distinct endpoints with any observation.
	Endpoints int
	// Verified is how many are currently serving what they should from EVERY
	// vantage that has looked. Deliberately strict: an endpoint whose relay
	// probe fails while its local check passes is NOT verified, because a
	// client cannot get to it.
	Verified int
	// Diverged is how many have a mismatch from any vantage.
	Diverged int
	// Unreachable is how many could not be connected to at all. Separate from
	// diverged because the operator response differs — a network problem is not
	// a certificate problem.
	Unreachable int
}

// SummarizeEndpointVerifications rolls the per-vantage rows up per endpoint.
func (s *Store) SummarizeEndpointVerifications(ctx context.Context, tenantID string) (EndpointVerificationSummary, error) {
	var out EndpointVerificationSummary
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// The roll-up is per endpoint, and an endpoint counts as verified only
		// when no vantage found a problem. bool_and over the vantages is what
		// makes "verified" mean verified everywhere somebody looked, rather
		// than verified somewhere.
		return tx.QueryRow(ctx,
			`SELECT count(*),
			        count(*) FILTER (WHERE ok),
			        count(*) FILTER (WHERE diverged),
			        count(*) FILTER (WHERE unreachable)
			   FROM (
			      SELECT endpoint_id,
			             bool_and(reached AND mismatch = '') AS ok,
			             bool_or(mismatch <> '')             AS diverged,
			             bool_or(NOT reached)                AS unreachable
			        FROM endpoint_verifications
			       WHERE tenant_id = $1
			       GROUP BY endpoint_id
			   ) rolled`,
			tenantID).Scan(&out.Endpoints, &out.Verified, &out.Diverged, &out.Unreachable)
	})
	return out, err
}
