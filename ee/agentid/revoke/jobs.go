// SPDX-License-Identifier: LicenseRef-trstctl-EE

package revoke

import (
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// Outbox destinations for the cascade. The cascade job source is a FEATURE-NEUTRAL
// outbox seam: these are plain destination strings on the AN-6 outbox (the outbox
// names "jobs"/destinations, not "revocation"), so `make editions-gate` stays green
// and the core outbox carries no edition-specific concept. The downstream trust-plane
// publication (claim 19) is just another destination.
const (
	// DestinationRevocationJob is the per-descendant cascade job: the executor claims
	// it, performs the effect(s), and records signed completion evidence. One job per
	// descendant is enqueued in the directive transaction (INV-A8).
	DestinationRevocationJob = "agent.revocation.job"
	// DestinationDownstreamPlane is the downstream trust-plane revocation-entry
	// publication (KRL/CRL) — a job publishes a revocation entry here through the SAME
	// outbox (claim 19 / AN-6).
	DestinationDownstreamPlane = "agent.revocation.downstream-plane"
)

// JobPayload is the durable, replayable body of a per-descendant revocation job,
// stored as outbox.payload. It carries everything the executor needs to perform the
// effect idempotently and to sign completion evidence, with NO key material: the
// directive it belongs to, the target credential, whether it is a follow-on, and the
// reason class (carried so downstream publications and notifications can state why).
// It is a pure value; the idempotency key is the outbox row's key, derived by
// JobIdempotencyKey, so a redelivery collapses to one recorded effect (claim 21).
type JobPayload struct {
	TenantID     string      `json:"tenant_id"`
	DirectiveID  string      `json:"directive_id"`
	CredentialID string      `json:"credential_id"`
	Reason       ReasonClass `json:"reason"`
	FollowOn     bool        `json:"follow_on,omitempty"`
	// PublishDownstream marks a job that must also publish a revocation entry to the
	// downstream trust plane (KRL/CRL) through the outbox (claim 19). The executor
	// enqueues that publication in the SAME transaction as recording the job effect.
	PublishDownstream bool `json:"publish_downstream,omitempty"`
}

// encode marshals the job payload to the outbox body bytes.
func (p JobPayload) encode() ([]byte, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("revoke: encode job payload: %w", err)
	}
	return b, nil
}

// decodeJobPayload parses an outbox body back into a JobPayload.
func decodeJobPayload(b []byte) (JobPayload, error) {
	var p JobPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return JobPayload{}, fmt.Errorf("revoke: decode job payload: %w", err)
	}
	return p, nil
}

// JobIdempotencyKey derives the stable AN-5 idempotency key for the job that revokes
// credentialID under directiveID. It is a pure function of (directiveID,
// credentialID): the enqueue, the outbox delivery, the recorded-effect insert, and
// any reconcile/replay all derive the same key, so a job that runs more than once
// (at-least-once delivery, crash-resume, follow-on re-enqueue) records AT MOST ONE
// effect (claim 21 / INV-A8). It also namespaces the directive so two directives
// against overlapping descendant sets keep independent per-job effects.
func JobIdempotencyKey(directiveID, credentialID string) string {
	return "agid-revoke:" + directiveID + ":" + credentialID
}

// downstreamIdempotencyKey derives the idempotency key for the downstream-plane
// publication a job emits (claim 19). It is distinct from the job's own key so the
// publication and the job effect are independently at-most-once, but still stable per
// (directive, credential) so a re-published entry is de-duplicated downstream.
func downstreamIdempotencyKey(directiveID, credentialID string) string {
	return "agid-revoke-downstream:" + directiveID + ":" + credentialID
}

// downstreamEntry is the revocation entry published to the downstream trust plane
// (KRL/CRL). It is deliberately minimal and self-describing so any downstream plane
// can consume it: the tenant, the revoked credential, and the reason class.
type downstreamEntry struct {
	TenantID     string      `json:"tenant_id"`
	CredentialID string      `json:"credential_id"`
	Reason       ReasonClass `json:"reason"`
}

// encodeDownstreamEntry marshals the downstream revocation entry to outbox bytes.
func encodeDownstreamEntry(tenantID, credentialID string, reason ReasonClass) ([]byte, error) {
	b, err := json.Marshal(downstreamEntry{TenantID: tenantID, CredentialID: credentialID, Reason: reason})
	if err != nil {
		return nil, fmt.Errorf("revoke: encode downstream entry: %w", err)
	}
	return b, nil
}

// completionRefOf derives the completion reference recorded on the job row and used
// to link the job to its evidence: a digest of the signed evidence body. It stays
// inside internal/crypto so this package never imports a stdlib hash (AN-3).
func completionRefOf(evidenceBody []byte) []byte {
	return crypto.SHA256Sum(evidenceBody)
}
