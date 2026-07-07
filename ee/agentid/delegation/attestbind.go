// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// attestbind.go defines the PURE, datastore-free control-plane contracts the AGID-07b
// broker precondition uses to bind a verified attestation to the issuance it justified
// and to refuse a REPLAY (claim 9 / INV-A6), plus the sub-hour TTL-ceiling derivation the
// ephemeral issuer is clamped to (claims 7/26 / INV-A7).
//
// IMPORTANT (AN-4): this file — and the whole `delegation` package — is SIGNER-LINKED
// (cmd/trstctl-signer attaches delegation.NewSignerGate). It therefore imports NO
// datastore: the concrete PostgreSQL-backed recorder lives in the CONTROL-PLANE-ONLY
// sub-package ee/agentid/delegation/brokerstore, which the signer never imports. Here we
// define only the IssuanceBinding value, the IssuanceBindingRecorder interface the
// precondition holds, the sub-hour ceiling math, and the shared errors — all pure Go, no
// pgx, no database/sql. This keeps the isolated signer's dependency closure free of a
// message bus and a SQL driver (TestSignerDependencyClosure).

// AttestationBindingDestination is the AN-6 outbox destination the attestation-binding
// publish intent is enqueued under. A separate worker drains it at-least-once; the
// carried idempotency key renders the downstream effect exactly-once (AN-5/AN-6). It is
// non-secret and edition-scoped. The brokerstore recorder enqueues under it.
const AttestationBindingDestination = "agid.attestation.bound"

// Binding/TTL errors (shared by the precondition here and the brokerstore recorder).
var (
	// ErrAttestationReplay is returned when the attestation evidence presented for an
	// issuance has ALREADY justified an issuance for this tenant (the evidence_digest
	// UNIQUE index rejected the insert). The second issuance is refused with NO key op
	// (claim 9 / INV-A6). The brokerstore recorder returns it; the precondition surfaces
	// it.
	ErrAttestationReplay = errors.New("delegation: attestation evidence already bound to a prior issuance (replay refused)")
	// ErrNoBindingStore is returned when the precondition has no recorder configured (or a
	// recorder with no store). Fail-closed: without durable binding there is no replay
	// defense, so issuance is refused rather than minted unrecorded.
	ErrNoBindingStore = errors.New("delegation: no attestation-binding store configured")
	// ErrTTLCeilingExceeded is returned when the requested credential validity would
	// exceed the minimum validity ceiling along the delegation chain, or is not
	// sub-hour. Fail-closed: an over-long credential is refused, never minted (claim 7
	// / INV-A7).
	ErrTTLCeilingExceeded = errors.New("delegation: requested credential TTL exceeds the chain ceiling or is not sub-hour")
	// ErrNoChainCeiling is returned when a sub-hour ceiling cannot be derived. Fail-closed.
	ErrNoChainCeiling = errors.New("delegation: cannot derive a validity ceiling from the chain")
)

// SubHour is the hard sub-hour ceiling every chain-bound ephemeral credential is clamped
// to (claim 7 / INV-A7: validity < 1h). A derived or requested TTL at or above this is
// clamped below it; a credential can never be minted with an hour-or-longer lifetime.
const SubHour = time.Hour

// maxSubHour is the largest lifetime a chain-bound credential may carry: strictly less
// than SubHour. One second below the hour keeps the credential provably sub-hour while
// leaving the ceiling as generous as the invariant allows.
const maxSubHour = SubHour - time.Second

// IssuanceBinding is the durable record of one chain-bound issuance: the credential it
// minted, the verified chain head + agent-stack + attestation digests to persist
// (INV-A3/A6), the validity window, and the idempotency key the outbox intent carries. It
// is a pure value the precondition assembles and hands to an IssuanceBindingRecorder.
type IssuanceBinding struct {
	// TenantID scopes every row (AN-1).
	TenantID string
	// IdempotencyKey keys the AN-6 outbox intent so at-least-once delivery is
	// exactly-once downstream, and (paired with the AN-5 idempotencer) collapses a
	// retried request to a single issuance event (claim 15 / AN-5).
	IdempotencyKey string
	// CredentialID is the issued credential's identifier (the mint result's id).
	CredentialID string
	// CredentialDER is the public issued credential/certificate bytes returned by the
	// isolated signer. It is public material only and lets the control plane serve the
	// credential a relying party verifies offline; no private key material crosses.
	CredentialDER []byte
	// SubjectID is the agent subject the credential was issued for.
	SubjectID string
	// ChainHeadDigest is the verified leaf record digest (chain head); ChainDigest is
	// the digest over the whole verified chain (the binding material digest). Both are
	// persisted so the issuance registry binds the exact chain that justified it.
	ChainHeadDigest []byte
	ChainDigest     []byte
	// AgentStackDigest is the agent-stack representation digest (empty in the chain-only
	// fallback).
	AgentStackDigest []byte
	// TaskEnvelopeDigest is the optional bound task-envelope digest (AGID-05).
	TaskEnvelopeDigest []byte
	// EvidenceDigest is the verified attestation-evidence digest whose per-tenant
	// uniqueness refuses a replay (claim 9 / INV-A6). Empty when no attestation was
	// required (chain-only fallback), in which case no binding row is written and no
	// replay defense applies (there is nothing to replay).
	EvidenceDigest []byte
	// AttestationClass names the verified attestation class recorded with the binding.
	AttestationClass string
	// NotBefore/NotAfter are the credential validity window (Unix seconds) to persist.
	NotBefore int64
	NotAfter  int64
	// Chain is the verified public delegation chain that justified this issuance, ordered
	// root-first. The control-plane recorder projects it into the tenant read model and
	// ledger after the signer has approved it, so GET chain and cascade revocation operate
	// on the same verified facts. Public DER/signatures only; no private key material.
	Chain []RecordEnvelope
}

// IssuanceBindingRecorder records one chain-bound issuance's binding durably and refuses
// a replay. The production recorder (ee/agentid/delegation/brokerstore.Recorder) satisfies
// it over the AGID-02 store + AN-6 outbox; it is an interface so the BrokerPrecondition —
// and the signer-linked delegation package — stay datastore-free (AN-4), while the
// replay/idempotency paths use the real recorder against embedded PostgreSQL.
type IssuanceBindingRecorder interface {
	// RecordIssuanceBinding persists the issuance + attestation binding + AN-6 outbox
	// intent in one transaction, returning ErrAttestationReplay when the evidence was
	// already bound (claim 9 / INV-A6). It performs no key operation.
	RecordIssuanceBinding(ctx context.Context, b IssuanceBinding) error
}

// SubHourCeiling derives the credential lifetime for a chain-bound issuance: the MINIMUM
// of (a) the tightest remaining validity along the chain relative to now, (b) an
// explicit requested TTL when positive, and (c) the hard sub-hour ceiling. The result is
// always strictly less than one hour and never longer than the chain permits (claim 7 /
// INV-A7). It is a pure computation over the already-verified chain — no revocation
// status is queried (revocation is by expiry, claim 26).
//
// requestedTTL <= 0 means "no explicit request": the ceiling is derived from the chain
// (clamped sub-hour). A positive requestedTTL that exceeds the derived ceiling is an
// error (ErrTTLCeilingExceeded) — the caller asked for more than the chain allows.
func SubHourCeiling(chain []RecordEnvelope, now time.Time, requestedTTL time.Duration) (time.Duration, error) {
	ceiling := maxSubHour
	nowUnix := now.Unix()
	for _, env := range chain {
		na := env.Record.Validity.NotAfter
		if na == 0 {
			continue // an open-ended hop imposes no ceiling of its own
		}
		remain := time.Duration(na-nowUnix) * time.Second
		if remain <= 0 {
			// An already-expired hop cannot justify any live credential.
			return 0, fmt.Errorf("%w: a chain hop has already expired", ErrTTLCeilingExceeded)
		}
		if remain < ceiling {
			ceiling = remain
		}
	}
	if requestedTTL > 0 {
		if requestedTTL > ceiling {
			return 0, fmt.Errorf("%w: requested %s exceeds ceiling %s", ErrTTLCeilingExceeded, requestedTTL, ceiling)
		}
		return requestedTTL, nil
	}
	// No explicit request: use the derived ceiling. It is sub-hour by construction
	// (initialized to maxSubHour and only ever lowered), so a chain of purely open-ended
	// hops still yields the sub-hour clamp rather than an unbounded credential.
	if ceiling <= 0 || ceiling >= SubHour {
		return 0, ErrNoChainCeiling
	}
	return ceiling, nil
}
