// SPDX-License-Identifier: BUSL-1.1

// Package revoke is the CONTROL-PLANE cascaded-revocation engine (AGID-10, the
// cascade limbs of independent AGID-claim-16): on a revocation directive naming a subject
// it determines the descendant credential set from the AGID-02 delegation-tree
// projection and RECORDS the determining watermark (§7.1); it commits the directive
// projection AND one revocation job per descendant in ONE database transaction via
// the AN-6 transactional outbox (the JetStream directive event is appended
// durable-first and reconciled — see the G3 design note); each job executes
// idempotently with at-least-once delivery and AT MOST ONE recorded effect per AN-5
// idempotency key (AGID-claim-21), performing at least one external effect (status flip,
// KRL/CRL publish through the same outbox — AGID-claim-19, session invalidation, or
// dependent notification); every completed job records SIGNED per-job completion
// evidence in the ledger (§7.3 / INV-A9); and a descendant whose delegation record
// was committed after the watermark generates a FOLLOW-ON job under the same
// directive (§7.2).
//
// It lives in its OWN package, SEPARATE from the signer-linked `delegation` package,
// so the isolated AN-4 signer never links a SQL driver or the message bus through
// this control-plane code (AN-4). It imports the AGID-02 store (SQL) and the core
// orchestrator outbox (NATS/SQL) — both control-plane substrates — and signs
// completion evidence via internal/crypto (AN-3). It does NOT flip the subject to the
// terminal `revoked-with-evidence` state; that gate, the aggregate evidence artifact,
// and the in-signer refuse-while-active are AGID-11.
//
// It writes raw per-tenant DML against tenant tables (the directive/job rows and the
// AN-6 outbox enqueue, on the caller's RLS-scoped tx), so it opts into the AN-1
// tenant-filter rule with the //trstctl:repository marker: the tenantfilter analyzer
// then actively verifies every query below constrains tenant_id in a
// WHERE/ON-CONFLICT/INSERT-column predicate (fail-closed, ARCH-004).
//
//trstctl:repository
package revoke

import (
	"fmt"

	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/eventspec"
)

// ReasonClass is the directive reason class recorded in the ledger (AGID-claim-17): why
// the subject is being revoked. The four classes are the ones the patent enumerates;
// an unknown class is rejected at directive construction so the ledger only ever
// carries a recognized reason (a malformed reason is a producer bug, not silent).
type ReasonClass string

// The recognized reason classes (AGID-claim-17).
const (
	// ReasonCompromise: the subject (or a key on its chain) is believed compromised.
	ReasonCompromise ReasonClass = "compromise"
	// ReasonTaskCompletion: the delegated task is complete and the credential is no
	// longer needed (routine teardown).
	ReasonTaskCompletion ReasonClass = "task-completion"
	// ReasonPolicyChange: a policy change invalidates the outstanding authority.
	ReasonPolicyChange ReasonClass = "policy-change"
	// ReasonRootPrincipalRequest: the root principal explicitly requested revocation.
	ReasonRootPrincipalRequest ReasonClass = "root-principal-request"
)

// Valid reports whether rc is one of the recognized reason classes.
func (rc ReasonClass) Valid() bool {
	switch rc {
	case ReasonCompromise, ReasonTaskCompletion, ReasonPolicyChange, ReasonRootPrincipalRequest:
		return true
	default:
		return false
	}
}

// EffectClass is the class of external effect a revocation job performs (recorded in
// the per-job completion evidence, §7.3). A job executes at least one of these; the
// executor records the one it performed as the evidence's effect class.
type EffectClass string

// The revocation effect classes (§7, AGID-claim-16/19).
const (
	// EffectRevoke: flip the descendant credential's status to revoked (the core
	// revoke effect; every job performs at least this).
	EffectRevoke EffectClass = "revoke"
	// EffectKRLPublish: publish a revocation entry (KRL/CRL) to a downstream trust
	// plane through the SAME outbox (AGID-claim-19).
	EffectKRLPublish EffectClass = "krl-publish"
	// EffectSessionInvalidate: invalidate the descendant's active sessions.
	EffectSessionInvalidate EffectClass = "session-invalidate"
	// EffectNotify: notify registered dependents of the revocation.
	EffectNotify EffectClass = "notify"
)

// Directive is a revocation directive naming a subject (a delegation record, agent
// identity, or credential — an opaque subject id here) and the reason class. The
// cascade determines the descendant set + watermark for this subject and records the
// directive in the ledger. DirectiveID is the caller-supplied stable id of the
// directive (used to derive per-job idempotency keys); when empty the cascade derives
// it from the durable-first directive event id, so a replay keys the same jobs.
type Directive struct {
	TenantID    string
	DirectiveID string
	Subject     string
	Reason      ReasonClass
}

// validate checks the directive is well-formed before any determination or ledger
// write: it names a tenant and a subject and carries a recognized reason class
// (fail-closed — a bad reason never reaches the ledger).
func (d Directive) validate() error {
	if d.TenantID == "" {
		return fmt.Errorf("revoke: directive requires a tenant (AN-1)")
	}
	if d.Subject == "" {
		return fmt.Errorf("revoke: directive requires a subject")
	}
	if !d.Reason.Valid() {
		return fmt.Errorf("revoke: directive reason class %q is not recognized (AGID-claim-17)", d.Reason)
	}
	return nil
}

// directiveEvent builds the AN-2 RevocationDirective event that records this
// directive and the determining watermark (§7.1, AGID-claim-16). It reuses the AGID-01
// RevocationDirectiveV1 payload + Encode so the event is the exact shape the AGID-02
// projection folds. eventID is stamped by the caller before append (durable-first),
// so the reconcile pass can key the per-descendant outbox jobs on it (G3).
func (d Directive) directiveEvent(eventID string, watermark uint64) (eventspec.Event, error) {
	ev, err := delegation.Encode(delegation.RevocationDirectiveV1{
		TenantID:  d.TenantID,
		SubjectID: d.Subject,
		Reason:    string(d.Reason),
		Watermark: watermark,
	})
	if err != nil {
		return eventspec.Event{}, fmt.Errorf("revoke: encode directive event: %w", err)
	}
	ev.ID = eventID
	return ev, nil
}
