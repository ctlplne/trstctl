// SPDX-License-Identifier: BUSL-1.1

package revoke

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

// neweventID returns an opaque, unique event id for a durable-first append. It uses
// internal/crypto randomness (AN-3) so this package needs no stdlib rand and does not
// couple to internal/events' id generator; the id only needs to be globally unique
// (the reconcile key). 16 random bytes are collision-safe for this use.
func neweventID() string {
	b, err := crypto.RandomBytes(16)
	if err != nil {
		// RandomBytes only fails if the OS CSPRNG fails, which is fatal for a
		// control plane; surface a recognizable sentinel the caller's append will
		// reject rather than silently minting a weak id.
		return ""
	}
	return "agid-revoke-evt-" + hex.EncodeToString(b)
}

// Clock returns the current Unix time in seconds. It is injected so completion
// evidence timestamps are deterministic in tests.
type Clock func() int64

// Executor performs a single revocation job idempotently and records SIGNED per-job
// completion evidence (AGID-claims-16/19/21 / INV-A9). It is the outbox Handler the
// dispatcher hands a claimed revocation-job Message: it decodes the job payload,
// performs the effect(s), and — in ONE pg transaction — records the effect (keyed by
// the job's idempotency key so AT MOST ONE effect is recorded per key), stamps the
// job's completion reference, appends the signed completion-evidence event
// durable-first, and (for a downstream-publishing job) enqueues the downstream-plane
// revocation entry on the SAME transaction (AGID-claim-19). A worker retrying the job
// at-least-once re-runs Execute; the conditional effect insert collapses a redelivery
// whose effect already landed to a no-op, so execution resumes after a control-plane
// failure without duplication or loss (AGID-claim-21).
type Executor struct {
	log       EventLog
	repo      repoTxAccess
	outbox    OutboxEnqueuer
	signer    crypto.Signer
	executor  string
	clock     Clock
	effectsOf func(JobPayload) []EffectClass
}

// repoTxAccess is the narrow core-store surface the executor needs: run a tenant tx.
// The AGID-02 *store.Repo does not expose this, so the executor holds the core store
// directly (like brokerstore does). It is an interface so tests can pass the real
// core store.
type repoTxAccess interface {
	WithTenant(ctx context.Context, tenantID string, fn func(pgx.Tx) error) error
}

// ExecutorOption configures an Executor.
type ExecutorOption func(*Executor)

// WithExecutorID sets the executor identity recorded in completion evidence.
func WithExecutorID(id string) ExecutorOption {
	return func(e *Executor) {
		if id != "" {
			e.executor = id
		}
	}
}

// WithClock injects the executor clock (deterministic tests). Production uses a real
// Unix-seconds clock.
func WithClock(clock Clock) ExecutorOption {
	return func(e *Executor) {
		if clock != nil {
			e.clock = clock
		}
	}
}

// WithEffectClasses overrides which effect classes a job performs, as a function of
// its payload. The default performs revoke (always) plus krl-publish for a
// downstream-publishing job. It exists so a deployment can add session-invalidate /
// notify effects; each job still records exactly one primary effect class in its
// evidence (the first in the returned list), and any additional effects are performed
// under the same idempotency key so the whole job stays at-most-once.
func WithEffectClasses(f func(JobPayload) []EffectClass) ExecutorOption {
	return func(e *Executor) {
		if f != nil {
			e.effectsOf = f
		}
	}
}

// NewExecutor builds the job executor over the event log (evidence append), the core
// store (the shared effect/evidence/outbox transaction), the AN-6 outbox (downstream
// publication), and the completion-evidence signer (internal/crypto, AN-3). log,
// core, outbox, and signer are required.
func NewExecutor(log EventLog, core repoTxAccess, outbox OutboxEnqueuer, signer crypto.Signer, opts ...ExecutorOption) (*Executor, error) {
	if log == nil || core == nil || outbox == nil || signer == nil {
		return nil, fmt.Errorf("revoke: NewExecutor requires log, core store, outbox, and signer")
	}
	e := &Executor{
		log:      log,
		repo:     core,
		outbox:   outbox,
		signer:   signer,
		executor: "agid-revoke-executor",
		clock:    func() int64 { return 0 },
		effectsOf: func(p JobPayload) []EffectClass {
			effects := []EffectClass{EffectRevoke}
			if p.PublishDownstream {
				effects = append(effects, EffectKRLPublish)
			}
			return effects
		},
	}
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
}

// Handler adapts the executor to the core orchestrator.Handler so the outbox
// dispatcher can drive it. Delivery is at-least-once; Execute is idempotent on the
// message's IdempotencyKey, so the net effect is exactly-once (the AN-5 ↔ AN-6
// bridge).
func (e *Executor) Handler() orchestrator.Handler {
	return orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
		return e.Execute(ctx, m)
	})
}

// Execute performs the revocation job carried by m and records its signed completion
// evidence idempotently. It decodes the job payload, computes the effect class(es),
// signs the completion evidence, and in ONE pg transaction records the effect
// (at-most-one per idempotency key), stamps the job completion ref, appends the
// evidence event durable-first, and enqueues the downstream-plane publication for a
// publishing job (AGID-claim-19). A redelivery whose effect already landed is a no-op
// (AGID-claim-21). The message's IdempotencyKey is the job key; m.Payload is the JobPayload.
func (e *Executor) Execute(ctx context.Context, m orchestrator.Message) error {
	p, err := decodeJobPayload(m.Payload)
	if err != nil {
		return err
	}
	if p.TenantID == "" || p.DirectiveID == "" || p.CredentialID == "" {
		return fmt.Errorf("revoke: job payload missing tenant, directive, or credential")
	}
	idempotencyKey := m.IdempotencyKey
	if idempotencyKey == "" {
		idempotencyKey = JobIdempotencyKey(p.DirectiveID, p.CredentialID)
	}

	effects := e.effectsOf(p)
	if len(effects) == 0 {
		effects = []EffectClass{EffectRevoke}
	}
	primary := effects[0]

	// Build + sign the completion evidence for the primary effect. Signing is
	// side-effect-free and outside the tx; the recorded-effect insert is what makes
	// the whole job at-most-once. The evidence event id is durable-first appended
	// inside the tx-guarded path below only when the effect is newly recorded.
	evidence := CompletionEvidence{
		TenantID:       p.TenantID,
		DirectiveID:    p.DirectiveID,
		IdempotencyKey: idempotencyKey,
		CredentialID:   p.CredentialID,
		EffectClass:    primary,
		CompletedAt:    e.clock(),
		Executor:       e.executor,
	}
	signed, body, err := signCompletionEvidence(e.signer, evidence)
	if err != nil {
		return err
	}

	// First, atomically claim the effect: record it iff absent. This is the AN-5
	// idempotency gate (AGID-claim-21). If another attempt already recorded the effect,
	// recorded is false and we must NOT re-append evidence or re-publish downstream.
	recorded := false
	err = e.repo.WithTenant(ctx, p.TenantID, func(tx pgx.Tx) error {
		ins, err := recordEffectTx(ctx, tx, p, idempotencyKey, primary, e.executor, signed.CompletedAt, body, signed.Signature, signed.PublicKey)
		if err != nil {
			return err
		}
		recorded = ins
		if !recorded {
			return nil // effect already landed: no-op (AGID-claim-21)
		}
		// Downstream-plane publication (AGID-claim-19), SAME tx as the effect, so the
		// publish intent is durable iff the effect is. Keyed independently but stably
		// so a redelivery de-duplicates downstream.
		if p.PublishDownstream {
			entry, err := encodeDownstreamEntry(p.TenantID, p.CredentialID, p.Reason)
			if err != nil {
				return err
			}
			if _, err := e.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID:       p.TenantID,
				Destination:    DestinationDownstreamPlane,
				IdempotencyKey: downstreamIdempotencyKey(p.DirectiveID, p.CredentialID),
				Payload:        entry,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("revoke: execute job %q: %w", idempotencyKey, err)
	}
	if !recorded {
		return nil
	}

	// The effect + downstream intent committed. Append the signed completion-evidence
	// event to the ledger durable-first (AN-2). The recorded-effect row is the
	// idempotency guard, so if this append fails the job is retried and the effect
	// insert is a no-op — the evidence event is re-appended without a second effect.
	// Because the effect row is the source of truth for "evidenced", a duplicate
	// evidence event on retry is harmless (the terminal gate reads effect rows).
	if err := e.appendEvidenceEvent(ctx, p, signed, body); err != nil {
		return fmt.Errorf("revoke: append completion evidence: %w", err)
	}
	return nil
}
