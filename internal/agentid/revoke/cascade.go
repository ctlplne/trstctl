// SPDX-License-Identifier: BUSL-1.1

package revoke

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agentid/delegation"
	agidstore "trstctl.com/trstctl/internal/agentid/delegation/store"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

// EventLog is the narrow slice of the AN-2 event log the cascade needs: append a
// durable event and replay the stream. The concrete implementation is
// internal/events.Log (JetStream); this interface keeps the cascade testable and
// documents that the cascade only ever appends (never deletes) directive/evidence
// events and reads the prefix to determine descendants. Sequence is assigned by
// Append and set on Replay, exactly as events.Log does.
type EventLog interface {
	Append(ctx context.Context, e eventspec.Event) (eventspec.Event, error)
	Replay(ctx context.Context, from uint64, fn func(eventspec.Event) error) error
}

// OutboxEnqueuer is the AN-6 transactional-outbox seam the cascade enqueues on. It is
// exactly the core orchestrator.Outbox surface (Enqueue / EnqueueIfAbsent on the
// caller's tx), named generically here so the cascade depends on the feature-neutral
// enqueue primitive rather than any revocation-specific outbox. The core outbox row
// carries "jobs"/destinations, not "revocation" (editions-gate stays green).
type OutboxEnqueuer interface {
	Enqueue(ctx context.Context, tx pgx.Tx, e orchestrator.Entry) (int64, error)
	EnqueueIfAbsent(ctx context.Context, tx pgx.Tx, e orchestrator.Entry) (bool, error)
}

// Cascade is the control-plane revocation cascade engine. It reads the AGID-02
// projection to determine descendants, records the directive durable-first on the
// event log, and commits the directive projection ⊕ the per-descendant outbox jobs in
// ONE database transaction (INV-A8). It holds no key material; the executor it builds
// signs completion evidence with a signer supplied per-run.
type Cascade struct {
	log    EventLog
	core   *corestore.Store
	repo   *agidstore.Repo
	outbox OutboxEnqueuer
}

// NewCascade builds a cascade over the event log, the core store (for the shared RLS
// transaction), the AGID-02 repo (directive/job rows + the descendant read), and the
// AN-6 outbox. All four are required; a nil dependency is a wiring bug (fail-closed).
func NewCascade(log EventLog, core *corestore.Store, repo *agidstore.Repo, outbox OutboxEnqueuer) (*Cascade, error) {
	if log == nil || core == nil || repo == nil || outbox == nil {
		return nil, fmt.Errorf("revoke: NewCascade requires log, core store, repo, and outbox")
	}
	return &Cascade{log: log, core: core, repo: repo, outbox: outbox}, nil
}

// DirectiveResult is the outcome of enqueuing a directive: the directive id the jobs
// are keyed under, the durable-first directive event id (the reconcile key, G3), the
// determining watermark recorded in the directive, and the descendant credential set
// that was enqueued (one job each).
type DirectiveResult struct {
	DirectiveID string
	EventID     string
	Watermark   uint64
	Descendants []string
}

// EnqueueDirective runs the determination + transactional-enqueue limbs of the
// cascade (AGID-claim-16):
//
//  1. DETERMINE the descendant credential set for the directive's subject from the
//     AGID-02 delegation-tree projection, AS OF a watermark = the current head of the
//     ledger (the highest folded sequence). The set and the watermark are a pure,
//     replayable function of the event prefix (§7.1).
//  2. Append the RevocationDirective event DURABLE-FIRST on the JetStream log,
//     recording the reason class (AGID-claim-17) and the determining watermark. The
//     JetStream append is NOT in the pg tx (it cannot join one — G3); it is the source
//     of truth and its ID keys the outbox jobs so the append→enqueue gap is healable.
//  3. In ONE pg transaction: insert the directive projection row + one revocation-job
//     row per descendant AND enqueue one outbox job per descendant (EnqueueIfAbsent,
//     keyed by the per-job idempotency key). A fault between the directive/projection
//     write and the job enqueue leaves NEITHER (they share the tx) — the INV-A8
//     atomicity the card asserts.
//
// It performs no key operation. downstreamCredentials, when non-empty, marks those
// descendants' jobs to also publish a downstream-plane revocation entry (AGID-claim-19);
// pass the full descendant set to publish for every credential.
func (c *Cascade) EnqueueDirective(ctx context.Context, d Directive) (DirectiveResult, error) {
	if err := d.validate(); err != nil {
		return DirectiveResult{}, err
	}

	// (1) Determine descendants + watermark from the projection (as-of ledger head).
	watermark, err := c.ledgerHead(ctx)
	if err != nil {
		return DirectiveResult{}, err
	}
	descendants, err := c.descendantsAsOf(ctx, d.TenantID, d.Subject, watermark)
	if err != nil {
		return DirectiveResult{}, err
	}

	// (2) Append the directive event DURABLE-FIRST (records reason + watermark). Its
	// ID keys the reconcile pass (G3). We pre-generate the ID so the payload the
	// projection folds and the outbox key derive from the same identity.
	eventID := neweventID()
	ev, err := d.directiveEvent(eventID, watermark)
	if err != nil {
		return DirectiveResult{}, err
	}
	appended, err := c.log.Append(ctx, ev)
	if err != nil {
		return DirectiveResult{}, fmt.Errorf("revoke: append directive event: %w", err)
	}

	// The directive id the jobs are keyed under. When the caller did not supply a
	// stable id, use the durable-first event id so a replay/reconcile keys the same
	// jobs (idempotent by construction).
	directiveID := d.DirectiveID
	if directiveID == "" {
		directiveID = appended.ID
	}

	// (3) ONE pg tx: directive projection row + per-descendant job rows + outbox jobs.
	dir := agidstore.RevocationDirective{
		DirectiveID: directiveID,
		SubjectID:   d.Subject,
		Reason:      string(d.Reason),
		Watermark:   watermark,
		Terminal:    false, // AGID-11 flips terminal; this card never does.
		Seq:         appended.Sequence,
	}
	jobRows := make([]agidstore.RevocationJob, 0, len(descendants))
	for _, cred := range descendants {
		jobRows = append(jobRows, agidstore.RevocationJob{
			DirectiveID:    directiveID,
			IdempotencyKey: JobIdempotencyKey(directiveID, cred),
			CredentialID:   cred,
			FollowOn:       false,
		})
	}

	err = c.core.WithTenant(ctx, d.TenantID, func(tx pgx.Tx) error {
		// Directive projection row + per-descendant job rows, on the caller's tx.
		if err := agidstore.InsertRevocationDirectiveWithJobsTx(ctx, tx, dir, jobRows); err != nil {
			return err
		}
		// One outbox job per descendant, SAME tx (transactional outbox, INV-A8).
		// EnqueueIfAbsent keyed by the per-job idempotency key so the inline enqueue
		// and any later reconcile cannot both enqueue the same job.
		for _, cred := range descendants {
			body, err := JobPayload{
				TenantID:          d.TenantID,
				DirectiveID:       directiveID,
				CredentialID:      cred,
				Reason:            d.Reason,
				PublishDownstream: true, // every descendant publishes downstream (AGID-claim-19)
			}.encode()
			if err != nil {
				return err
			}
			if _, err := c.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID:       d.TenantID,
				Destination:    DestinationRevocationJob,
				IdempotencyKey: JobIdempotencyKey(directiveID, cred),
				Payload:        body,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return DirectiveResult{}, fmt.Errorf("revoke: commit directive+jobs+outbox: %w", err)
	}

	return DirectiveResult{
		DirectiveID: directiveID,
		EventID:     appended.ID,
		Watermark:   watermark,
		Descendants: descendants,
	}, nil
}

// ledgerHead returns the highest event sequence currently in the log — the watermark
// the descendant set is determined as-of. It replays only to observe the last
// sequence (the fold to determine descendants is a second, bounded pass). A log with
// no events yields 0.
func (c *Cascade) ledgerHead(ctx context.Context) (uint64, error) {
	var head uint64
	if err := c.log.Replay(ctx, 1, func(e eventspec.Event) error {
		if e.Sequence > head {
			head = e.Sequence
		}
		return nil
	}); err != nil {
		return 0, fmt.Errorf("revoke: read ledger head: %w", err)
	}
	return head, nil
}

// descendantsAsOf folds the ledger prefix up to watermark and returns the descendant
// credential set for subject, using the AGID-02 projection (the authoritative fold).
// It is deterministic and idempotent under replay and duplicate delivery (the
// projection guarantees it), so the enumeration recorded against the watermark is
// reproducible (§7.1, AGID-claim-16 / INV-A8).
func (c *Cascade) descendantsAsOf(ctx context.Context, tenantID, subject string, watermark uint64) ([]string, error) {
	prefix, err := c.tenantPrefix(ctx, tenantID, watermark)
	if err != nil {
		return nil, err
	}
	set, err := delegation.DescendantSetOf(prefix, subject, watermark)
	if err != nil {
		return nil, fmt.Errorf("revoke: fold descendant set: %w", err)
	}
	return set.Credentials, nil
}

// tenantPrefix replays the ledger prefix with sequence <= watermark and returns the
// events for tenantID, with Sequence set (so the bounded fold is exact, AN-1). The
// projection's fold ignores non-delegation events, so replaying the whole prefix and
// filtering by tenant is correct and keeps this package from needing a tenant-scoped
// event index.
func (c *Cascade) tenantPrefix(ctx context.Context, tenantID string, watermark uint64) ([]eventspec.Event, error) {
	var out []eventspec.Event
	if err := c.log.Replay(ctx, 1, func(e eventspec.Event) error {
		if watermark != delegation.UnboundedWatermark && e.Sequence > watermark {
			return nil
		}
		if e.TenantID == tenantID {
			out = append(out, e)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("revoke: replay tenant prefix: %w", err)
	}
	return out, nil
}
