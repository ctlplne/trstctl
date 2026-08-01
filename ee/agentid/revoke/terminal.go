// SPDX-License-Identifier: LicenseRef-trstctl-EE

package revoke

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	agidstore "trstctl.com/trstctl/ee/agentid/delegation/store"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

// terminal.go is the AGID-11 terminal-state transition (AGID-claim-16 TERMINAL limb /
// INV-A9): the subject transitions to the terminal `revoked-with-evidence` state ONLY
// WHEN signed completion evidence exists — and VERIFIES — for EVERY enqueued AND
// follow-on job of the directive (the obligation set AGID-10 recorded). Missing or
// unverifiable evidence for any one job leaves the directive NON-terminal. The terminal
// verdict is VERIFIABLE FROM THE LEDGER BY DETERMINISTIC REPLAY: it is a pure function
// of the recorded jobs and their recorded per-job evidence, so a fresh reader replaying
// the durable state reaches the SAME verdict (VerifyTerminal below).
//
// On the transition, the engine — in ONE database transaction — flips the directive's
// terminal flag + stamps terminal_at (idempotently), and OUTSIDE the tx but bound to it
// durable-first appends the terminal AN-2 event carrying the SIGNED aggregate evidence
// artifact (aggregate.go: the completion-evidence digest + subject id + reason class +
// directive watermark + ledger head as of terminal — AGID-claims 18/33). It performs NO key
// op on issued credentials and NEVER mints a credential; its only signing is the
// aggregate artifact via internal/crypto (AN-3).
//
// IMPORTANT (spec note 1.5(b)): the terminal state is the LEDGER FACT that every
// enqueued and follow-on job completed, NOT a guarantee that an already-issued short-TTL
// credential is unusable before it expires. The cascade (AGID-10) covers
// sessions/dependents and FUTURE issuance/renewal (the latter refused in-signer while the
// directive is active — refuse_active.go); expiry covers the outstanding credential. This
// engine records the fact and its portable proof; it does not and must not claim more.

// TypeRevocationTerminal is the AN-2 event appended when a directive reaches the terminal
// revoked-with-evidence state (INV-A9). Its payload is the SIGNED aggregate evidence
// artifact, so the terminal fact and its offline-verifiable proof are replayable from the
// ledger alone. A projector that does not know it skips it (forward-compatible).
const TypeRevocationTerminal = "agent.revocation.terminal"

// RevocationTerminalSchemaV1 is the baseline payload-shape version for the terminal event.
const RevocationTerminalSchemaV1 = 1

// TerminalTransition performs the evidenced terminal-state transition for a directive
// (AGID-claim-16 terminal limb). It reads the obligation set + per-job evidence, verifies
// completeness, and — only when complete — flips the directive terminal and mints +
// appends the signed aggregate artifact. It holds the AGID-02 store (the durable
// obligation/evidence reads + the terminal flip), the AN-2 log (the durable-first
// terminal event), an aggregate-artifact signer (internal/crypto, AN-3), and a clock
// (injected so terminal_at is deterministic in tests). It performs no credential key op.
type TerminalTransition struct {
	repo   *agidstore.Repo
	core   repoTxAccess
	log    EventLog
	signer crypto.Signer
	clock  Clock
}

// NewTerminalTransition builds the terminal engine over the AGID-02 repo, the core store
// (the shared RLS transaction for the terminal flip), the AN-2 log (terminal event), and
// the aggregate-artifact signer. All four are required; a nil dependency is a wiring bug
// (fail-closed). The clock defaults to Unix-0 (deterministic); production injects a real
// clock, tests a fake one.
func NewTerminalTransition(repo *agidstore.Repo, core repoTxAccess, log EventLog, signer crypto.Signer, opts ...TerminalOption) (*TerminalTransition, error) {
	if repo == nil || core == nil || log == nil || signer == nil {
		return nil, fmt.Errorf("revoke: NewTerminalTransition requires repo, core store, log, and signer")
	}
	tt := &TerminalTransition{repo: repo, core: core, log: log, signer: signer, clock: func() int64 { return 0 }}
	for _, opt := range opts {
		opt(tt)
	}
	return tt, nil
}

// TerminalOption configures a TerminalTransition.
type TerminalOption func(*TerminalTransition)

// WithTerminalClock injects the clock used to stamp terminal_at (deterministic tests).
func WithTerminalClock(clock Clock) TerminalOption {
	return func(tt *TerminalTransition) {
		if clock != nil {
			tt.clock = clock
		}
	}
}

// TerminalVerdict is the deterministic result of evaluating a directive's obligation set
// against its recorded per-job evidence. Terminal is true iff EVERY job is evidenced AND
// every piece of evidence verifies. Missing is the idempotency keys of jobs with no
// recorded (or unverifiable) evidence — empty iff Terminal. LedgerHead is the ledger head
// observed as of the verdict (bound into the aggregate on transition). EvidenceDigests are
// the per-job completion-evidence digests (sorted-input to the aggregate digest) so a
// publisher can list exactly what an auditor verifies against.
type TerminalVerdict struct {
	DirectiveID     string
	Terminal        bool
	JobCount        int
	Missing         []string
	EvidenceDigests [][]byte
	LedgerHead      uint64
}

// VerifyTerminal computes the terminal verdict for a directive by DETERMINISTIC REPLAY of
// the durable state (AGID-claim-16 terminal limb / INV-A9): it reads the obligation set (every
// enqueued and follow-on job) and, for each, loads the recorded signed completion evidence
// and VERIFIES its signature. The directive is terminal iff there is at least one job and
// every job has verifying evidence. It is a PURE READ — no flip, no event, no signing — so
// a relying party or a replaying reader reaches the same verdict the transition did. A job
// with missing evidence, or evidence whose signature does not verify, is surfaced in
// Missing and makes the verdict non-terminal (unverifiable evidence is not proof).
func (tt *TerminalTransition) VerifyTerminal(ctx context.Context, tenantID, directiveID string) (TerminalVerdict, error) {
	jobs, err := tt.repo.FetchRevocationJobs(ctx, tenantID, directiveID)
	if err != nil {
		return TerminalVerdict{}, err
	}
	verdict := TerminalVerdict{DirectiveID: directiveID, JobCount: len(jobs)}

	for _, j := range jobs {
		ev, found, err := LoadEvidence(ctx, tt.repo, tenantID, directiveID, j.IdempotencyKey)
		if err != nil {
			// A stored evidence blob that cannot even be decoded is treated as missing
			// (unverifiable), not a hard engine error: the directive is simply not yet
			// terminal for that job. Surface it so callers can see which job is at fault.
			verdict.Missing = append(verdict.Missing, j.IdempotencyKey)
			continue
		}
		if !found {
			verdict.Missing = append(verdict.Missing, j.IdempotencyKey)
			continue
		}
		if err := VerifyCompletionEvidence(ev); err != nil {
			// Recorded but unverifiable evidence does not count as completion.
			verdict.Missing = append(verdict.Missing, j.IdempotencyKey)
			continue
		}
		// The per-job completion-evidence digest the aggregate binds is the digest of the
		// canonical evidence body — the same value the store stamped as the job completion
		// ref (jobs.go completionRefOf). Recompute it deterministically from the verified
		// evidence so the aggregate is reproducible on replay.
		body, err := ev.evidenceBodyBytes()
		if err != nil {
			verdict.Missing = append(verdict.Missing, j.IdempotencyKey)
			continue
		}
		verdict.EvidenceDigests = append(verdict.EvidenceDigests, completionRefOf(body))
	}

	// A directive with NO jobs is not "terminal": there is nothing evidenced. (A cascade
	// always enqueues at least the original descendant set; a zero-job directive is a
	// determination that found no descendants, which is a distinct, non-terminal state.)
	verdict.Terminal = len(jobs) > 0 && len(verdict.Missing) == 0

	head, err := tt.ledgerHead(ctx)
	if err != nil {
		return TerminalVerdict{}, err
	}
	verdict.LedgerHead = head
	return verdict, nil
}

// TransitionResult reports the outcome of a Transition attempt: whether the directive is
// (now or already) terminal, whether THIS call performed the flip (Transitioned=false for
// a repeat call or a non-terminal directive), and — when terminal — the signed aggregate
// artifact (encoded, portable) and its published per-job evidence digests.
type TransitionResult struct {
	DirectiveID       string
	Terminal          bool
	Transitioned      bool
	Verdict           TerminalVerdict
	AggregateArtifact []byte
	EvidenceDigests   [][]byte
}

// Transition evaluates the directive and, ONLY IF it is terminal (every enqueued and
// follow-on job evidenced + verifying), performs the terminal transition: in ONE RLS
// transaction it flips the directive terminal + stamps terminal_at (idempotent), and on a
// fresh flip mints the SIGNED aggregate artifact and appends the terminal AN-2 event
// durable-first (INV-A9). A non-terminal directive returns Terminal=false with no flip and
// no event. A second call after the flip returns Terminal=true, Transitioned=false and the
// SAME aggregate artifact (recomputed deterministically), so the operation is idempotent
// and replay-safe. tenantID scopes every read/write by RLS.
func (tt *TerminalTransition) Transition(ctx context.Context, tenantID, directiveID string) (TransitionResult, error) {
	// Directive must exist and carry a recognized reason (the aggregate binds the reason).
	dir, found, err := tt.repo.FetchRevocationDirective(ctx, tenantID, directiveID)
	if err != nil {
		return TransitionResult{}, err
	}
	if !found {
		return TransitionResult{}, fmt.Errorf("revoke: directive %q not found for terminal transition", directiveID)
	}
	reason := ReasonClass(dir.Reason)
	if !reason.Valid() {
		return TransitionResult{}, fmt.Errorf("revoke: directive %q has unrecognized stored reason %q", directiveID, dir.Reason)
	}

	verdict, err := tt.VerifyTerminal(ctx, tenantID, directiveID)
	if err != nil {
		return TransitionResult{}, err
	}
	res := TransitionResult{DirectiveID: directiveID, Verdict: verdict, EvidenceDigests: verdict.EvidenceDigests}
	if !verdict.Terminal {
		// Not every job evidenced: leave the directive non-terminal (fail-closed on the
		// terminal fact). No flip, no event, no artifact.
		return res, nil
	}
	res.Terminal = true

	// If the directive is ALREADY terminal, the canonical aggregate artifact is the one
	// appended durable-first at the transition; reload it from the ledger so a repeat call
	// returns the SAME bytes (idempotent + replay-safe). ECDSA signatures are randomized,
	// so re-signing would produce different bytes; the persisted artifact is authoritative.
	if dir.Terminal {
		persisted, found, err := tt.loadTerminalArtifact(ctx, tenantID, directiveID)
		if err != nil {
			return TransitionResult{}, err
		}
		if found {
			encoded, err := EncodeAggregate(persisted)
			if err != nil {
				return TransitionResult{}, err
			}
			res.AggregateArtifact = encoded
			res.Transitioned = false
			return res, nil
		}
		// Terminal flag set but no terminal event found (a crash between the flip and the
		// event append): fall through to mint + append, healing the missing event. The
		// flip below is a no-op (already terminal), so we append the (fresh) artifact.
	}

	// Build the signed aggregate artifact from the verdict (AGID-claims 18/33). The BOUND BODY is
	// deterministic (subject/reason/watermark/head/completion-digest); only the ECDSA
	// signature bytes vary run-to-run, which is why the persisted artifact above is reused
	// on a repeat call rather than re-signed.
	artifact, err := signAggregate(tt.signer, AggregateEvidence{
		TenantID:                 tenantID,
		DirectiveID:              directiveID,
		SubjectID:                dir.SubjectID,
		ReasonClass:              reason,
		Watermark:                dir.Watermark,
		LedgerHead:               verdict.LedgerHead,
		JobCount:                 verdict.JobCount,
		CompletionEvidenceDigest: CompletionEvidenceDigestOf(verdict.EvidenceDigests),
	})
	if err != nil {
		return TransitionResult{}, err
	}

	// Flip terminal + stamp terminal_at, idempotently, in ONE RLS tx. transitioned is true
	// only on the FIRST flip; a repeat call finds terminal already true and skips the event.
	transitioned := false
	terminalAt := tt.clock()
	err = tt.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		did, err := agidstore.MarkDirectiveTerminalTx(ctx, tx, directiveID, terminalAt)
		if err != nil {
			return err
		}
		transitioned = did
		return nil
	})
	if err != nil {
		return TransitionResult{}, fmt.Errorf("revoke: flip directive terminal: %w", err)
	}
	res.Transitioned = transitioned

	// Append the terminal AN-2 event carrying the signed aggregate artifact durable-first
	// (INV-A9), on the fresh flip OR when healing a set-but-eventless directive (the
	// fall-through above). The terminal flag alone does not carry the artifact, so the
	// event is what makes the terminal fact + its proof replayable from the ledger. We
	// append when we performed the flip, or when the flag was already set but no prior
	// event existed (found=false above led here).
	if transitioned || dir.Terminal {
		if err := tt.appendTerminalEvent(ctx, tenantID, directiveID, artifact); err != nil {
			return TransitionResult{}, err
		}
	}
	res.AggregateArtifact, err = EncodeAggregate(artifact)
	if err != nil {
		return TransitionResult{}, err
	}
	return res, nil
}

// loadTerminalArtifact reads the aggregate artifact recorded in the terminal AN-2 event
// for a directive back from the ledger. found is false when no terminal event exists yet.
// It is how a repeat Transition (already-terminal) returns the canonical persisted
// artifact rather than re-signing a fresh (byte-differing) one.
func (tt *TerminalTransition) loadTerminalArtifact(ctx context.Context, tenantID, directiveID string) (AggregateEvidence, bool, error) {
	var out AggregateEvidence
	found := false
	if err := tt.log.Replay(ctx, 1, func(e eventspec.Event) error {
		if found || e.Type != TypeRevocationTerminal || e.TenantID != tenantID {
			return nil
		}
		var pl terminalEventPayload
		if err := json.Unmarshal(e.Data, &pl); err != nil {
			return nil // a malformed/foreign terminal event is skipped, not fatal
		}
		if pl.DirectiveID == directiveID {
			out = pl.Aggregate
			found = true
		}
		return nil
	}); err != nil {
		return AggregateEvidence{}, false, fmt.Errorf("revoke: load terminal artifact: %w", err)
	}
	return out, found, nil
}

// terminalEventPayload is the AN-2 terminal event body: the signed aggregate artifact
// plus the directive identity, so the terminal fact + its offline-verifiable proof are
// replayable from the ledger alone.
type terminalEventPayload struct {
	DirectiveID string            `json:"directive_id"`
	Aggregate   AggregateEvidence `json:"aggregate"`
}

// LoadTerminalArtifact loads the SIGNED aggregate evidence artifact recorded for a
// directive's terminal event, encoded for offline verification (EncodeAggregate), by
// deterministic replay of the AN-2 log. found=false means the directive has not reached
// the terminal revoked-with-evidence state yet (no terminal event exists), so its
// aggregate artifact is not available. It is a PURE READ — no flip, no key op — so the
// control-plane API surface (ee/agentid/api RevocationEvidence) and operators can serve
// the published artifact a relying party verifies with VerifyAggregateOffline WITHOUT
// standing up a TerminalTransition (which requires a signer). It reuses the exact terminal
// event decode the transition writes, so the served artifact is byte-identical to the one
// the terminal transition minted.
func LoadTerminalArtifact(ctx context.Context, log EventLog, tenantID, directiveID string) (encoded []byte, found bool, err error) {
	if log == nil {
		return nil, false, fmt.Errorf("revoke: LoadTerminalArtifact requires an event log")
	}
	var artifact AggregateEvidence
	if err := log.Replay(ctx, 1, func(e eventspec.Event) error {
		if found || e.Type != TypeRevocationTerminal || e.TenantID != tenantID {
			return nil
		}
		var pl terminalEventPayload
		if err := json.Unmarshal(e.Data, &pl); err != nil {
			return nil // a malformed/foreign terminal event is skipped, not fatal
		}
		if pl.DirectiveID == directiveID {
			artifact = pl.Aggregate
			found = true
		}
		return nil
	}); err != nil {
		return nil, false, fmt.Errorf("revoke: load terminal artifact: %w", err)
	}
	if !found {
		return nil, false, nil
	}
	enc, err := EncodeAggregate(artifact)
	if err != nil {
		return nil, false, err
	}
	return enc, true, nil
}

// appendTerminalEvent appends the terminal event (with the signed aggregate artifact) to
// the AN-2 log durable-first. It is appended AFTER the terminal flip commits, so the flag
// is the idempotency guard and a retried transition re-appends nothing (the flip is
// already done).
func (tt *TerminalTransition) appendTerminalEvent(ctx context.Context, tenantID, directiveID string, artifact AggregateEvidence) error {
	data, err := json.Marshal(terminalEventPayload{DirectiveID: directiveID, Aggregate: artifact})
	if err != nil {
		return fmt.Errorf("revoke: marshal terminal event: %w", err)
	}
	_, err = tt.log.Append(ctx, eventspec.Event{
		Type:          TypeRevocationTerminal,
		TenantID:      tenantID,
		SchemaVersion: RevocationTerminalSchemaV1,
		Data:          data,
	})
	if err != nil {
		return fmt.Errorf("revoke: append terminal event: %w", err)
	}
	return nil
}

// ledgerHead returns the highest event sequence currently in the log — the ledger head
// bound into the aggregate as of the terminal revoked state (AGID-claim-33). A log with no
// events yields 0.
func (tt *TerminalTransition) ledgerHead(ctx context.Context) (uint64, error) {
	var head uint64
	if err := tt.log.Replay(ctx, 1, func(e eventspec.Event) error {
		if e.Sequence > head {
			head = e.Sequence
		}
		return nil
	}); err != nil {
		return 0, fmt.Errorf("revoke: read ledger head: %w", err)
	}
	return head, nil
}
