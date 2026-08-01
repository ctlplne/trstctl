// SPDX-License-Identifier: LicenseRef-trstctl-EE

package revoke_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/ee/agentid/revoke"
	"trstctl.com/trstctl/internal/crypto"
)

// TestRevoke_TerminalOnlyWhenAllJobsComplete: the subject transitions to the terminal
// revoked-with-evidence state ONLY WHEN signed completion evidence exists for EVERY
// enqueued and follow-on job; withholding one job's evidence leaves it NON-terminal, and
// supplying all makes it terminal (AGID-claim-16 terminal limb / INV-A9).
func TestRevoke_TerminalOnlyWhenAllJobsComplete(t *testing.T) {
	h := newHarness(t, "revoke_terminal_allcomplete")
	ctx := context.Background()
	c := h.cascade(t)
	ex := h.executor(t)

	// Two descendants ⇒ two jobs. Both must be evidenced for terminal.
	h.seedChainCredential(t, tenantA, "c1", "subj", "child", "subj", "cred-1")
	h.seedChainCredential(t, tenantA, "c2", "subj", "child2", "subj", "cred-2")

	res, err := c.EnqueueDirective(ctx, revoke.Directive{TenantID: tenantA, Subject: "subj", Reason: revoke.ReasonCompromise})
	if err != nil {
		t.Fatalf("EnqueueDirective: %v", err)
	}
	if len(res.Descendants) != 2 {
		t.Fatalf("expected 2 descendants, got %v", res.Descendants)
	}

	tt := h.terminal(t, 1_700_000_500)

	// Execute exactly ONE of the two jobs (withhold the other's evidence).
	cred1 := credID("cred-1")
	key1 := revoke.JobIdempotencyKey(res.DirectiveID, cred1)
	body, err := revoke.BuildJobPayloadForTest(tenantA, res.DirectiveID, cred1, revoke.ReasonCompromise, true)
	if err != nil {
		t.Fatalf("build job payload: %v", err)
	}
	if err := ex.Execute(ctx, orchMsg(tenantA, key1, body)); err != nil {
		t.Fatalf("execute one job: %v", err)
	}

	// With one job un-evidenced, the directive is NOT terminal.
	got, err := tt.Transition(ctx, tenantA, res.DirectiveID)
	if err != nil {
		t.Fatalf("Transition (partial): %v", err)
	}
	if got.Terminal {
		t.Fatalf("directive became terminal with %d of 2 jobs evidenced (missing=%v)", got.Verdict.JobCount-len(got.Verdict.Missing), got.Verdict.Missing)
	}
	if len(got.Verdict.Missing) != 1 {
		t.Fatalf("expected exactly 1 missing job, got %v", got.Verdict.Missing)
	}
	if got.Transitioned {
		t.Fatal("Transition reported a flip for a non-terminal directive")
	}
	// The directive row must still be non-terminal.
	if dir, _, _ := h.repo.FetchRevocationDirective(ctx, tenantA, res.DirectiveID); dir.Terminal {
		t.Fatal("directive row is terminal despite a missing job's evidence")
	}

	// Now execute the remaining job by draining the outbox: all jobs evidenced.
	drainOutbox(t, h.outbox, ex, 12)

	got2, err := tt.Transition(ctx, tenantA, res.DirectiveID)
	if err != nil {
		t.Fatalf("Transition (complete): %v", err)
	}
	if !got2.Terminal {
		t.Fatalf("directive is not terminal with all jobs evidenced (missing=%v)", got2.Verdict.Missing)
	}
	if !got2.Transitioned {
		t.Fatal("Transition did not report the terminal flip on first completion")
	}
	if len(got2.AggregateArtifact) == 0 {
		t.Fatal("terminal transition produced no aggregate artifact")
	}
	// The directive row is now terminal, and a distinct terminal event was appended once.
	dir, found, err := h.repo.FetchRevocationDirective(ctx, tenantA, res.DirectiveID)
	if err != nil || !found {
		t.Fatalf("fetch directive: found=%v err=%v", found, err)
	}
	if !dir.Terminal {
		t.Fatal("directive row is not terminal after full completion")
	}
	if n := h.countEvents(t, tenantA, revoke.TypeRevocationTerminal); n != 1 {
		t.Fatalf("terminal events appended = %d, want exactly 1", n)
	}

	// Idempotent: a second transition finds it already terminal, flips nothing, re-appends
	// no event, and yields the SAME aggregate artifact bytes (deterministic).
	got3, err := tt.Transition(ctx, tenantA, res.DirectiveID)
	if err != nil {
		t.Fatalf("Transition (idempotent): %v", err)
	}
	if !got3.Terminal || got3.Transitioned {
		t.Fatalf("second transition: terminal=%v transitioned=%v, want terminal=true transitioned=false", got3.Terminal, got3.Transitioned)
	}
	if string(got3.AggregateArtifact) != string(got2.AggregateArtifact) {
		t.Fatal("aggregate artifact is not deterministic across transitions")
	}
	if n := h.countEvents(t, tenantA, revoke.TypeRevocationTerminal); n != 1 {
		t.Fatalf("terminal events after idempotent re-run = %d, want still 1", n)
	}
}

// TestRevoke_TerminalStateReplayVerifiable: the terminal state is verifiable from the
// ledger/durable projection by DETERMINISTIC REPLAY — a fresh reader replaying the
// recorded jobs + per-job evidence reaches the SAME terminal verdict (AGID-claim-16 / INV-A9).
func TestRevoke_TerminalStateReplayVerifiable(t *testing.T) {
	h := newHarness(t, "revoke_terminal_replay")
	ctx := context.Background()

	h.seedChainCredential(t, tenantA, "c1", "subj", "child", "subj", "cred-1")
	h.seedChainCredential(t, tenantA, "c2", "subj", "child2", "subj", "cred-2")
	res := h.enqueueAndDrain(t, tenantA, "subj", revoke.ReasonPolicyChange)

	// First engine performs the transition.
	tt1 := h.terminal(t, 1_700_000_500)
	first, err := tt1.Transition(ctx, tenantA, res.DirectiveID)
	if err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if !first.Terminal {
		t.Fatalf("directive not terminal after full drain (missing=%v)", first.Verdict.Missing)
	}

	// A DIFFERENT engine instance (fresh state, a different aggregate signer even) replays
	// the durable projection and must reach the same terminal verdict — the verdict is a
	// pure function of the recorded jobs + recorded evidence, not of engine state.
	be := crypto.NewSoftwareBackend()
	otherSigner, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("other signer: %v", err)
	}
	tt2, err := revoke.NewTerminalTransition(h.repo, h.core, h.log, otherSigner)
	if err != nil {
		t.Fatalf("NewTerminalTransition (replay): %v", err)
	}
	verdict, err := tt2.VerifyTerminal(ctx, tenantA, res.DirectiveID)
	if err != nil {
		t.Fatalf("VerifyTerminal (replay): %v", err)
	}
	if !verdict.Terminal {
		t.Fatalf("replay verdict is non-terminal (missing=%v) — terminal state not replay-verifiable", verdict.Missing)
	}
	if verdict.JobCount != first.Verdict.JobCount {
		t.Fatalf("replay job count = %d, first = %d (not deterministic)", verdict.JobCount, first.Verdict.JobCount)
	}
	if len(verdict.Missing) != 0 {
		t.Fatalf("replay reports missing jobs %v, want none", verdict.Missing)
	}

	// Replaying the SAME state repeatedly yields identical verdicts (determinism).
	verdict2, err := tt2.VerifyTerminal(ctx, tenantA, res.DirectiveID)
	if err != nil {
		t.Fatalf("VerifyTerminal (replay 2): %v", err)
	}
	if verdict2.Terminal != verdict.Terminal || verdict2.JobCount != verdict.JobCount {
		t.Fatal("terminal verdict is not deterministic under repeated replay")
	}
}

// TestRevoke_AggregateEvidenceThirdPartyVerifiable: the signed aggregate artifact binds a
// digest of the per-job completion evidence and is THIRD-PARTY verifiable OFFLINE against
// ONLY the published per-job evidence digests — no control-plane access (AGID-claim-18 /
// INV-A9). A truncated or substituted digest set fails closed.
func TestRevoke_AggregateEvidenceThirdPartyVerifiable(t *testing.T) {
	h := newHarness(t, "revoke_aggregate_offline")
	ctx := context.Background()

	h.seedChainCredential(t, tenantA, "c1", "subj", "child", "subj", "cred-1")
	h.seedChainCredential(t, tenantA, "c2", "subj", "child2", "subj", "cred-2")
	res := h.enqueueAndDrain(t, tenantA, "subj", revoke.ReasonRootPrincipalRequest)

	tt := h.terminal(t, 1_700_000_500)
	got, err := tt.Transition(ctx, tenantA, res.DirectiveID)
	if err != nil || !got.Terminal {
		t.Fatalf("Transition: terminal=%v err=%v", got.Terminal, err)
	}

	// The auditor receives ONLY the encoded artifact + the published per-job evidence
	// digests (no store, no signer). Decode + verify offline.
	artifact, err := revoke.DecodeAggregate(got.AggregateArtifact)
	if err != nil {
		t.Fatalf("decode aggregate: %v", err)
	}
	published := got.EvidenceDigests
	if len(published) != 2 {
		t.Fatalf("expected 2 published evidence digests, got %d", len(published))
	}
	if err := revoke.VerifyAggregateOffline(artifact, published); err != nil {
		t.Fatalf("aggregate did not verify offline against the published digests: %v", err)
	}

	// Independent reconstruction: an auditor who recomputes the completion-evidence digest
	// over the published digests gets the exact bound value (the artifact is self-contained).
	if !bytesEq(revoke.CompletionEvidenceDigestOf(published), artifact.CompletionEvidenceDigest) {
		t.Fatal("recomputed completion-evidence digest does not equal the artifact binding")
	}

	// Truncated set (drop one digest) fails closed.
	if err := revoke.VerifyAggregateOffline(artifact, published[:1]); err == nil {
		t.Fatal("aggregate verified against a TRUNCATED digest set; offline verify is not fail-closed")
	}

	// Substituted digest fails closed.
	bad := [][]byte{published[0], crypto.SHA256Sum([]byte("not-a-real-evidence-digest"))}
	if err := revoke.VerifyAggregateOffline(artifact, bad); err == nil {
		t.Fatal("aggregate verified against a SUBSTITUTED digest; offline verify is not fail-closed")
	}

	// Tampering with the signed body (flip the bound subject) breaks the signature.
	tampered := artifact
	tampered.SubjectID = "someone-else"
	if err := revoke.VerifyAggregateOffline(tampered, published); err == nil {
		t.Fatal("tampered aggregate verified; the signature does not bind the body")
	}
}

// TestRevoke_AggregateArtifactBindsSubjectReasonWatermarkHead: the aggregate artifact also
// binds the SUBJECT ID, the REASON CLASS, the DIRECTIVE WATERMARK, and the LEDGER HEAD as
// of the terminal revoked state — the independent-AGID-claim-33 binding set (AGID-claim-33).
func TestRevoke_AggregateArtifactBindsSubjectReasonWatermarkHead(t *testing.T) {
	h := newHarness(t, "revoke_aggregate_claim33")
	ctx := context.Background()

	h.seedChainCredential(t, tenantA, "c1", "kill-subject", "child", "kill-subject", "cred-1")
	res := h.enqueueAndDrain(t, tenantA, "kill-subject", revoke.ReasonCompromise)

	tt := h.terminal(t, 1_700_000_500)
	got, err := tt.Transition(ctx, tenantA, res.DirectiveID)
	if err != nil || !got.Terminal {
		t.Fatalf("Transition: terminal=%v err=%v", got.Terminal, err)
	}
	artifact, err := revoke.DecodeAggregate(got.AggregateArtifact)
	if err != nil {
		t.Fatalf("decode aggregate: %v", err)
	}

	// Subject id.
	if artifact.SubjectID != "kill-subject" {
		t.Fatalf("aggregate subject = %q, want %q", artifact.SubjectID, "kill-subject")
	}
	// Reason class.
	if artifact.ReasonClass != revoke.ReasonCompromise {
		t.Fatalf("aggregate reason = %q, want %q", artifact.ReasonClass, revoke.ReasonCompromise)
	}
	// Directive watermark (the determining watermark recorded on the directive).
	if artifact.Watermark != res.Watermark {
		t.Fatalf("aggregate watermark = %d, want %d (the directive's determining watermark)", artifact.Watermark, res.Watermark)
	}
	if artifact.Watermark == 0 {
		t.Fatal("aggregate binds a zero watermark")
	}
	// Ledger head as of terminal (>= the determining watermark, since more events were
	// appended between determination and terminal — the evidence events at least).
	if artifact.LedgerHead < res.Watermark {
		t.Fatalf("aggregate ledger head %d < determining watermark %d (head must be as-of terminal)", artifact.LedgerHead, res.Watermark)
	}
	// The completion-evidence digest is bound and non-empty (AGID-claim-18 limb of the same
	// artifact).
	if len(artifact.CompletionEvidenceDigest) == 0 {
		t.Fatal("aggregate binds no completion-evidence digest")
	}

	// Each bound field is COVERED BY THE SIGNATURE: flipping any one breaks offline verify.
	for _, mut := range []struct {
		name string
		f    func(a revoke.AggregateEvidence) revoke.AggregateEvidence
	}{
		{"subject", func(a revoke.AggregateEvidence) revoke.AggregateEvidence { a.SubjectID = "x"; return a }},
		{"reason", func(a revoke.AggregateEvidence) revoke.AggregateEvidence {
			a.ReasonClass = revoke.ReasonPolicyChange
			return a
		}},
		{"watermark", func(a revoke.AggregateEvidence) revoke.AggregateEvidence {
			a.Watermark = artifact.Watermark + 1
			return a
		}},
		{"ledger_head", func(a revoke.AggregateEvidence) revoke.AggregateEvidence {
			a.LedgerHead = artifact.LedgerHead + 1
			return a
		}},
	} {
		if err := revoke.VerifyAggregateSignature(mut.f(artifact)); err == nil {
			t.Fatalf("mutating %s did not break the signature; the artifact does not bind it", mut.name)
		}
	}
}

// TestRevoke_IntervalExceedanceRecorded: the subject must transition within a
// policy-defined interval; advancing a fake clock past the interval records the exceedance
// as a DISTINCT ledger event (AGID-claim-23 / INV-A9), exactly once.
func TestRevoke_IntervalExceedanceRecorded(t *testing.T) {
	h := newHarness(t, "revoke_interval")
	ctx := context.Background()

	h.seedChainCredential(t, tenantA, "c1", "subj", "child", "subj", "cred-1")
	c := h.cascade(t)
	res, err := c.EnqueueDirective(ctx, revoke.Directive{TenantID: tenantA, Subject: "subj", Reason: revoke.ReasonCompromise})
	if err != nil {
		t.Fatalf("EnqueueDirective: %v", err)
	}

	// Directive created "now" (created_at ~ real now); the directive has NOT reached
	// terminal (its job is un-evidenced). Policy interval: 60s. Advance the fake clock far
	// past created_at + interval to force an exceedance for the still-draining directive.
	timing, found, err := h.repo.FetchDirectiveTiming(ctx, tenantA, res.DirectiveID)
	if err != nil || !found {
		t.Fatalf("fetch directive timing: found=%v err=%v", found, err)
	}
	const intervalSecs = 60
	future := timing.CreatedAt + intervalSecs + 3600 // an hour past the deadline

	// Before the deadline: no exceedance.
	within := h.intervalMonitor(t, intervalSecs, timing.CreatedAt+10)
	if r, err := within.Check(ctx, tenantA, res.DirectiveID); err != nil {
		t.Fatalf("Check (within): %v", err)
	} else if r.Exceeded {
		t.Fatalf("directive reported exceeded within the interval (elapsed=%d, interval=%d)", r.ElapsedSecs, intervalSecs)
	}
	if n := h.countEvents(t, tenantA, revoke.TypeRevocationIntervalExceeded); n != 0 {
		t.Fatalf("interval-exceeded events before the deadline = %d, want 0", n)
	}

	// Past the deadline: exceedance recorded as a distinct ledger event.
	past := h.intervalMonitor(t, intervalSecs, future)
	r, err := past.Check(ctx, tenantA, res.DirectiveID)
	if err != nil {
		t.Fatalf("Check (past): %v", err)
	}
	if !r.Exceeded {
		t.Fatalf("directive not reported exceeded past the deadline (elapsed=%d, interval=%d)", r.ElapsedSecs, intervalSecs)
	}
	if !r.Recorded {
		t.Fatal("exceedance not recorded on first past-deadline check")
	}
	if n := h.countEvents(t, tenantA, revoke.TypeRevocationIntervalExceeded); n != 1 {
		t.Fatalf("interval-exceeded events after the deadline = %d, want exactly 1 (distinct event)", n)
	}

	// Idempotent: a second past-deadline check does NOT append a duplicate exceedance.
	r2, err := past.Check(ctx, tenantA, res.DirectiveID)
	if err != nil {
		t.Fatalf("Check (past, 2nd): %v", err)
	}
	if !r2.Exceeded || r2.Recorded {
		t.Fatalf("second check: exceeded=%v recorded=%v, want exceeded=true recorded=false (no duplicate)", r2.Exceeded, r2.Recorded)
	}
	if n := h.countEvents(t, tenantA, revoke.TypeRevocationIntervalExceeded); n != 1 {
		t.Fatalf("interval-exceeded events after a repeat check = %d, want still 1", n)
	}
}

// TestRevoke_IncompleteJobsQuery: the projection exposes a query returning exactly the
// jobs for which signed completion evidence has NOT been recorded (AGID-claim-22). An
// incomplete cascade surfaces exactly the missing-evidence jobs; a complete one surfaces
// none.
func TestRevoke_IncompleteJobsQuery(t *testing.T) {
	h := newHarness(t, "revoke_incomplete")
	ctx := context.Background()
	c := h.cascade(t)
	ex := h.executor(t)

	h.seedChainCredential(t, tenantA, "c1", "subj", "child", "subj", "cred-1")
	h.seedChainCredential(t, tenantA, "c2", "subj", "child2", "subj", "cred-2")
	h.seedChainCredential(t, tenantA, "c3", "subj", "child3", "subj", "cred-3")

	res, err := c.EnqueueDirective(ctx, revoke.Directive{TenantID: tenantA, Subject: "subj", Reason: revoke.ReasonCompromise})
	if err != nil {
		t.Fatalf("EnqueueDirective: %v", err)
	}
	if len(res.Descendants) != 3 {
		t.Fatalf("expected 3 descendants, got %v", res.Descendants)
	}

	// Before any job runs, ALL three jobs are incomplete.
	incomplete, err := revoke.IncompleteJobs(ctx, h.repo, tenantA, res.DirectiveID)
	if err != nil {
		t.Fatalf("IncompleteJobs (initial): %v", err)
	}
	if len(incomplete) != 3 {
		t.Fatalf("incomplete jobs before execution = %d, want 3", len(incomplete))
	}

	// Execute exactly ONE job (cred-1). The query must then surface exactly the OTHER two.
	cred1 := credID("cred-1")
	key1 := revoke.JobIdempotencyKey(res.DirectiveID, cred1)
	body, err := revoke.BuildJobPayloadForTest(tenantA, res.DirectiveID, cred1, revoke.ReasonCompromise, true)
	if err != nil {
		t.Fatalf("build job payload: %v", err)
	}
	if err := ex.Execute(ctx, orchMsg(tenantA, key1, body)); err != nil {
		t.Fatalf("execute one job: %v", err)
	}

	incomplete, err = revoke.IncompleteJobs(ctx, h.repo, tenantA, res.DirectiveID)
	if err != nil {
		t.Fatalf("IncompleteJobs (after one): %v", err)
	}
	if len(incomplete) != 2 {
		t.Fatalf("incomplete jobs after one execution = %d, want exactly 2", len(incomplete))
	}
	// The evidenced credential must NOT appear; the two un-evidenced ones must.
	want := map[string]bool{credID("cred-2"): true, credID("cred-3"): true}
	for _, j := range incomplete {
		if j.CredentialID == cred1 {
			t.Fatalf("evidenced credential %q appears in the incomplete set", cred1)
		}
		if !want[j.CredentialID] {
			t.Fatalf("unexpected credential %q in the incomplete set", j.CredentialID)
		}
		if j.IdempotencyKey != revoke.JobIdempotencyKey(res.DirectiveID, j.CredentialID) {
			t.Fatalf("incomplete job idempotency key = %q, mismatched", j.IdempotencyKey)
		}
	}

	// Drain the rest: the incomplete set is now empty (the cascade is complete).
	drainOutbox(t, h.outbox, ex, 12)
	incomplete, err = revoke.IncompleteJobs(ctx, h.repo, tenantA, res.DirectiveID)
	if err != nil {
		t.Fatalf("IncompleteJobs (complete): %v", err)
	}
	if len(incomplete) != 0 {
		t.Fatalf("incomplete jobs after full drain = %d, want 0", len(incomplete))
	}
}

// bytesEq is a local byte comparison for the aggregate-digest assertions.
func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
