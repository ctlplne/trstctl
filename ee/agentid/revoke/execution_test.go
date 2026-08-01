// SPDX-License-Identifier: LicenseRef-trstctl-EE

package revoke_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/ee/agentid/revoke"
	"trstctl.com/trstctl/internal/orchestrator"
)

// TestRevoke_JobIdempotentAtLeastOnce: a job carries an AN-5 idempotency key and
// executes with at-least-once delivery and AT MOST ONE recorded effect per key.
// Replaying the same job N times records exactly one effect; a crash-resume mid-cascade
// (the worker dies after some jobs, another resumes) leaves no duplicate and no lost
// effect (AGID-claims 16/21 / INV-A8).
func TestRevoke_JobIdempotentAtLeastOnce(t *testing.T) {
	h := newHarness(t, "revoke_idempotent")
	ctx := context.Background()
	c := h.cascade(t)
	ex := h.executor(t)

	h.seedChainCredential(t, tenantA, "c1", "subj", "child", "subj", "cred-1")
	h.seedChainCredential(t, tenantA, "c2", "subj", "child2", "subj", "cred-2")

	res, err := c.EnqueueDirective(ctx, revoke.Directive{TenantID: tenantA, Subject: "subj", Reason: revoke.ReasonCompromise})
	if err != nil {
		t.Fatalf("EnqueueDirective: %v", err)
	}
	if len(res.Descendants) != 2 {
		t.Fatalf("expected 2 descendants, got %v", res.Descendants)
	}

	// Directly replay ONE job N times by handing the executor the same Message. Every
	// replay must record AT MOST ONE effect for that key.
	cred1 := credID("cred-1")
	key1 := revoke.JobIdempotencyKey(res.DirectiveID, cred1)
	body, err := revoke.BuildJobPayloadForTest(tenantA, res.DirectiveID, cred1, revoke.ReasonCompromise, true)
	if err != nil {
		t.Fatalf("build job payload: %v", err)
	}
	msg := orchestrator.Message{TenantID: tenantA, Destination: revoke.DestinationRevocationJob, IdempotencyKey: key1, Payload: body}
	for i := 0; i < 5; i++ {
		if err := ex.Execute(ctx, msg); err != nil {
			t.Fatalf("execute replay %d: %v", i, err)
		}
	}
	if n, err := effectCount(ctx, h, res.DirectiveID); err != nil {
		t.Fatalf("count effects after replays: %v", err)
	} else if n != 1 {
		t.Fatalf("replaying one job 5x recorded %d effects, want exactly 1 (at-most-one per key)", n)
	}

	// Crash-resume mid-cascade: dispatch the remaining outbox jobs (job for cred-2 and a
	// possible redelivery of cred-1), simulating a fresh worker resuming after a crash.
	// The total recorded effects must be exactly the descendant count — no dup, no loss.
	drainOutbox(t, h.outbox, ex, 12)
	if n, err := effectCount(ctx, h, res.DirectiveID); err != nil {
		t.Fatalf("count effects after resume: %v", err)
	} else if n != len(res.Descendants) {
		t.Fatalf("after crash-resume recorded %d effects, want %d (one per descendant, no dup/loss)", n, len(res.Descendants))
	}

	// And every job row is now evidenced (completion_ref stamped), so the terminal gate
	// (AGID-11) can see the cascade is complete.
	jobs, err := h.repo.FetchRevocationJobs(ctx, tenantA, res.DirectiveID)
	if err != nil {
		t.Fatalf("fetch jobs: %v", err)
	}
	for _, j := range jobs {
		if len(j.CompletionRef) == 0 {
			t.Fatalf("job %q has no completion ref after execution (not evidenced)", j.IdempotencyKey)
		}
	}
}

// TestRevoke_PerJobSignedCompletionEvidence: every completed job records SIGNED
// completion evidence in the ledger — job identity, target credential, effect class,
// timestamp, executor — and the signature verifies against the recorded public key
// (§7.3 / INV-A9). This is the per-job proof AGID-11's terminal gate consumes.
func TestRevoke_PerJobSignedCompletionEvidence(t *testing.T) {
	h := newHarness(t, "revoke_evidence")
	ctx := context.Background()
	c := h.cascade(t)
	ex := h.executor(t)

	h.seedChainCredential(t, tenantA, "c1", "subj", "child", "subj", "cred-1")

	res, err := c.EnqueueDirective(ctx, revoke.Directive{TenantID: tenantA, Subject: "subj", Reason: revoke.ReasonPolicyChange})
	if err != nil {
		t.Fatalf("EnqueueDirective: %v", err)
	}
	drainOutbox(t, h.outbox, ex, 8)

	cred1 := credID("cred-1")
	key1 := revoke.JobIdempotencyKey(res.DirectiveID, cred1)
	ev, found, err := revoke.LoadEvidence(ctx, h.repo, tenantA, res.DirectiveID, key1)
	if err != nil || !found {
		t.Fatalf("load evidence: found=%v err=%v", found, err)
	}

	// The evidence names the job, the target credential, an effect class, a timestamp,
	// and the executor (the enumerated fields).
	if ev.DirectiveID != res.DirectiveID || ev.IdempotencyKey != key1 {
		t.Fatalf("evidence job identity = (%q,%q), want (%q,%q)", ev.DirectiveID, ev.IdempotencyKey, res.DirectiveID, key1)
	}
	if ev.CredentialID != cred1 {
		t.Fatalf("evidence target credential = %q, want %q", ev.CredentialID, cred1)
	}
	if ev.EffectClass == "" {
		t.Fatal("evidence has no effect class")
	}
	if ev.CompletedAt == 0 {
		t.Fatal("evidence has no completion timestamp")
	}
	if ev.Executor == "" {
		t.Fatal("evidence has no executor identity")
	}

	// The evidence is SIGNED and verifies against its embedded public key (unforgeable).
	if len(ev.Signature) == 0 || len(ev.PublicKey) == 0 {
		t.Fatal("evidence is not signed (missing signature or public key)")
	}
	if err := revoke.VerifyCompletionEvidence(ev); err != nil {
		t.Fatalf("completion evidence signature does not verify: %v", err)
	}

	// Tampering with any evidenced field breaks the signature (proves the sig binds it).
	tampered := ev
	tampered.CredentialID = "cred-tampered"
	if err := revoke.VerifyCompletionEvidence(tampered); err == nil {
		t.Fatal("tampered evidence verified; the signature does not bind the credential")
	}
}

// TestRevoke_FollowOnJobAfterWatermark: a descendant whose delegation/issuance record
// was committed AFTER the directive's determining watermark (a sub-delegation minted
// moments before the directive, sequenced after it, discovered at replay) generates a
// FOLLOW-ON job under the SAME directive (§7.2 / AGID-claim-16). The original cascade misses
// it; the follow-on pass chases it, and the late descendant gets a follow_on job +
// outbox entry — exactly once.
func TestRevoke_FollowOnJobAfterWatermark(t *testing.T) {
	h := newHarness(t, "revoke_followon")
	ctx := context.Background()
	c := h.cascade(t)

	// One descendant present BEFORE the directive.
	h.seedChainCredential(t, tenantA, "c1", "subj", "child", "subj", "cred-1")

	res, err := c.EnqueueDirective(ctx, revoke.Directive{TenantID: tenantA, Subject: "subj", Reason: revoke.ReasonCompromise})
	if err != nil {
		t.Fatalf("EnqueueDirective: %v", err)
	}
	if len(res.Descendants) != 1 {
		t.Fatalf("original determination = %v, want exactly cred-1", res.Descendants)
	}
	wm := res.Watermark

	// A LATE descendant: its records are appended to the ledger AFTER the directive
	// watermark, so the original determination could not have seen it.
	h.seedChainCredential(t, tenantA, "c2-late", "subj", "child-late", "subj", "cred-late")

	// Sanity: the late credential's issuance sequence is beyond the recorded watermark.
	lateWM, err := c.LedgerHeadForTest(ctx)
	if err != nil {
		t.Fatalf("ledger head: %v", err)
	}
	if lateWM <= wm {
		t.Fatalf("late seed did not advance the ledger head (%d <= %d)", lateWM, wm)
	}

	// The follow-on pass discovers the late descendant and enqueues a follow-on job.
	fo, err := c.GenerateFollowOn(ctx, tenantA, res.DirectiveID)
	if err != nil {
		t.Fatalf("GenerateFollowOn: %v", err)
	}
	credLate := credID("cred-late")
	if len(fo.NewJobs) != 1 || fo.NewJobs[0] != credLate {
		t.Fatalf("follow-on new jobs = %v, want exactly the late credential %q", fo.NewJobs, credLate)
	}

	// The late descendant now carries a follow_on job under the SAME directive, and the
	// already-covered original credential did not get a duplicate.
	jobs, err := h.repo.FetchRevocationJobs(ctx, tenantA, res.DirectiveID)
	if err != nil {
		t.Fatalf("fetch jobs: %v", err)
	}
	var followOnCount, cred1Count, credLateFollowOn int
	for _, j := range jobs {
		if j.CredentialID == credID("cred-1") {
			cred1Count++
		}
		if j.FollowOn {
			followOnCount++
			if j.CredentialID == credLate {
				credLateFollowOn++
			}
		}
	}
	if cred1Count != 1 {
		t.Fatalf("original credential has %d jobs, want 1 (no duplicate from follow-on)", cred1Count)
	}
	if followOnCount != 1 || credLateFollowOn != 1 {
		t.Fatalf("follow-on jobs = %d (late follow_on = %d), want exactly 1 for the late descendant", followOnCount, credLateFollowOn)
	}

	// Idempotent: a second follow-on pass adds nothing (the late descendant is covered).
	fo2, err := c.GenerateFollowOn(ctx, tenantA, res.DirectiveID)
	if err != nil {
		t.Fatalf("GenerateFollowOn (2nd): %v", err)
	}
	if len(fo2.NewJobs) != 0 {
		t.Fatalf("second follow-on pass added %v, want none (idempotent)", fo2.NewJobs)
	}

	// The follow-on job executes and records signed evidence like any other job.
	ex := h.executor(t)
	drainOutbox(t, h.outbox, ex, 12)
	key := revoke.JobIdempotencyKey(res.DirectiveID, credLate)
	if _, found, err := revoke.LoadEvidence(ctx, h.repo, tenantA, res.DirectiveID, key); err != nil || !found {
		t.Fatalf("follow-on job not evidenced: found=%v err=%v", found, err)
	}
}

// effectCount returns the number of recorded effects under a directive (tenantA).
func effectCount(ctx context.Context, h *harness, directiveID string) (int, error) {
	return h.repo.CountEffects(ctx, tenantA, directiveID)
}
