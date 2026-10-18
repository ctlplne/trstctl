// SPDX-License-Identifier: BUSL-1.1

package reprotect

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/decommission/depstate"
)

// Guard for VDEC-claim-6.
func TestReprotect_CredentialReissueSupersession(t *testing.T) {
	ctx := context.Background()
	job := credentialJob()
	// #nosec G101 -- NewCredentialID is public fixture metadata, not credential material (CWE-798).
	issuer := &recordingCredentialIssuer{
		replacement: CredentialReplacement{
			NewCredentialID:   "credential:new-serial-100",
			TargetID:          "target:qa-apache",
			FingerprintSHA256: "aabbcc",
		},
	}
	cutover := &recordingCredentialCutover{}
	supersessions := &recordingSupersessionRecorder{}
	sink := &recordingCompletionSink{}
	exec, err := NewCredentialReissueExecutor(issuer, cutover, supersessions, NewCompletionRecorder(sink))
	if err != nil {
		t.Fatalf("NewCredentialReissueExecutor: %v", err)
	}

	res, err := exec.Execute(ctx, CredentialReissueRequest{Job: job, SuccessorKeyID: "key://tenant-a/successor"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(issuer.requests) != 1 {
		t.Fatalf("issuer requests = %d, want 1", len(issuer.requests))
	}
	if issuer.requests[0].Job.IdempotencyKey != job.IdempotencyKey {
		t.Fatalf("issuer lost idempotency key: %#v", issuer.requests[0].Job)
	}
	if res.Replacement.OldCredentialID != job.Dependent.ID || res.Replacement.NewCredentialID != "credential:new-serial-100" {
		t.Fatalf("replacement mismatch: %#v", res.Replacement)
	}
	if len(supersessions.links) != 1 {
		t.Fatalf("supersession links = %d, want 1", len(supersessions.links))
	}
	if len(cutover.requests) != 1 {
		t.Fatalf("cutover verifications = %d, want 1", len(cutover.requests))
	}
	link := supersessions.links[0]
	if link.OldCredentialID != job.Dependent.ID || link.NewCredentialID != "credential:new-serial-100" || link.SuccessorKeyID != "key://tenant-a/successor" {
		t.Fatalf("supersession link mismatch: %#v", link)
	}
	if link.IdempotencyKey != job.IdempotencyKey {
		t.Fatalf("supersession link lost idempotency key: %#v", link)
	}
	if len(sink.events) != 1 {
		t.Fatalf("completion events = %d, want 1", len(sink.events))
	}
	event := sink.events[0]
	if event.SuccessorKeyID != "key://tenant-a/successor" {
		t.Fatalf("completion successor key = %q, want key://tenant-a/successor", event.SuccessorKeyID)
	}
	if event.CredentialSupersession == nil {
		t.Fatalf("completion event did not bind credential supersession: %#v", event)
	}
	if event.CredentialSupersession.OldCredentialID != job.Dependent.ID || event.CredentialSupersession.NewCredentialID != "credential:new-serial-100" {
		t.Fatalf("completion supersession mismatch: %#v", event.CredentialSupersession)
	}
	if !res.Completion.Recorded {
		t.Fatalf("first execution did not record completion: %#v", res.Completion)
	}

	replayed, err := exec.Execute(ctx, CredentialReissueRequest{Job: job, SuccessorKeyID: "key://tenant-a/successor"})
	if err != nil {
		t.Fatalf("Execute replay: %v", err)
	}
	if replayed.Completion.Recorded {
		t.Fatal("idempotent replay recorded a second credential completion")
	}
	if len(sink.events) != 1 {
		t.Fatalf("completion event count after replay = %d, want 1", len(sink.events))
	}
}

func TestReprotect_CredentialMintDoesNotCompleteBeforeCutover(t *testing.T) {
	issuer := &recordingCredentialIssuer{replacement: CredentialReplacement{NewCredentialID: "leaf-b", TargetID: "target:qa-apache", FingerprintSHA256: "aabbcc"}}
	supersessions := &recordingSupersessionRecorder{}
	sink := &recordingCompletionSink{}
	exec, err := NewCredentialReissueExecutor(issuer, unavailableCredentialCutover{}, supersessions, NewCompletionRecorder(sink))
	if err != nil {
		t.Fatal(err)
	}
	_, err = exec.Execute(context.Background(), CredentialReissueRequest{
		Job: credentialJob(), SuccessorKeyID: "key://tenant-a/successor",
	})
	if err == nil {
		t.Fatal("mint without a verified deployment was reported complete")
	}
	if len(supersessions.links) != 0 || len(sink.events) != 0 {
		t.Fatalf("unverified mint wrote supersession=%d completion=%d", len(supersessions.links), len(sink.events))
	}
}

func TestReprotect_CredentialRejectsMismatchedServedLeaf(t *testing.T) {
	issuer := &recordingCredentialIssuer{replacement: CredentialReplacement{NewCredentialID: "leaf-b", TargetID: "target:qa-apache", FingerprintSHA256: "aabbcc"}}
	cutover := &recordingCredentialCutover{servedFingerprint: "different"}
	supersessions := &recordingSupersessionRecorder{}
	sink := &recordingCompletionSink{}
	exec, err := NewCredentialReissueExecutor(issuer, cutover, supersessions, NewCompletionRecorder(sink))
	if err != nil {
		t.Fatal(err)
	}
	_, err = exec.Execute(context.Background(), CredentialReissueRequest{Job: credentialJob(), SuccessorKeyID: "key://tenant-a/successor"})
	if err == nil {
		t.Fatal("mismatched served leaf was accepted")
	}
	if len(supersessions.links) != 0 || len(sink.events) != 0 {
		t.Fatalf("mismatched served leaf wrote supersession=%d completion=%d", len(supersessions.links), len(sink.events))
	}
}

type recordingCredentialCutover struct {
	requests          []CredentialReissueRequest
	servedFingerprint string
}

func (v *recordingCredentialCutover) VerifyCredentialCutover(_ context.Context, req CredentialReissueRequest, replacement CredentialReplacement) (CredentialCutoverEvidence, error) {
	v.requests = append(v.requests, req)
	served := v.servedFingerprint
	if served == "" {
		served = replacement.FingerprintSHA256
	}
	return CredentialCutoverEvidence{
		TenantID: req.Job.TenantID, JobID: req.Job.ID,
		OldCredentialID: replacement.OldCredentialID, NewCredentialID: replacement.NewCredentialID,
		SuccessorKeyID: replacement.SuccessorKeyID, TargetID: replacement.TargetID,
		ExpectedFingerprintSHA256: replacement.FingerprintSHA256, ServedFingerprintSHA256: served,
		DeploymentReceiptID: "receipt:qa-apache", IndependentReadbackID: "probe:qa-apache",
	}, nil
}

type recordingCredentialIssuer struct {
	replacement CredentialReplacement
	requests    []CredentialIssueRequest
}

func (i *recordingCredentialIssuer) IssueReplacementCredential(_ context.Context, req CredentialIssueRequest) (CredentialReplacement, error) {
	i.requests = append(i.requests, req)
	return i.replacement, nil
}

type recordingSupersessionRecorder struct {
	links []CredentialSupersession
}

func (r *recordingSupersessionRecorder) RecordCredentialSupersession(_ context.Context, link CredentialSupersession) error {
	r.links = append(r.links, link)
	return nil
}

func credentialJob() Job {
	return Job{
		ID:             "job-credential",
		TenantID:       "tenant-a",
		KeyID:          "key://tenant-a/root",
		LedgerPosition: 11,
		Kind:           JobKindReIssue,
		Dependent:      depstate.Dependent{Class: depstate.DependentCredential, ID: "credential:old-serial-99"},
		IdempotencyKey: "idem-credential",
	}
}
