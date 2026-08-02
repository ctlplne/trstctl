// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reprotect

import (
	"context"
	"testing"

	"trstctl.com/trstctl/ee/decommission/depstate"
)

// Guard for VDEC-claim-6.
func TestReprotect_CredentialReissueSupersession(t *testing.T) {
	ctx := context.Background()
	job := credentialJob()
	issuer := &recordingCredentialIssuer{
		replacement: CredentialReplacement{
			NewCredentialID: "credential:new-serial-100",
		},
	}
	supersessions := &recordingSupersessionRecorder{}
	sink := &recordingCompletionSink{}
	exec, err := NewCredentialReissueExecutor(issuer, supersessions, NewCompletionRecorder(sink))
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
