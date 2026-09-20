// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/dependents"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func issuanceCSR(t *testing.T) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "issued.acme.test", DNSNames: []string{"issued.acme.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// TestIssuanceIsIdempotentAndObservable is the acceptance: a certificate is
// issued end-to-end through the (built-in) CA, a retried issuance does not mint
// two certs, and the call is observable in the outbox.
func TestIssuanceIsIdempotentAndObservable(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	builtin, err := ca.NewBuiltin("trstctl Built-in CA")
	if err != nil {
		t.Fatal(err)
	}
	var dependentRecords []dependents.Record
	svc := ca.NewIssuanceService(
		builtin,
		orchestrator.NewIdempotency(s),
		orchestrator.NewOutbox(s),
		s,
		ca.WithDependentRecorder(dependents.RecorderFunc(func(_ context.Context, rec dependents.Record) error {
			dependentRecords = append(dependentRecords, rec)
			return nil
		})),
	)
	csr := issuanceCSR(t)

	first, err := svc.Issue(ctx, ca.IssueRequest{TenantID: tenantA, CSR: csr, TTL: 24 * time.Hour}, "issue-1")
	if err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	if first.Serial == "" || len(first.CertificatePEM) == 0 {
		t.Fatalf("issued cert = %+v", first)
	}
	// The issued certificate is real and carries the CSR's identity.
	info, err := certinfo.Inspect(first.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect issued cert: %v", err)
	}
	if info.SerialNumber != first.Serial {
		t.Errorf("serial mismatch: cert %s vs result %s", info.SerialNumber, first.Serial)
	}

	// A retried issuance with the same key returns the original certificate — no
	// second mint.
	second, err := svc.Issue(ctx, ca.IssueRequest{TenantID: tenantA, CSR: csr, TTL: 24 * time.Hour}, "issue-1")
	if err != nil {
		t.Fatalf("replay Issue: %v", err)
	}
	if second.Serial != first.Serial {
		t.Errorf("replay minted a new certificate: %s != %s", second.Serial, first.Serial)
	}
	if len(dependentRecords) != 1 {
		t.Fatalf("dependent records = %d, want exactly 1 despite retry", len(dependentRecords))
	}
	dep := dependentRecords[0]
	if dep.TenantID != tenantA || dep.ProtectedByKeyID != builtin.Name() || dep.Kind != dependents.KindCredential || dep.DependentID != first.Serial {
		t.Fatalf("dependent record = %+v, issued cert = %+v", dep, first)
	}
	if dep.IdempotencyKey != "issue-1" {
		t.Fatalf("dependent idempotency key = %q, want issue-1", dep.IdempotencyKey)
	}

	// The issuance is observable in the outbox — exactly once, despite the retry.
	pending, err := orchestrator.NewOutbox(s).Pending(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	issues := 0
	for _, e := range pending {
		if e.Destination == "ca.issue" {
			issues++
		}
	}
	if issues != 1 {
		t.Errorf("outbox has %d ca.issue entries, want exactly 1", issues)
	}
}

func TestExternalCAIssueRedeliveryRecordsDependentOnce(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	builtin, err := ca.NewBuiltin("external-ca-1")
	if err != nil {
		t.Fatal(err)
	}
	var dependentRecords []dependents.Record
	svc := ca.NewIssuanceService(
		builtin,
		orchestrator.NewIdempotency(s),
		orchestrator.NewOutbox(s),
		s,
		ca.WithOutboxIssueWorker("external-ca-1", nil),
		ca.WithDependentRecorder(dependents.RecorderFunc(func(_ context.Context, rec dependents.Record) error {
			dependentRecords = append(dependentRecords, rec)
			return nil
		})),
	)
	payload, err := json.Marshal(ca.ExternalIssuePayload{
		AuthorityID:            "external-ca-1",
		TenantID:               tenantA,
		CSR:                    issuanceCSR(t),
		TTLNanos:               int64(24 * time.Hour),
		ProviderIdempotencyKey: ca.ProviderIdempotencyKey("external-issue-1"),
		RequestBinding:         "projection-test-external-issue-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	msg := orchestrator.Message{
		TenantID:       tenantA,
		Destination:    ca.DestinationExternalCAIssue,
		IdempotencyKey: "external-issue-1",
		Payload:        payload,
	}
	if err := svc.DeliverExternalIssue(ctx, msg); err != nil {
		t.Fatalf("first DeliverExternalIssue: %v", err)
	}
	if err := svc.DeliverExternalIssue(ctx, msg); err != nil {
		t.Fatalf("redelivered DeliverExternalIssue: %v", err)
	}
	if len(dependentRecords) != 1 {
		t.Fatalf("dependent records = %d, want exactly 1 despite redelivery", len(dependentRecords))
	}
	dep := dependentRecords[0]
	if dep.TenantID != tenantA || dep.ProtectedByKeyID != "external-ca-1" || dep.Kind != dependents.KindCredential {
		t.Fatalf("dependent record = %+v", dep)
	}
	if dep.IdempotencyKey != "external-issue-1" || dep.Source != "ca.issue" {
		t.Fatalf("dependent idempotency/source = %q/%q, want external-issue-1/ca.issue", dep.IdempotencyKey, dep.Source)
	}
}

func TestExternalCAIssuedCertificateInventoryRebuildsFromEventLog(t *testing.T) {
	const authorityID = "a1000000-0000-4000-8000-000000000001"
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	registered, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegistered("external-ca-event-tenant"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, registered); err != nil {
		t.Fatal(err)
	}
	builtin, err := ca.NewBuiltin("external-event-ca")
	if err != nil {
		t.Fatal(err)
	}
	svc := ca.NewIssuanceService(
		builtin, orchestrator.NewIdempotency(s), orchestrator.NewOutbox(s), s,
		ca.WithAuditLog(log), ca.WithOutboxIssueWorker(authorityID, nil),
	)
	payload, err := json.Marshal(ca.ExternalIssuePayload{
		AuthorityID: authorityID, TenantID: tenantA, CSR: issuanceCSR(t),
		TTLNanos: int64(24 * time.Hour), ProviderIdempotencyKey: ca.ProviderIdempotencyKey("external-event-1"),
		RequestBinding: "projection-test-external-event-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	msg := orchestrator.Message{
		TenantID: tenantA, Destination: ca.DestinationExternalCAIssue,
		IdempotencyKey: "external-event-1", Payload: payload,
	}
	if err := svc.DeliverExternalIssue(ctx, msg); err != nil {
		t.Fatal(err)
	}
	assertInventory := func(where string) {
		t.Helper()
		rows, err := s.ListCertificatesByIssuanceIdempotencyKey(ctx, tenantA, "external-event-1")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || len(rows[0].CertificateDER) == 0 || rows[0].Source != "external-ca:"+authorityID {
			t.Fatalf("%s inventory = %+v, want one event-sourced external certificate", where, rows)
		}
	}
	assertInventory("live")
	if err := projections.New(s).Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	assertInventory("rebuilt")
}
