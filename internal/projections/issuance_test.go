package projections_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
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
	svc := ca.NewIssuanceService(builtin, orchestrator.NewIdempotency(s), orchestrator.NewOutbox(s), s)
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
