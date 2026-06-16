package projections_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/letsencrypt"
	"trstctl.com/trstctl/internal/ca/letsencrypt/acmefake"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
)

func leCSR(t *testing.T) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "le.acme.test", DNSNames: []string{"le.acme.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// TestLetsEncryptIssuanceIdempotentAndObservable is the acceptance for the first
// CA plugin: a real certificate is issued end-to-end through the Let's Encrypt
// (ACME) plugin, a retried issuance does not mint two certs, and the call is
// observable in the outbox.
func TestLetsEncryptIssuanceIdempotentAndObservable(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	acmeCA, err := acmefake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(acmeCA.Close)

	plugin, err := letsencrypt.NewPlugin("lets-encrypt", acmeCA.DirectoryURL())
	if err != nil {
		t.Fatal(err)
	}
	svc := ca.NewIssuanceService(plugin, orchestrator.NewIdempotency(s), orchestrator.NewOutbox(s), s)

	req := ca.IssueRequest{TenantID: tenantA, CSR: leCSR(t), DNSNames: []string{"le.acme.test"}, TTL: 24 * time.Hour}

	first, err := svc.Issue(ctx, req, "le-issue-1")
	if err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	if first.Serial == "" || first.Issuer != "lets-encrypt" {
		t.Fatalf("issued via LE = %+v", first)
	}
	// The issued certificate is real and carries the requested domain.
	info, err := certinfo.Inspect(first.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect issued cert: %v", err)
	}
	ok := false
	for _, n := range info.DNSNames {
		if n == "le.acme.test" {
			ok = true
		}
	}
	if !ok {
		t.Errorf("issued cert SANs = %v, want le.acme.test", info.DNSNames)
	}

	// A retried issuance with the same key returns the original certificate.
	second, err := svc.Issue(ctx, req, "le-issue-1")
	if err != nil {
		t.Fatalf("replay Issue: %v", err)
	}
	if second.Serial != first.Serial {
		t.Errorf("replay minted a new certificate: %s != %s", second.Serial, first.Serial)
	}

	// Exactly one ca.issue entry is observable in the outbox despite the retry.
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
