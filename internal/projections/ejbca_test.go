package projections_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/ejbca"
	"trstctl.com/trstctl/internal/ca/ejbca/ejbcafake"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

// TestEJBCAPluginRidesIssuanceRails proves the EJBCA plugin rides the platform
// rails (S4.10 acceptance): through ca.IssuanceService it is idempotent (AN-5)
// and observable in the outbox (AN-6).
func TestEJBCAPluginRidesIssuanceRails(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	srv, err := ejbcafake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	plugin := ejbca.New(ejbca.Config{
		Name: "ejbca", BaseURL: externalCATestBaseURL("ejbca"), Token: []byte(srv.Token()),
		CAName: "ManagementCA", CertificateProfile: "ENDUSER", EndEntityProfile: "User",
		Username: "trstctl", Password: []byte("enroll-secret"),
	}, ejbca.WithHTTPClient(externalCATestHTTPClient(t, srv.URL())))
	svc := ca.NewIssuanceService(plugin, orchestrator.NewIdempotency(s), orchestrator.NewOutbox(s), s)

	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "ej.acme.test", DNSNames: []string{"ej.acme.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	req := ca.IssueRequest{TenantID: tenantA, CSR: csr, DNSNames: []string{"ej.acme.test"}, TTL: 365 * 24 * time.Hour}

	first, err := svc.Issue(ctx, req, "ej-1")
	if err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	if first.Serial == "" || first.Issuer != "ejbca" {
		t.Fatalf("issued cert = %+v", first)
	}
	second, err := svc.Issue(ctx, req, "ej-1")
	if err != nil {
		t.Fatalf("replay Issue: %v", err)
	}
	if second.Serial != first.Serial {
		t.Errorf("replay minted a new certificate: %s != %s", second.Serial, first.Serial)
	}

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
