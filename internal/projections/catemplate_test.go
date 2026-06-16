package projections_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/example"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

// TestTemplatePluginRidesIssuanceRails proves a CA plugin built from the template
// rides the platform rails the remaining CA sprints (S4.7–S4.14) require: through
// ca.IssuanceService it is idempotent (AN-5, no double mint on retry) and
// observable in the outbox (AN-6).
func TestTemplatePluginRidesIssuanceRails(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	plugin, err := example.New("example-ca")
	if err != nil {
		t.Fatal(err)
	}
	svc := ca.NewIssuanceService(plugin, orchestrator.NewIdempotency(s), orchestrator.NewOutbox(s), s)

	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "tmpl.acme.test", DNSNames: []string{"tmpl.acme.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	req := ca.IssueRequest{TenantID: tenantA, CSR: csr, DNSNames: []string{"tmpl.acme.test"}, TTL: 24 * time.Hour}

	first, err := svc.Issue(ctx, req, "tmpl-1")
	if err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	if first.Serial == "" || first.Issuer != "example-ca" {
		t.Fatalf("issued cert = %+v", first)
	}
	second, err := svc.Issue(ctx, req, "tmpl-1")
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
