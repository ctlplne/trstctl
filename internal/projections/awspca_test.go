package projections_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/awspca"
	"trstctl.com/trstctl/internal/ca/awspca/awspcafake"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

// TestAWSPCAPluginRidesIssuanceRails proves the AWS Private CA plugin rides the
// platform rails (S4.12 acceptance): through ca.IssuanceService it is idempotent
// (AN-5) and observable in the outbox (AN-6).
func TestAWSPCAPluginRidesIssuanceRails(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	api, err := awspcafake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	plugin := awspca.New(awspca.Config{Name: "aws-private-ca", CertificateAuthorityArn: api.CAArn()}, api)
	svc := ca.NewIssuanceService(plugin, orchestrator.NewIdempotency(s), orchestrator.NewOutbox(s), s)

	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "aws.acme.test", DNSNames: []string{"aws.acme.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	req := ca.IssueRequest{TenantID: tenantA, CSR: csr, DNSNames: []string{"aws.acme.test"}, TTL: 90 * 24 * time.Hour}

	first, err := svc.Issue(ctx, req, "aws-1")
	if err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	if first.Serial == "" || first.Issuer != "aws-private-ca" {
		t.Fatalf("issued cert = %+v", first)
	}
	second, err := svc.Issue(ctx, req, "aws-1")
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
