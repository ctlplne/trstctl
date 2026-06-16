package gcpcas_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/ca/gcpcas"
	"trstctl.com/trstctl/internal/ca/gcpcas/gcpcasfake"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func gcpcasCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: []string{cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// TestPluginIssuesEndToEnd is the acceptance: the GCP CAS plugin issues a real
// certificate against a faithful CAS API double (CreateCertificate, synchronous).
func TestPluginIssuesEndToEnd(t *testing.T) {
	api, err := gcpcasfake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	p := gcpcas.New(gcpcas.Config{Name: "gcp-cas", CaPool: api.CaPool()}, api)
	if p.Name() != "gcp-cas" {
		t.Errorf("Name = %q", p.Name())
	}
	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: gcpcasCSR(t, "svc.gcpcas.test"), DNSNames: []string{"svc.gcpcas.test"}, TTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(cert.CertificatePEM) == 0 || cert.Serial == "" || cert.Issuer != "gcp-cas" {
		t.Fatalf("issued cert = %+v", cert)
	}
	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	found := false
	for _, n := range info.DNSNames {
		if n == "svc.gcpcas.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued cert SANs = %v, want svc.gcpcas.test", info.DNSNames)
	}
	if !info.NotAfter.After(time.Now()) {
		t.Errorf("issued cert already expired: %s", info.NotAfter)
	}
}

// TestPluginPassesConformance: the GCP CAS plugin passes the shared CA-plugin
// conformance suite (S4.6).
func TestPluginPassesConformance(t *testing.T) {
	api, err := gcpcasfake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	p := gcpcas.New(gcpcas.Config{Name: "gcp-cas", CaPool: api.CaPool()}, api)
	report := catemplate.Conformance(context.Background(), p)
	if !report.OK() {
		t.Fatalf("GCP CAS plugin failed conformance: %+v", report.Checks)
	}
}

// TestRejectsUnknownCaPool: CreateCertificate against an unknown CA pool is
// surfaced as an issuance error.
func TestRejectsUnknownCaPool(t *testing.T) {
	api, err := gcpcasfake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	p := gcpcas.New(gcpcas.Config{Name: "gcp-cas", CaPool: "projects/nope/locations/us-central1/caPools/missing"}, api)
	if _, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: gcpcasCSR(t, "svc.gcpcas.test"), DNSNames: []string{"svc.gcpcas.test"}, TTL: 24 * time.Hour,
	}); err == nil {
		t.Error("Issue accepted an unknown CA pool")
	}
}
