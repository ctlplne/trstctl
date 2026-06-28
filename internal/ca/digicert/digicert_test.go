package digicert_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func digicertCSR(t *testing.T, cn string) []byte {
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

// TestPluginIssuesEndToEnd is the acceptance: the DigiCert plugin issues a real
// certificate against a faithful CertCentral test double (order → poll → download
// pem_all).
func TestPluginIssuesEndToEnd(t *testing.T) {
	srv, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	p := digicert.New("digicert", srv.URL(), []byte(srv.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	if p.Name() != "digicert" {
		t.Errorf("Name = %q", p.Name())
	}

	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: digicertCSR(t, "svc.digicert.test"), DNSNames: []string{"svc.digicert.test"}, TTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(cert.CertificatePEM) == 0 || cert.Serial == "" || cert.Issuer != "digicert" {
		t.Fatalf("issued cert = %+v", cert)
	}
	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	found := false
	for _, n := range info.DNSNames {
		if n == "svc.digicert.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued cert SANs = %v, want svc.digicert.test", info.DNSNames)
	}
	if !info.NotAfter.After(time.Now()) {
		t.Errorf("issued cert already expired: %s", info.NotAfter)
	}
}

// TestPluginPassesConformance: the DigiCert plugin passes the shared CA-plugin
// conformance suite (S4.6).
func TestPluginPassesConformance(t *testing.T) {
	srv, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	p := digicert.New("digicert", srv.URL(), []byte(srv.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	report := catemplate.Conformance(context.Background(), p)
	if !report.OK() {
		t.Fatalf("DigiCert plugin failed conformance: %+v", report.Checks)
	}
}

// TestRejectsBadAPIKey: a wrong X-DC-DEVKEY is surfaced as an issuance error (the
// CertCentral API answers 403).
func TestRejectsBadAPIKey(t *testing.T) {
	srv, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	p := digicert.New("digicert", srv.URL(), []byte("wrong-key"), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	if _, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: digicertCSR(t, "svc.digicert.test"), DNSNames: []string{"svc.digicert.test"}, TTL: 24 * time.Hour,
	}); err == nil {
		t.Error("Issue accepted a bad API key")
	}
}
