package venafi_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/venafi"
	"trstctl.com/trstctl/internal/ca/venafi/venafifake"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func venafiCSR(t *testing.T, cn string) []byte {
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

// TestPluginIssuesEndToEnd is the acceptance: the Venafi plugin requests and
// retrieves a real certificate against a TPP Web SDK test double.
func TestPluginIssuesEndToEnd(t *testing.T) {
	srv, err := venafifake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	p := venafi.New(venafi.Config{
		Name:        "venafi",
		BaseURL:     srv.URL(),
		AccessToken: []byte(srv.Token()),
		PolicyDN:    srv.PolicyDN(),
		Application: "trstctl-unit-test",
	}, venafi.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	if p.Name() != "venafi" {
		t.Errorf("Name = %q", p.Name())
	}

	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: venafiCSR(t, "svc.venafi.test"), DNSNames: []string{"svc.venafi.test"}, TTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(cert.CertificatePEM) == 0 || cert.Serial == "" || cert.Issuer != "venafi" {
		t.Fatalf("issued cert = %+v", cert)
	}
	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	found := false
	for _, n := range info.DNSNames {
		if n == "svc.venafi.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued cert SANs = %v, want svc.venafi.test", info.DNSNames)
	}
	if !info.NotAfter.After(time.Now()) {
		t.Errorf("issued cert already expired: %s", info.NotAfter)
	}
}

func TestPluginRejectsWrongToken(t *testing.T) {
	srv, err := venafifake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	p := venafi.New(venafi.Config{Name: "venafi", BaseURL: srv.URL(), AccessToken: []byte("wrong"), PolicyDN: srv.PolicyDN()}, venafi.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	_, err = p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: venafiCSR(t, "svc.venafi.test"), DNSNames: []string{"svc.venafi.test"}, TTL: 24 * time.Hour,
	})
	if err == nil {
		t.Fatal("Issue with wrong token succeeded")
	}
}
