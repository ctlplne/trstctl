package sectigo_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"certctl.io/certctl/internal/ca"
	"certctl.io/certctl/internal/ca/catemplate"
	"certctl.io/certctl/internal/ca/sectigo"
	"certctl.io/certctl/internal/ca/sectigo/sectigofake"
	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/crypto/certinfo"
)

func sectigoCSR(t *testing.T, cn string) []byte {
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

func config(srv *sectigofake.Server) sectigo.Config {
	return sectigo.Config{
		Name: "sectigo", BaseURL: srv.URL(),
		Login: srv.Login(), Password: srv.Password(), CustomerURI: srv.CustomerURI(),
		OrgID: 1234, CertType: 224,
	}
}

// TestPluginIssuesEndToEnd is the acceptance: the Sectigo plugin issues a real
// certificate against a faithful SCM test double (enroll → collect pem).
func TestPluginIssuesEndToEnd(t *testing.T) {
	srv, err := sectigofake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	p := sectigo.New(config(srv), sectigo.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	if p.Name() != "sectigo" {
		t.Errorf("Name = %q", p.Name())
	}
	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: sectigoCSR(t, "svc.sectigo.test"), DNSNames: []string{"svc.sectigo.test"}, TTL: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(cert.CertificatePEM) == 0 || cert.Serial == "" || cert.Issuer != "sectigo" {
		t.Fatalf("issued cert = %+v", cert)
	}
	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	found := false
	for _, n := range info.DNSNames {
		if n == "svc.sectigo.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued cert SANs = %v, want svc.sectigo.test", info.DNSNames)
	}
	if !info.NotAfter.After(time.Now()) {
		t.Errorf("issued cert already expired: %s", info.NotAfter)
	}
}

// TestPluginPassesConformance: the Sectigo plugin passes the shared CA-plugin
// conformance suite (S4.6).
func TestPluginPassesConformance(t *testing.T) {
	srv, err := sectigofake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	p := sectigo.New(config(srv))
	report := catemplate.Conformance(context.Background(), p)
	if !report.OK() {
		t.Fatalf("Sectigo plugin failed conformance: %+v", report.Checks)
	}
}

// TestPollsWhilePending: SCM issues asynchronously — collect returns -183 "being
// processed" until the cert is ready. The plugin polls and ultimately succeeds.
func TestPollsWhilePending(t *testing.T) {
	srv, err := sectigofake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	srv.SetPendingPolls(2) // first two collects report "being processed"

	p := sectigo.New(config(srv), sectigo.WithPollInterval(time.Millisecond))
	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: sectigoCSR(t, "pending.sectigo.test"), DNSNames: []string{"pending.sectigo.test"}, TTL: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue (with pending polls): %v", err)
	}
	if len(cert.CertificatePEM) == 0 {
		t.Error("no certificate after polling through pending")
	}
}

// TestRejectsBadCredentials: a wrong password is surfaced as an issuance error
// (SCM answers 401).
func TestRejectsBadCredentials(t *testing.T) {
	srv, err := sectigofake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	cfg := config(srv)
	cfg.Password = "wrong-password"
	p := sectigo.New(cfg)
	if _, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: sectigoCSR(t, "svc.sectigo.test"), DNSNames: []string{"svc.sectigo.test"}, TTL: 24 * time.Hour,
	}); err == nil {
		t.Error("Issue accepted bad credentials")
	}
}
