package ejbca_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/ca/ejbca"
	"trstctl.com/trstctl/internal/ca/ejbca/ejbcafake"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func ejbcaCSR(t *testing.T, cn string) []byte {
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

func config(srv *ejbcafake.Server) ejbca.Config {
	return ejbca.Config{
		Name: "ejbca", BaseURL: srv.URL(), Token: []byte(srv.Token()),
		CAName: "ManagementCA", CertificateProfile: "ENDUSER", EndEntityProfile: "User",
		Username: "trstctl", Password: []byte("enroll-secret"),
	}
}

// TestPluginIssuesEndToEnd is the acceptance: the EJBCA plugin issues a real
// certificate against a faithful EJBCA REST test double (pkcs10enroll).
func TestPluginIssuesEndToEnd(t *testing.T) {
	srv, err := ejbcafake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	p := ejbca.New(config(srv), ejbca.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	if p.Name() != "ejbca" {
		t.Errorf("Name = %q", p.Name())
	}
	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: ejbcaCSR(t, "svc.ejbca.test"), DNSNames: []string{"svc.ejbca.test"}, TTL: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(cert.CertificatePEM) == 0 || cert.Serial == "" || cert.Issuer != "ejbca" {
		t.Fatalf("issued cert = %+v", cert)
	}
	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	found := false
	for _, n := range info.DNSNames {
		if n == "svc.ejbca.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued cert SANs = %v, want svc.ejbca.test", info.DNSNames)
	}
	if !info.NotAfter.After(time.Now()) {
		t.Errorf("issued cert already expired: %s", info.NotAfter)
	}
}

// TestPluginPassesConformance: the EJBCA plugin passes the shared CA-plugin
// conformance suite (S4.6).
func TestPluginPassesConformance(t *testing.T) {
	srv, err := ejbcafake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	p := ejbca.New(config(srv))
	report := catemplate.Conformance(context.Background(), p)
	if !report.OK() {
		t.Fatalf("EJBCA plugin failed conformance: %+v", report.Checks)
	}
}

// TestRejectsBadToken: a wrong OAuth2 bearer token is surfaced as an issuance
// error (EJBCA answers 403).
func TestRejectsBadToken(t *testing.T) {
	srv, err := ejbcafake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	cfg := config(srv)
	cfg.Token = []byte("wrong-token")
	p := ejbca.New(cfg)
	if _, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: ejbcaCSR(t, "svc.ejbca.test"), DNSNames: []string{"svc.ejbca.test"}, TTL: 24 * time.Hour,
	}); err == nil {
		t.Error("Issue accepted a bad bearer token")
	}
}
