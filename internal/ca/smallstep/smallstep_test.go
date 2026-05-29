package smallstep_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"certctl.io/certctl/internal/ca"
	"certctl.io/certctl/internal/ca/catemplate"
	"certctl.io/certctl/internal/ca/smallstep"
	"certctl.io/certctl/internal/ca/smallstep/smallstepfake"
	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/crypto/certinfo"
)

func smallstepCSR(t *testing.T, cn string) []byte {
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

func config(srv *smallstepfake.Server) smallstep.Config {
	return smallstep.Config{
		Name: "smallstep", BaseURL: srv.URL(),
		ProvisionerName: srv.ProvisionerName(), ProvisionerKey: srv.ProvisionerKey(),
	}
}

// TestPluginIssuesEndToEnd is the acceptance: the Smallstep plugin issues a real
// certificate against a faithful step-ca test double (mint OTT → /1.0/sign).
func TestPluginIssuesEndToEnd(t *testing.T) {
	srv, err := smallstepfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	p := smallstep.New(config(srv), smallstep.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	if p.Name() != "smallstep" {
		t.Errorf("Name = %q", p.Name())
	}
	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: smallstepCSR(t, "svc.smallstep.test"), DNSNames: []string{"svc.smallstep.test"}, TTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(cert.CertificatePEM) == 0 || cert.Serial == "" || cert.Issuer != "smallstep" {
		t.Fatalf("issued cert = %+v", cert)
	}
	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	found := false
	for _, n := range info.DNSNames {
		if n == "svc.smallstep.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued cert SANs = %v, want svc.smallstep.test", info.DNSNames)
	}
	if !info.NotAfter.After(time.Now()) {
		t.Errorf("issued cert already expired: %s", info.NotAfter)
	}
}

// TestPluginPassesConformance: the Smallstep plugin passes the shared CA-plugin
// conformance suite (S4.6).
func TestPluginPassesConformance(t *testing.T) {
	srv, err := smallstepfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	p := smallstep.New(config(srv))
	report := catemplate.Conformance(context.Background(), p)
	if !report.OK() {
		t.Fatalf("Smallstep plugin failed conformance: %+v", report.Checks)
	}
}

// TestRejectsBadProvisionerKey: an OTT minted with the wrong provisioner key is
// rejected by step-ca (the signature does not verify), surfaced as an error.
func TestRejectsBadProvisionerKey(t *testing.T) {
	srv, err := smallstepfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	cfg := config(srv)
	cfg.ProvisionerKey = []byte("the-wrong-provisioner-secret")
	p := smallstep.New(cfg)
	if _, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: smallstepCSR(t, "svc.smallstep.test"), DNSNames: []string{"svc.smallstep.test"}, TTL: 24 * time.Hour,
	}); err == nil {
		t.Error("Issue accepted an OTT signed with the wrong provisioner key")
	}
}
