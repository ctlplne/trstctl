package letsencrypt_test

import (
	"context"
	"testing"
	"time"

	"certctl.io/certctl/internal/ca"
	"certctl.io/certctl/internal/ca/letsencrypt"
	"certctl.io/certctl/internal/ca/letsencrypt/acmefake"
	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/crypto/certinfo"
)

func buildCSR(t *testing.T, cn string, dnsNames []string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: dnsNames}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// TestPluginIssuesRealCertEndToEnd is the acceptance: a real certificate is
// issued end-to-end through the (ACME / Let's Encrypt) plugin.
func TestPluginIssuesRealCertEndToEnd(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	p, err := letsencrypt.NewPlugin("lets-encrypt", srv.DirectoryURL())
	if err != nil {
		t.Fatalf("NewPlugin: %v", err)
	}
	if p.Name() != "lets-encrypt" {
		t.Errorf("Name = %q", p.Name())
	}

	csr := buildCSR(t, "svc.acme.test", []string{"svc.acme.test"})
	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: csr, DNSNames: []string{"svc.acme.test"}, TTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cert.Serial == "" || len(cert.CertificatePEM) == 0 || cert.Issuer != "lets-encrypt" {
		t.Fatalf("issued certificate = %+v", cert)
	}

	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect issued cert: %v", err)
	}
	found := false
	for _, n := range info.DNSNames {
		if n == "svc.acme.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued cert SANs = %v, want svc.acme.test", info.DNSNames)
	}
	if !info.NotAfter.After(time.Now()) {
		t.Errorf("issued cert already expired: %s", info.NotAfter)
	}
	if info.SerialNumber != cert.Serial {
		t.Errorf("serial mismatch: cert %s vs result %s", info.SerialNumber, cert.Serial)
	}
}
