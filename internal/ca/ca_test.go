package ca_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// buildCSR creates a PKCS#10 CSR via the crypto boundary, so this external test
// never imports crypto/* (AN-3).
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

func TestBuiltinIssuesFromCSR(t *testing.T) {
	b, err := ca.NewBuiltin("trstctl Built-in CA")
	if err != nil {
		t.Fatalf("NewBuiltin: %v", err)
	}
	if b.Name() != "trstctl Built-in CA" {
		t.Errorf("Name = %q", b.Name())
	}

	csr := buildCSR(t, "svc.acme.test", []string{"svc.acme.test"})
	cert, err := b.Issue(context.Background(), ca.IssueRequest{TenantID: "t1", CSR: csr, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cert.Serial == "" || len(cert.CertificatePEM) == 0 || cert.Issuer != "trstctl Built-in CA" {
		t.Fatalf("issued certificate = %+v", cert)
	}

	// The issued leaf carries the CSR's subject and SAN.
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
}

func TestBuiltinRejectsBadCSR(t *testing.T) {
	b, err := ca.NewBuiltin("ca")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Issue(context.Background(), ca.IssueRequest{TenantID: "t1", CSR: []byte("not a csr")}); err == nil {
		t.Error("Issue accepted a malformed CSR")
	}
}
