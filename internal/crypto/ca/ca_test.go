package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"
)

func testCSR(t *testing.T, cn string, dnsNames []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dnsNames,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestIssueFromCSRProducesChainedCert(t *testing.T) {
	auth, err := NewAuthority("trstctl Built-in CA")
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	csr := testCSR(t, "svc.acme.test", []string{"svc.acme.test", "alt.acme.test"})

	issued, err := auth.IssueFromCSR(csr, 24*time.Hour)
	if err != nil {
		t.Fatalf("IssueFromCSR: %v", err)
	}
	if issued.Serial == "" || len(issued.CertificatePEM) == 0 {
		t.Fatalf("issued = %+v, want serial + PEM", issued)
	}

	// The leaf parses, carries the CSR's subject/SANs, and verifies against the CA.
	leaf := parseLeaf(t, issued.CertificatePEM)
	if leaf.Subject.CommonName != "svc.acme.test" {
		t.Errorf("leaf subject = %q, want svc.acme.test", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 2 {
		t.Errorf("leaf DNSNames = %v, want 2", leaf.DNSNames)
	}
	caCert := parseLeaf(t, auth.CertificatePEM())
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("issued leaf does not chain to the CA: %v", err)
	}
}

func TestIssueFromCSRRejectsGarbage(t *testing.T) {
	auth, _ := NewAuthority("ca")
	if _, err := auth.IssueFromCSR([]byte("not a csr"), time.Hour); err == nil {
		t.Error("IssueFromCSR accepted a malformed CSR")
	}
}

func parseLeaf(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes) // first PEM block is the leaf
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}
