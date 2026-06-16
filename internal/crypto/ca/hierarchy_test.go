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

// leafCSR builds a PKCS#10 CSR for the given common name and DNS SANs.
func leafCSR(t *testing.T, cn string, dnsNames []string) []byte {
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

func leafFromPEM(t *testing.T, chainPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(chainPEM)
	if block == nil {
		t.Fatal("no PEM block in chain")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestRootAndIntermediateChainVerifies builds a root → intermediate hierarchy and
// confirms an end-entity issued by the intermediate verifies up to the root.
func TestRootAndIntermediateChainVerifies(t *testing.T) {
	root, err := NewRoot(CASpec{CommonName: "trstctl Test Root", MaxPathLen: 1, TTL: 10 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewRoot: %v", err)
	}
	inter, err := root.CreateIntermediate(CASpec{CommonName: "trstctl Test Intermediate", TTL: 5 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateIntermediate: %v", err)
	}

	issued, err := inter.IssueLeaf(leafCSR(t, "svc.internal", []string{"svc.internal"}), 90*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}

	// The issued chain must verify: leaf -> intermediate -> root.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root.CertificatePEM()) {
		t.Fatal("could not add root to pool")
	}
	inters := x509.NewCertPool()
	if !inters.AppendCertsFromPEM(inter.CertificatePEM()) {
		t.Fatal("could not add intermediate to pool")
	}
	leaf := leafFromPEM(t, issued.CertificatePEM)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("issued leaf does not chain to the root: %v", err)
	}
}

// TestIssueLeafEnforcesNameConstraints rejects an end-entity whose SAN is outside
// the CA's permitted DNS name constraints.
func TestIssueLeafEnforcesNameConstraints(t *testing.T) {
	root, err := NewRoot(CASpec{CommonName: "Constrained Root", PermittedDNSDomains: []string{"acme.test"}, TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.IssueLeaf(leafCSR(t, "ok", []string{"ok.acme.test"}), time.Hour); err != nil {
		t.Errorf("a permitted SAN was rejected: %v", err)
	}
	if _, err := root.IssueLeaf(leafCSR(t, "evil", []string{"evil.example.com"}), time.Hour); err == nil {
		t.Error("a SAN outside the name constraints was issued")
	}
}

// TestPathLengthExhaustionRejected: a CA whose remaining path length is zero
// cannot create a further intermediate.
func TestPathLengthExhaustionRejected(t *testing.T) {
	root, err := NewRoot(CASpec{CommonName: "PathLen Root", MaxPathLen: 1, TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	inter, err := root.CreateIntermediate(CASpec{CommonName: "PathLen Intermediate", TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("first intermediate: %v", err)
	}
	if inter.MaxPathLen() != 0 {
		t.Errorf("intermediate remaining path length = %d, want 0", inter.MaxPathLen())
	}
	if _, err := inter.CreateIntermediate(CASpec{CommonName: "Too Deep", TTL: time.Hour}); err == nil {
		t.Error("created an intermediate past the path-length constraint")
	}
}

// TestCrossSign signs another root's certificate with this CA, producing a
// cross-certificate that verifies under this CA's signature.
func TestCrossSign(t *testing.T) {
	a, err := NewRoot(CASpec{CommonName: "Root A", TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewRoot(CASpec{CommonName: "Root B", TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	crossPEM, err := a.CrossSign(b.CertificateDER())
	if err != nil {
		t.Fatalf("CrossSign: %v", err)
	}
	block, _ := pem.Decode(crossPEM)
	if block == nil {
		t.Fatal("cross cert has no PEM block")
	}
	cross, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// The cross-certificate carries B's subject but is signed by A.
	if cross.Subject.CommonName != "Root B" {
		t.Errorf("cross cert subject = %q, want Root B", cross.Subject.CommonName)
	}
	aCert := leafFromPEM(t, a.CertificatePEM())
	if err := cross.CheckSignatureFrom(aCert); err != nil {
		t.Errorf("cross cert is not signed by Root A: %v", err)
	}
}

// TestCrossSignCarriesConstraints is the PKIGOV-004 regression: a cross-cert is a
// fully privileged CA cert, so the matching pathLen and name constraints must be
// carried/clamped onto it — never left unconstrained. This FAILS pre-fix (the old
// CrossSign emitted IsCA:true with no MaxPathLen and no PermittedDNSDomains).
func TestCrossSignCarriesConstraints(t *testing.T) {
	signer, err := NewRoot(CASpec{
		CommonName:          "Cross Signer Root",
		PermittedDNSDomains: []string{"example.com"},
		MaxPathLen:          1, // may delegate one more level of CA
		TTL:                 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Target CA: constrained to example.com, may itself sign sub-CAs (pathLen 2).
	target, err := NewRoot(CASpec{
		CommonName:          "Cross Target Root",
		PermittedDNSDomains: []string{"example.com"},
		MaxPathLen:          2,
		TTL:                 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	crossPEM, err := signer.CrossSign(target.CertificateDER())
	if err != nil {
		t.Fatalf("CrossSign: %v", err)
	}
	cross := leafFromPEM(t, crossPEM)

	// (1) Name constraints must be present and marked critical.
	if len(cross.PermittedDNSDomains) == 0 {
		t.Fatal("cross-cert carries no dNSName name constraints; an unconstrained CA was minted")
	}
	if !cross.PermittedDNSDomainsCritical {
		t.Error("cross-cert name constraints are not critical")
	}
	foundExample := false
	for _, d := range cross.PermittedDNSDomains {
		if d == "example.com" {
			foundExample = true
		}
	}
	if !foundExample {
		t.Errorf("cross-cert permitted domains %v do not include the intersected example.com", cross.PermittedDNSDomains)
	}

	// (2) Path length must be present and clamped to the signer's lane: the signer
	// holds depth 1, so a CA it cross-signs may carry at most depth 1 — even though
	// the target asked for depth 2.
	if !cross.BasicConstraintsValid || !cross.IsCA {
		t.Fatal("cross-cert is not a valid CA certificate")
	}
	pathLen, has := crossPathLen(cross)
	if !has {
		t.Fatal("cross-cert has no path-length basic constraint; it is unconstrained")
	}
	if pathLen != 1 {
		t.Errorf("cross-cert pathLen = %d, want 1 (clamped to signer depth, below the target's requested 2)", pathLen)
	}
}

// TestCrossSignRejectsUnconstrainedExpansion proves the cross-cert constrains a
// target that was itself unconstrained: an out-of-lane SAN issued beneath the
// cross-signed chain fails X.509 verification against the signer as trust anchor.
func TestCrossSignRejectsUnconstrainedExpansion(t *testing.T) {
	// Signer is constrained to example.com.
	signer, err := NewRoot(CASpec{
		CommonName:          "Lane Signer",
		PermittedDNSDomains: []string{"example.com"},
		MaxPathLen:          2,
		TTL:                 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Target is UNCONSTRAINED (no name constraints) and can issue leaves directly.
	target, err := NewRoot(CASpec{
		CommonName: "Wide Target",
		MaxPathLen: 0,
		TTL:        365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	crossPEM, err := signer.CrossSign(target.CertificateDER())
	if err != nil {
		t.Fatalf("CrossSign: %v", err)
	}
	cross := leafFromPEM(t, crossPEM)
	// The cross-cert must have inherited the signer's example.com constraint even
	// though the target had none.
	if len(cross.PermittedDNSDomains) == 0 {
		t.Fatal("cross-cert of an unconstrained target is itself unconstrained (PKIGOV-004 not fixed)")
	}

	// Issue a leaf from the target for a name OUTSIDE the signer's lane.
	issued, err := target.IssueLeaf(leafCSR(t, "out", []string{"out.evil.test"}), 90*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	leaf := leafFromPEM(t, issued.CertificatePEM)

	// Build a pool: trust anchor = signer; intermediate = the cross-cert (target's
	// key, signed by signer). The out-of-lane leaf must FAIL verification because
	// the cross-cert's name constraints forbid out.evil.test.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(signer.CertificatePEM()) {
		t.Fatal("add signer to roots")
	}
	inters := x509.NewCertPool()
	inters.AddCert(cross)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err == nil {
		t.Error("an out-of-lane SAN verified through the cross-cert; name constraints were not enforced")
	}
}

// TestCrossSignRejectsNonCA: cross-signing only makes sense for a CA certificate.
func TestCrossSignRejectsNonCA(t *testing.T) {
	signer, err := NewRoot(CASpec{CommonName: "Signer", TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := signer.IssueLeaf(leafCSR(t, "leaf", []string{"leaf.test"}), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := leafFromPEM(t, issued.CertificatePEM)
	if _, err := signer.CrossSign(leaf.Raw); err == nil {
		t.Error("cross-signed a non-CA leaf certificate; want rejection")
	}
}
