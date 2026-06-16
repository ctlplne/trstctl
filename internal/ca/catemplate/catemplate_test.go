package catemplate_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/crypto"
	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
)

// localBackend is a conforming CA-specific seam for the tests: it signs the CSR
// with a local software authority and returns the chain. A real plugin's Backend
// would instead call its upstream CA.
type localBackend struct {
	name      string
	authority *cryptoca.Authority
}

func (b localBackend) CAName() string { return b.name }

func (b localBackend) Issue(_ context.Context, req ca.IssueRequest) ([]byte, error) {
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	issued, err := b.authority.IssueFromCSR(req.CSR, ttl)
	if err != nil {
		return nil, err
	}
	return issued.CertificatePEM, nil
}

func newLocalBackend(t *testing.T, name string) localBackend {
	t.Helper()
	authority, err := cryptoca.NewAuthority(name)
	if err != nil {
		t.Fatal(err)
	}
	return localBackend{name: name, authority: authority}
}

func testCSR(t *testing.T, cn string) []byte {
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

// TestPluginWrapsBackend: the template turns a Backend into a ca.CA, parsing the
// issued chain and labelling it with the backend's name.
func TestPluginWrapsBackend(t *testing.T) {
	p := catemplate.New(newLocalBackend(t, "wrap-ca"))
	if p.Name() != "wrap-ca" {
		t.Errorf("Name = %q, want wrap-ca", p.Name())
	}
	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "t1", CSR: testCSR(t, "wrap.test"), DNSNames: []string{"wrap.test"}, TTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(cert.CertificatePEM) == 0 || cert.Serial == "" {
		t.Fatalf("issued cert = %+v", cert)
	}
	if cert.Issuer != "wrap-ca" {
		t.Errorf("Issuer = %q, want wrap-ca", cert.Issuer)
	}
	if !cert.NotAfter.After(time.Now()) {
		t.Errorf("NotAfter = %v, want future", cert.NotAfter)
	}
}

// TestPluginRejectsEmptyCSR: the template rejects an empty CSR before calling the
// backend (a shared contract check).
func TestPluginRejectsEmptyCSR(t *testing.T) {
	p := catemplate.New(newLocalBackend(t, "ca"))
	if _, err := p.Issue(context.Background(), ca.IssueRequest{TenantID: "t1"}); err == nil {
		t.Error("Issue accepted an empty CSR")
	}
}

// erroringBackend always fails its upstream call.
type erroringBackend struct{}

func (erroringBackend) CAName() string { return "broken-ca" }
func (erroringBackend) Issue(context.Context, ca.IssueRequest) ([]byte, error) {
	return nil, errors.New("upstream unreachable")
}

// TestPluginSurfacesBackendError: the template surfaces a backend failure.
func TestPluginSurfacesBackendError(t *testing.T) {
	p := catemplate.New(erroringBackend{})
	if _, err := p.Issue(context.Background(), ca.IssueRequest{TenantID: "t1", CSR: testCSR(t, "x.test")}); err == nil {
		t.Error("Issue did not surface the backend error")
	}
}

// TestConformancePassesForConformingBackend: the shared conformance suite passes
// for a plugin that honours the contract.
func TestConformancePassesForConformingBackend(t *testing.T) {
	p := catemplate.New(newLocalBackend(t, "conforming-ca"))
	report := catemplate.Conformance(context.Background(), p)
	if !report.OK() {
		t.Fatalf("conforming plugin failed conformance: %+v", report.Checks)
	}
}

// nonCertBackend returns bytes that are not a certificate — a non-conforming CA.
type nonCertBackend struct{}

func (nonCertBackend) CAName() string { return "non-cert-ca" }
func (nonCertBackend) Issue(context.Context, ca.IssueRequest) ([]byte, error) {
	return []byte("this is not a certificate"), nil
}

// TestConformanceFailsForBrokenBackend: the suite is not vacuous — it fails a
// plugin that returns a non-certificate.
func TestConformanceFailsForBrokenBackend(t *testing.T) {
	p := catemplate.New(nonCertBackend{})
	report := catemplate.Conformance(context.Background(), p)
	if report.OK() {
		t.Error("conformance passed a plugin that issues no real certificate")
	}
}
