package profilelint_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca/profilelint"
	"trstctl.com/trstctl/internal/crypto"
)

// issueProfiledLeaf mints a real end-entity leaf through the served issuing path
// (SignLeafFromCSRWithProfile) carrying the full RFC 5280 / CA-Browser-Forum profile
// — CDP, AIA OCSP + CA-issuers, a policy OID, and a SAN. This is the shape the
// served binary issues (PKIGOV-001), so linting it exercises the real artifact, not
// a hand-rolled fixture. All crypto stays behind the AN-3 boundary.
func issueProfiledLeaf(t *testing.T, cn string, ttl time.Duration) []byte {
	t.Helper()
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Profile Lint Issuing CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: []string{cn}}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csr, ttl, crypto.LeafProfile{
		CRLDistributionPoints: []string{"http://crl.trstctl.test/issuing.crl"},
		OCSPServers:           []string{"http://ocsp.trstctl.test"},
		IssuingCertificateURL: []string{"http://pki.trstctl.test/issuing.crt"},
		CertificatePolicyOIDs: []string{"1.3.6.1.4.1.59551.1.1"},
	})
	if err != nil {
		t.Fatalf("SignLeafFromCSRWithProfile: %v", err)
	}
	return leaf
}

// TestProfileLintPassesConformantServedLeaf is the PKIGOV-009 positive acceptance:
// the structural RFC 5280 linter must NOT flag a conformant served leaf (the exact
// profile shape the binary issues). A false positive here would block real issuance.
func TestProfileLintPassesConformantServedLeaf(t *testing.T) {
	leaf := issueProfiledLeaf(t, "svc.example.test", 90*24*time.Hour)
	findings, err := profilelint.Lint(leaf, profilelint.Options{Leaf: true, MaxValidity: 398 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if profilelint.HasErrors(findings) {
		t.Fatalf("conformant served leaf was flagged by the profile linter: %v", profilelint.Errors(findings))
	}
}

// TestProfileLintFailsOnBrokenProfile is the PKIGOV-009 negative acceptance: the
// linter must be RED on a deliberately-broken profile. Here a CA certificate is
// linted as if it were an end-entity leaf, which a conformant leaf profile forbids:
// it asserts CA=true and carries no SAN. The linter must return error-level findings
// (e_leaf_is_ca and e_leaf_without_san), proving it would fail CI on a profile
// regression. Pre-PKIGOV-009 there was NO such linter in the suite.
func TestProfileLintFailsOnBrokenProfile(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	// A CA cert: IsCA=true, no SAN — a "leaf" with this shape is non-conformant.
	caDER, err := crypto.SelfSignedCACert(caKey, "Not A Leaf CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	findings, err := profilelint.Lint(caDER, profilelint.Options{Leaf: true})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if !profilelint.HasErrors(findings) {
		t.Fatal("profile linter did not flag a CA certificate linted as an end-entity leaf (PKIGOV-009)")
	}
	codes := map[string]bool{}
	for _, f := range profilelint.Errors(findings) {
		codes[f.Code] = true
	}
	if !codes["e_leaf_is_ca"] {
		t.Error("linter did not flag CA=true on a leaf (e_leaf_is_ca)")
	}
	if !codes["e_leaf_without_san"] {
		t.Error("linter did not flag a missing SAN on a leaf (e_leaf_without_san)")
	}
}

// TestProfileLintFlagsOverlongValidity confirms the validity-cap check is RED when a
// leaf's lifetime exceeds the profile ceiling (an over-long validity is a classic
// profile regression a public-CA linter catches).
func TestProfileLintFlagsOverlongValidity(t *testing.T) {
	leaf := issueProfiledLeaf(t, "long.example.test", 30*24*time.Hour)
	// Lint with a 1-hour ceiling: the 30-day leaf must trip e_validity_too_long.
	findings, err := profilelint.Lint(leaf, profilelint.Options{Leaf: true, MaxValidity: time.Hour})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	found := false
	for _, f := range profilelint.Errors(findings) {
		if f.Code == "e_validity_too_long" {
			found = true
		}
	}
	if !found {
		t.Errorf("linter did not flag an over-long validity; findings = %v", findings)
	}
}
