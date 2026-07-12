// SPDX-License-Identifier: MPL-2.0

package profilelint_test

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca/profilelint"
	"trstctl.com/trstctl/internal/crypto"
	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/crypto/certinfo"
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
	leaf, err := issueCSRLeaf(t, caDER, caKey, cn, []string{cn}, nil, ttl, crypto.LeafProfile{
		CRLDistributionPoints: []string{"http://crl.trstctl.test/issuing.crl"},
		OCSPServers:           []string{"http://ocsp.trstctl.test"},
		IssuingCertificateURL: []string{"http://pki.trstctl.test/issuing.crt"},
		CertificatePolicyOIDs: []string{"1.3.6.1.4.1.59551.1.1"},
	})
	if err != nil {
		t.Fatal(err)
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
	// TEST-CA-KEYUSAGE-001: the CA cert carries keyCertSign, so linting it as a
	// leaf must also flag e_leaf_asserts_cert_sign (the M11 mutation guard).
	if !codes["e_leaf_asserts_cert_sign"] {
		t.Error("linter did not flag keyCertSign on a leaf (e_leaf_asserts_cert_sign)")
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

func TestArchiveProfileLintFixturesWritesCorpus(t *testing.T) {
	dir := os.Getenv("TRSTCTL_PROFILE_LINT_FIXTURE_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	written := writeProfileLintFixtures(t, dir)
	want := []string{
		"agent-client-mtls-leaf.pem",
		"agent-server-mtls-leaf.pem",
		"issuing-ca.pem",
		"served-leaf-client-auth.pem",
		"served-leaf-full-profile.pem",
		"served-leaf-legacy-empty-profile.pem",
		"served-leaf-server-auth.pem",
		"spiffe-x509-svid.pem",
		"timestamping-leaf.pem",
	}
	if !reflect.DeepEqual(written, want) {
		t.Fatalf("fixture corpus = %v, want %v", written, want)
	}
	for _, name := range want {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if block, _ := pem.Decode(raw); block == nil || block.Type != "CERTIFICATE" {
			t.Fatalf("%s is not a PEM certificate", name)
		}
		if name == "issuing-ca.pem" {
			continue
		}
		findings, err := profilelint.Lint(raw, profilelint.Options{Leaf: true, MaxValidity: 398 * 24 * time.Hour})
		if err != nil {
			t.Fatalf("Lint %s: %v", name, err)
		}
		if profilelint.HasErrors(findings) {
			t.Fatalf("%s has structural profile lint errors: %v", name, profilelint.Errors(findings))
		}
	}
}

type profileLintFixture struct {
	name string
	der  []byte
}

func writeProfileLintFixtures(t *testing.T, dir string) []string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create fixture dir: %v", err)
	}
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Profile Corpus Issuing CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	fullProfile := crypto.LeafProfile{
		CRLDistributionPoints: []string{"http://crl.trstctl.test/issuing.crl"},
		OCSPServers:           []string{"http://ocsp.trstctl.test"},
		IssuingCertificateURL: []string{"http://pki.trstctl.test/issuing.crt"},
		CertificatePolicyOIDs: []string{"1.3.6.1.4.1.59551.1.1"},
		MaxValidity:           398 * 24 * time.Hour,
		PermittedDNSSuffixes:  []string{"fixture.test"},
	}
	fullLeaf, err := issueCSRLeaf(t, caDER, caKey, "full.fixture.test", []string{"full.fixture.test"}, nil, 90*24*time.Hour, fullProfile)
	if err != nil {
		t.Fatal(err)
	}
	legacyLeaf, err := issueCSRLeaf(t, caDER, caKey, "legacy.fixture.test", []string{"legacy.fixture.test"}, nil, 30*24*time.Hour, crypto.LeafProfile{})
	if err != nil {
		t.Fatal(err)
	}
	serverAuthLeaf, err := issueCSRLeaf(t, caDER, caKey, "server.fixture.test", []string{"server.fixture.test"}, []string{"serverAuth"}, 24*time.Hour, crypto.LeafProfile{AllowedExtKeyUsage: []string{"serverAuth"}})
	if err != nil {
		t.Fatal(err)
	}
	clientAuthLeaf, err := issueCSRLeaf(t, caDER, caKey, "client.fixture.test", []string{"client.fixture.test"}, []string{"clientAuth"}, 24*time.Hour, crypto.LeafProfile{AllowedExtKeyUsage: []string{"clientAuth"}})
	if err != nil {
		t.Fatal(err)
	}
	tsaLeaf, err := issueTimestampingLeaf(t, caDER, caKey)
	if err != nil {
		t.Fatal(err)
	}
	agentServerLeaf, err := issueAgentServerLeaf(t, caDER, caKey)
	if err != nil {
		t.Fatal(err)
	}
	agentClientLeaf, err := issueAgentClientLeaf(t, caDER, caKey)
	if err != nil {
		t.Fatal(err)
	}
	svidLeaf, err := issueSVIDLeaf(t, caDER, caKey)
	if err != nil {
		t.Fatal(err)
	}

	fixtures := []profileLintFixture{
		{name: "agent-client-mtls-leaf.pem", der: agentClientLeaf},
		{name: "agent-server-mtls-leaf.pem", der: agentServerLeaf},
		{name: "issuing-ca.pem", der: caDER},
		{name: "served-leaf-client-auth.pem", der: clientAuthLeaf},
		{name: "served-leaf-full-profile.pem", der: fullLeaf},
		{name: "served-leaf-legacy-empty-profile.pem", der: legacyLeaf},
		{name: "served-leaf-server-auth.pem", der: serverAuthLeaf},
		{name: "spiffe-x509-svid.pem", der: svidLeaf},
		{name: "timestamping-leaf.pem", der: tsaLeaf},
	}

	names := make([]string, 0, len(fixtures))
	for _, fixture := range fixtures {
		if err := os.WriteFile(filepath.Join(dir, fixture.name), pemCert(fixture.der), 0o644); err != nil {
			t.Fatalf("write %s: %v", fixture.name, err)
		}
		names = append(names, fixture.name)
	}
	manifest := []byte("trstctl generated PKI profile corpus\n")
	for _, name := range names {
		role := "leaf"
		if name == "issuing-ca.pem" {
			role = "ca"
		}
		manifest = append(manifest, fmt.Sprintf("%s %s\n", role, name)...)
	}
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST.txt"), manifest, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return names
}

func issueCSRLeaf(t *testing.T, caDER []byte, caKey crypto.DigestSigner, cn string, dns, requestedEKUs []string, ttl time.Duration, prof crypto.LeafProfile) ([]byte, error) {
	t.Helper()
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, err
	}
	t.Cleanup(leafKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: dns, RequestedEKUs: requestedEKUs}, leafKey)
	if err != nil {
		return nil, err
	}
	leaf, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csr, ttl, prof)
	if err != nil {
		return nil, fmt.Errorf("SignLeafFromCSRWithProfile: %w", err)
	}
	return leaf, nil
}

func issueTimestampingLeaf(t *testing.T, caDER []byte, caKey crypto.DigestSigner) ([]byte, error) {
	t.Helper()
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, err
	}
	t.Cleanup(leafKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName:    "tsa.fixture.test",
		DNSNames:      []string{"tsa.fixture.test"},
		RequestedEKUs: []string{"timeStamping"},
	}, leafKey)
	if err != nil {
		return nil, err
	}
	leaf, err := crypto.SignTimestampingCertFromCSR(caDER, caKey, csr, 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("SignTimestampingCertFromCSR: %w", err)
	}
	return leaf, nil
}

func issueAgentServerLeaf(t *testing.T, caDER []byte, caKey crypto.DigestSigner) ([]byte, error) {
	t.Helper()
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, err
	}
	t.Cleanup(leafKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "agent-server.fixture.test"}, leafKey)
	if err != nil {
		return nil, err
	}
	chain, err := crypto.SignServerCertFromCSR(caDER, caKey, csr, []string{"agent-server.fixture.test"}, 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("SignServerCertFromCSR: %w", err)
	}
	return firstPEMCert(chain)
}

func issueAgentClientLeaf(t *testing.T, caDER []byte, caKey crypto.DigestSigner) ([]byte, error) {
	t.Helper()
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, err
	}
	t.Cleanup(leafKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "agent-client.fixture.test"}, leafKey)
	if err != nil {
		return nil, err
	}
	chain, err := crypto.SignAgentClientCSR(caDER, caKey, csr, "spiffe://trstctl.example/tenant/profile-lint/agent/fixture", 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("SignAgentClientCSR: %w", err)
	}
	return firstPEMCert(chain)
}

func issueSVIDLeaf(t *testing.T, caDER []byte, caKey crypto.DigestSigner) ([]byte, error) {
	t.Helper()
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, err
	}
	t.Cleanup(leafKey.Destroy)
	leaf, err := crypto.SignSVID(caDER, caKey, leafKey.Public().DER, "spiffe://fixture.test/ns/default/sa/web", 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("SignSVID: %w", err)
	}
	return leaf, nil
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func firstPEMCert(chain []byte) ([]byte, error) {
	block, _ := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("chain does not start with a certificate PEM block")
	}
	return block.Bytes, nil
}

// issueHierarchyLeaf mints a real end-entity leaf through the hierarchy/reference
// CA path (cryptoca.CA.IssueLeafWithProfile, the machinery Manager.IssueEndEntity
// serves), carrying the full served certificate-profile shape. This is the exact
// artifact a hierarchy-issued leaf is, so linting it exercises the real path, not a
// hand-rolled fixture. All crypto stays behind the AN-3 boundary.
func issueHierarchyLeaf(t *testing.T, prof crypto.LeafProfile, cn string, dns []string, ttl time.Duration) []byte {
	t.Helper()
	root, err := cryptoca.NewRoot(cryptoca.CASpec{
		CommonName:          "Hierarchy Profile Root CA",
		PermittedDNSDomains: []string{"profile.test"},
		MaxPathLen:          1,
		TTL:                 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewRoot: %v", err)
	}
	t.Cleanup(root.Destroy)
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: dns}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := root.IssueLeafWithProfile(csr, ttl, prof)
	if err != nil {
		t.Fatalf("IssueLeafWithProfile: %v", err)
	}
	leaf, err := firstPEMCert(issued.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// TestHierarchyIssueEndEntityProfileLint is the PKIGOV-002 acceptance: a
// hierarchy/reference-issued leaf must carry the SAME served certificate-profile
// shape as broker issuance — SKI, AKI, CRL distribution points, AIA (OCSP +
// CA-issuers), and certificatePolicies — so the structural RFC 5280 linter passes
// AND every served-shape pointer is present. Before PKIGOV-002 the hierarchy leaf
// template set none of SKI/AKI/CRLDP/AIA, so this test was RED (e_ski_absent,
// e_aki_absent, plus the missing-pointer assertions); routing IssueEndEntity
// through SignLeafFromCSRWithProfile makes it GREEN.
func TestHierarchyIssueEndEntityProfileLint(t *testing.T) {
	prof := crypto.LeafProfile{
		CRLDistributionPoints: []string{"http://crl.profile.test/issuing.crl"},
		OCSPServers:           []string{"http://ocsp.profile.test"},
		IssuingCertificateURL: []string{"http://pki.profile.test/issuing.crt"},
		CertificatePolicyOIDs: []string{"1.3.6.1.4.1.59551.1.1"},
		MaxValidity:           398 * 24 * time.Hour,
	}
	leaf := issueHierarchyLeaf(t, prof, "svc.profile.test", []string{"svc.profile.test"}, 90*24*time.Hour)

	findings, err := profilelint.Lint(leaf, profilelint.Options{Leaf: true, MaxValidity: 398 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if profilelint.HasErrors(findings) {
		t.Fatalf("hierarchy-issued leaf was flagged by the profile linter (PKIGOV-002): %v", profilelint.Errors(findings))
	}

	info, err := certinfo.Inspect(leaf)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if info.SubjectKeyID == "" {
		t.Error("hierarchy leaf is missing the Subject Key Identifier (PKIGOV-002)")
	}
	if info.AuthorityKeyID == "" {
		t.Error("hierarchy leaf is missing the Authority Key Identifier (PKIGOV-002)")
	}
	if len(info.CRLDistributionPoints) == 0 {
		t.Error("hierarchy leaf is missing the CRL distribution points (PKIGOV-002)")
	}
	if len(info.OCSPServers) == 0 {
		t.Error("hierarchy leaf is missing the OCSP AIA (PKIGOV-002)")
	}
	if len(info.IssuingCertificateURL) == 0 {
		t.Error("hierarchy leaf is missing the CA-issuers AIA (PKIGOV-002)")
	}
}

// TestHierarchyIssueEndEntityProfileLintNegative is the PKIGOV-002 negative
// fixture: the linter and the served profile machinery must be RED on a
// non-conformant hierarchy issuance. A leaf whose validity exceeds the bound
// profile ceiling is rejected before signing (no out-of-profile leaf is minted),
// and the hierarchy CA certificate linted as if it were an end-entity leaf trips
// the structural linter (IsCA=true, no SAN). Both prove the gate fails on a
// regression rather than silently passing.
func TestHierarchyIssueEndEntityProfileLintNegative(t *testing.T) {
	// (a) An over-long request is refused before any certificate is signed.
	root, err := cryptoca.NewRoot(cryptoca.CASpec{CommonName: "Hierarchy Negative Root CA", TTL: 10 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewRoot: %v", err)
	}
	t.Cleanup(root.Destroy)
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "too-long.test", DNSNames: []string{"too-long.test"}}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.IssueLeafWithProfile(csr, 30*24*time.Hour, crypto.LeafProfile{MaxValidity: time.Hour}); err == nil {
		t.Fatal("a request exceeding the profile validity ceiling was issued (PKIGOV-002)")
	} else if !crypto.IsLeafProfileViolation(err) {
		t.Fatalf("over-long issuance was rejected, but not as a leaf-profile violation: %v", err)
	}

	// (b) The hierarchy CA certificate itself, linted as a leaf, must be RED.
	findings, err := profilelint.Lint(root.CertificateDER(), profilelint.Options{Leaf: true})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if !profilelint.HasErrors(findings) {
		t.Fatal("profile linter did not flag a hierarchy CA certificate linted as an end-entity leaf (PKIGOV-002)")
	}
	codes := map[string]bool{}
	for _, f := range profilelint.Errors(findings) {
		codes[f.Code] = true
	}
	if !codes["e_leaf_is_ca"] {
		t.Error("linter did not flag CA=true on a hierarchy leaf (e_leaf_is_ca)")
	}
	if !codes["e_leaf_without_san"] {
		t.Error("linter did not flag a missing SAN on a hierarchy leaf (e_leaf_without_san)")
	}
}
