// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/x509"
	"slices"
	"testing"
	"time"
)

// TestCrossSignPreservesExcludedNameConstraints is the regression guard for the
// constraint-widening defect. CrossSignHierarchyCA copied only
// PermittedDNSDomains into the cross-certificate and discarded every other name
// constraint. Excluded subtrees are the half that matters most: an excluded
// "secret.corp.example" carves a hole out of a permitted "corp.example", so
// dropping it re-permits exactly the names the operator carved out — the
// cross-signed CA ends up MORE capable than the CA it cross-signs.
func TestCrossSignPreservesExcludedNameConstraints(t *testing.T) {
	issuerSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuerSigner.Destroy)
	issuerDER, err := SelfSignedHierarchyCA(issuerSigner, HierarchyCAProfile{
		CommonName: "cross-sign issuer", MaxPathLen: 1, TTL: 72 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	// A target constrained in every dimension, including exclusions.
	targetSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(targetSigner.Destroy)
	targetSelf, err := SelfSignedHierarchyCA(targetSigner, HierarchyCAProfile{
		CommonName:          "constrained target",
		PermittedDNSDomains: []string{"corp.example"},
		ExcludedDNSDomains:  []string{"secret.corp.example"},
		MaxPathLen:          0,
		TTL:                 48 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	crossed, err := CrossSignHierarchyCA(issuerDER.CertificateDER, issuerSigner, targetSelf.CertificateDER)
	if err != nil {
		t.Fatalf("cross-sign: %v", err)
	}
	cert, err := x509.ParseCertificate(crossed.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Contains(cert.PermittedDNSDomains, "corp.example") {
		t.Errorf("permitted DNS constraint lost: %v", cert.PermittedDNSDomains)
	}
	if !slices.Contains(cert.ExcludedDNSDomains, "secret.corp.example") {
		t.Fatalf("EXCLUDED DNS constraint was dropped (%v); the cross-certificate re-permits the subtree "+
			"the operator carved out, making it more capable than the CA it cross-signs",
			cert.ExcludedDNSDomains)
	}
}
