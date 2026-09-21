// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/x509"
	"testing"
	"time"
)

func clampTestCA(t *testing.T, ttl time.Duration) ([]byte, *LockedSigner) {
	t.Helper()
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, err := SelfSignedCACert(key, "Clamp Test CA", ttl)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func clampTestCSR(t *testing.T) []byte {
	t.Helper()
	subject, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(subject.Destroy)
	csr, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "leaf.example"}, subject)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// TestClampTTLToIssuerBoundsTheLeaf preserves the served hierarchy's TTL-clamp
// behavior after the clamp moved INTO the signing helper (AUD-201 follow-up
// E2/V34): a requested TTL beyond the issuer's expiry is clamped to the
// issuer's remaining window, and a zero TTL means "as long as the issuer can
// vouch".
func TestClampTTLToIssuerBoundsTheLeaf(t *testing.T) {
	caDER, caKey := clampTestCA(t, time.Hour)
	csr := clampTestCSR(t)

	for name, requested := range map[string]time.Duration{
		"beyond issuer expiry": 24 * time.Hour,
		"zero means issuer":    0,
	} {
		leafDER, err := SignLeafFromCSRWithProfile(caDER, caKey, csr, requested, LeafProfile{ClampTTLToIssuer: true})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		leaf, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Fatal(err)
		}
		ca, err := x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}
		if leaf.NotAfter.After(ca.NotAfter) {
			t.Fatalf("%s: leaf NotAfter %s outlives issuer NotAfter %s", name, leaf.NotAfter, ca.NotAfter)
		}
		if time.Until(leaf.NotAfter) < 55*time.Minute {
			t.Fatalf("%s: leaf clamped too far (NotAfter %s); it should get the issuer's remaining window", name, leaf.NotAfter)
		}
	}

	// A modest TTL inside the window is honored, not stretched.
	leafDER, err := SignLeafFromCSRWithProfile(caDER, caKey, csr, 10*time.Minute, LeafProfile{ClampTTLToIssuer: true})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if until := time.Until(leaf.NotAfter); until > 11*time.Minute {
		t.Fatalf("a requested TTL inside the issuer window was stretched to %s", until)
	}
}

// TestClampTTLToIssuerRejectsAnExpiredIssuer: an expired issuer cannot vouch
// for a new leaf, and the refusal is a profile violation so the served route
// keeps its invalid-hierarchy (4xx) error surface.
func TestClampTTLToIssuerRejectsAnExpiredIssuer(t *testing.T) {
	caDER, caKey := clampTestCA(t, -time.Hour)
	csr := clampTestCSR(t)

	_, err := SignLeafFromCSRWithProfile(caDER, caKey, csr, time.Minute, LeafProfile{ClampTTLToIssuer: true})
	if err == nil {
		t.Fatal("an expired issuer signed a leaf")
	}
	if !IsLeafProfileViolation(err) {
		t.Fatalf("expired-issuer refusal must be a profile violation for the 4xx surface, got: %v", err)
	}
}

// TestUnflaggedCallersKeepTheirTTLSemantics pins that the clamp is OPT-IN: a
// caller that manages validity itself (protocol servers, breakglass) gets the
// exact TTL it asked for even past the issuer's expiry, unchanged from before.
func TestUnflaggedCallersKeepTheirTTLSemantics(t *testing.T) {
	caDER, caKey := clampTestCA(t, time.Hour)
	csr := clampTestCSR(t)

	leafDER, err := SignLeafFromCSRWithProfile(caDER, caKey, csr, 24*time.Hour, LeafProfile{})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if until := time.Until(leaf.NotAfter); until < 23*time.Hour {
		t.Fatalf("an unflagged caller's TTL was clamped (NotAfter in %s); the clamp must be opt-in", until)
	}
}
