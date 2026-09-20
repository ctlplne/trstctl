// SPDX-License-Identifier: BUSL-1.1

package tsa

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// TestTSACertificateProfileRejectsNonTimestampingCert is the regression guard
// for the timestamp-forgery defect. Verify chained the TSA certificate to the
// trusted root and stopped there, so ANY end-entity certificate that root had
// issued — an ordinary TLS server certificate for the tenant, for example —
// could sign a timestamp token this verifier accepted. RFC 3161 §2.3 requires
// the TSA certificate to carry the timeStamping extended key usage and no other.
func TestTSACertificateProfileRejectsNonTimestampingCert(t *testing.T) {
	caSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caSigner.Destroy)
	caDER, err := crypto.SelfSignedCACert(caSigner, "trstctl TSA profile CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	leafSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafSigner.Destroy)

	// An ordinary serverAuth leaf from the same CA — exactly what an attacker
	// with any issued certificate would try to sign a timestamp with.
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "web.example", DNSNames: []string{"web.example"},
		RequestedEKUs: []string{"serverAuth"},
	}, leafSigner)
	if err != nil {
		t.Fatal(err)
	}
	serverLeaf, err := crypto.SignLeafFromCSR(caDER, caSigner, csrDER, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	err = verifyTSACertificateProfile(serverLeaf)
	if err == nil {
		t.Fatal("a serverAuth leaf was accepted as a TSA certificate; any certificate from this CA could forge a timestamp")
	}
	if !strings.Contains(err.Error(), "timeStamping") {
		t.Errorf("refusal should name the required usage, got: %v", err)
	}

	// A CA certificate must also be refused: a timestamp is signed by an end
	// entity, never by the authority itself.
	if err := verifyTSACertificateProfile(caDER); err == nil {
		t.Fatal("a CA certificate was accepted as a TSA certificate")
	}
}

// TestTSACertificateProfileAcceptsRealTSACert keeps the guard honest: the
// certificate this package's own authority uses must still verify, so the check
// cannot be satisfied by refusing everything.
func TestTSACertificateProfileAcceptsRealTSACert(t *testing.T) {
	caSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caSigner.Destroy)
	caDER, err := crypto.SelfSignedCACert(caSigner, "trstctl TSA profile CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tsaSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tsaSigner.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "trstctl timestamping",
	}, tsaSigner)
	if err != nil {
		t.Fatal(err)
	}
	// The path the served TSA actually uses to mint its own certificate.
	tsaLeaf, err := crypto.SignTimestampingCertFromCSR(caDER, caSigner, csrDER, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyTSACertificateProfile(tsaLeaf); err != nil {
		t.Fatalf("a proper timeStamping certificate was refused: %v", err)
	}
}
