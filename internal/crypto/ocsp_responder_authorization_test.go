// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// The agent-cache fixture is a real, publicly verifiable forgery. Keep this
// control beside the crypto boundary so its HTTP test needs no crypto imports.
func TestCR068PublicFixtureIsValidLeafSignedGood(t *testing.T) {
	issuerDER, err := os.ReadFile(filepath.Join("testdata", "cr068_issuer.der"))
	if err != nil {
		t.Fatal(err)
	}
	responseDER, err := os.ReadFile(filepath.Join("testdata", "cr068_leaf_signed_good.der"))
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	response, err := ocsp.ParseResponse(responseDER, issuer)
	if err != nil {
		t.Fatalf("fixture must be a correctly signed OCSP response: %v", err)
	}
	if response.Status != ocsp.Good || response.Certificate == nil || response.Certificate.IsCA ||
		response.Certificate.SerialNumber.Cmp(response.SerialNumber) != 0 ||
		!time.Now().Before(response.NextUpdate) {
		t.Fatalf("fixture must be a current good status signed by its own non-CA leaf: %+v", response)
	}
	if response.ProducedAt.Before(response.Certificate.NotBefore) || response.ProducedAt.After(response.Certificate.NotAfter) ||
		response.ThisUpdate.Before(response.Certificate.NotBefore) || response.NextUpdate.After(response.Certificate.NotAfter) {
		t.Fatal("fixture response time falls outside its leaf certificate; authorization must be the only refusal")
	}
	for _, eku := range response.Certificate.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			t.Fatal("fixture leaf unexpectedly has OCSP responder authority")
		}
	}
	if _, err := ParseOCSPResponse(responseDER, issuerDER); err == nil {
		t.Fatal("leaf-signed public fixture passed the authorized responder verifier")
	}
}

// CR-068: possession of an ordinary CA-issued leaf key must not turn that
// leaf into an OCSP responder, even when it signs a well-formed "good" answer
// for its own serial number.
func TestCR068OrdinaryLeafCannotSignItsOwnGoodOCSPResponse(t *testing.T) {
	caDER, caSigner := caForRevocation(t)
	leafSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafSigner.Destroy)
	csr, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "revoked.example.test"}, leafSigner)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := SignLeafFromCSR(caDER, caSigner, csr, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA {
		t.Fatal("ordinary leaf fixture is a CA")
	}
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			t.Fatal("ordinary leaf fixture unexpectedly has responder authority")
		}
	}
	adapter, err := newX509Signer(leafSigner)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	forged, err := ocsp.CreateResponse(issuer, leaf, ocsp.Response{
		Status: ocsp.Good, SerialNumber: leaf.SerialNumber, Certificate: leaf,
		ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ocsp.ParseResponse(forged, issuer); err != nil {
		t.Fatalf("control: the forged response must have a valid signature and issuer chain: %v", err)
	}
	if _, err := ParseOCSPResponse(forged, caDER); err == nil {
		t.Fatal("an ordinary leaf signed and verified its own forged good OCSP status")
	}
}

func TestCR068DelegatedResponseCannotOutliveResponderCertificate(t *testing.T) {
	caDER, caSigner := caForRevocation(t)
	responderSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(responderSigner.Destroy)
	now := time.Now().UTC().Truncate(time.Second)
	responderDER, err := CreateOCSPResponderCertificate(caDER, caSigner, responderSigner,
		"short-lived OCSP responder", now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	response, err := SignDelegatedOCSPResponse(caDER, responderDER, responderSigner,
		OCSPGood, "deadbeef", now, now.Add(2*time.Hour), time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseOCSPResponse(response, caDER); err == nil {
		t.Fatal("delegated OCSP answer remained valid after its responder certificate expired")
	}
}
