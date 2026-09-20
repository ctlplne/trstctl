// SPDX-License-Identifier: BUSL-1.1

package cmp_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	cmpsrv "trstctl.com/trstctl/internal/protocols/cmp"
)

// TestCMPRefusesUnanchoredProtectionIdentity is the regression guard for the
// unauthenticated-enrollment defect. CMP carries the identity that protected the
// PKIMessage inside the message's own extraCerts, and the server verified the
// protection signature against exactly that certificate. The check was therefore
// self-referential: any self-signed key pair satisfied it, and the served
// endpoint applied no other credential check, so anyone who could reach /cmp
// could mint a certificate from the tenant CA.
//
// newClient() builds precisely that self-signed identity, which is what makes it
// the right negative fixture here.
func TestCMPRefusesUnanchoredProtectionIdentity(t *testing.T) {
	ca := newRSACA(t)
	// Anchored to the CA — a self-signed client identity does NOT chain to it.
	srv := cmpsrv.New(cmpsrv.Config{
		Enroller: realEnroller{ca: ca}, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8,
		ProfileName:           "device",
		ClientTrustAnchorsDER: [][]byte{ca.certDER},
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	clientCert, clientKey, csrDER := newClient(t)
	reqDER := buildRequest(t, clientCert, clientKey, csrDER)

	resp, err := http.Post(ts.URL+"/cmp", "application/pkixcmp", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("CMP enrolled a self-signed protection identity (%d bytes); "+
			"any key pair could mint from the tenant CA", len(body))
	}
}

// TestCMPAcceptsAnchoredProtectionIdentity keeps the guard honest: a client
// whose protection identity was issued by the configured anchor still enrols.
//
// DELIBERATE CONTRACT CHANGE (AUD-201 follow-up H1/V22): this test used to pin
// the UNBOUND behaviour — protection identity "anchored-device" enrolling a
// CSR for "device-1" — which meant any anchored credential could mint ANY name
// the profile admitted. That third-party shape is now the RFC 4210 RA case and
// requires the explicit AllowRAEnrollment opt-in, exercised here; the default
// fail-closed binding is pinned by TestCMPDefaultRefusesCrossIdentityCSR and
// self-renewal by TestCMPDefaultAllowsSelfRenewal.
func TestCMPAcceptsAnchoredProtectionIdentity(t *testing.T) {
	ca := newRSACA(t)
	srv := cmpsrv.New(cmpsrv.Config{
		Enroller: realEnroller{ca: ca}, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8,
		ProfileName:           "device",
		ClientTrustAnchorsDER: [][]byte{ca.certDER},
		AllowRAEnrollment:     true,
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// A protection identity the anchor actually issued.
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	protCSR, err := crypto.CreateCertificateRequest(
		crypto.CertificateRequestTemplate{CommonName: "anchored-device"}, signer)
	if err != nil {
		t.Fatal(err)
	}
	protCert, err := crypto.SignLeafFromCSR(ca.certDER, ca.signer, protCSR, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	protKey, err := signer.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	_, _, csrDER := newClient(t)

	resp, err := http.Post(ts.URL+"/cmp", "application/pkixcmp",
		bytes.NewReader(buildRequest(t, protCert, protKey, csrDER)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("CMP refused an anchored protection identity: status=%d body=%s", resp.StatusCode, body)
	}
}

// TestCMPWithoutAnchorsRefusesToEnrol pins the fail-closed default: a deployment
// that configures no client anchors must refuse enrollment rather than accept
// every caller. Running open requires setting AllowUnauthenticatedClients
// deliberately, which production wiring never does.
func TestCMPWithoutAnchorsRefusesToEnrol(t *testing.T) {
	ca := newRSACA(t)
	srv := cmpsrv.New(cmpsrv.Config{
		Enroller: realEnroller{ca: ca}, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8,
		ProfileName: "device",
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	clientCert, clientKey, csrDER := newClient(t)
	resp, err := http.Post(ts.URL+"/cmp", "application/pkixcmp",
		bytes.NewReader(buildRequest(t, clientCert, clientKey, csrDER)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("CMP enrolled with no client trust anchors configured; the mount must fail closed")
	}
}
