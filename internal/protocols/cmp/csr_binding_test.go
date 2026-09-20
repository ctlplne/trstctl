// SPDX-License-Identifier: BUSL-1.1

package cmp_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	cmpsrv "trstctl.com/trstctl/internal/protocols/cmp"
)

func anchoredIdentity(t *testing.T, ca caFixture, commonName string) (certDER, keyPKCS8 []byte) {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	protCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: commonName}, signer)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err = crypto.SignLeafFromCSR(ca.certDER, ca.signer, protCSR, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPKCS8, err = signer.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	return certDER, keyPKCS8
}

func csrFor(t *testing.T, commonName string) []byte {
	t.Helper()
	subject, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(subject.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: commonName}, subject)
	if err != nil {
		t.Fatal(err)
	}
	return csrDER
}

func boundTestServer(t *testing.T, ca caFixture, allowRA bool) *httptest.Server {
	t.Helper()
	srv := cmpsrv.New(cmpsrv.Config{
		Enroller: realEnroller{ca: ca}, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8,
		ProfileName:           "device",
		ClientTrustAnchorsDER: [][]byte{ca.certDER},
		AllowRAEnrollment:     allowRA,
	})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts
}

// TestCMPDefaultRefusesCrossIdentityCSR is the regression guard for AUD-201
// follow-up H1/V22. CMP authenticated the client — the protection identity
// chained to the configured anchors — and then IGNORED who it was: the CSR's
// names were never compared to the identity, so any client holding ANY
// certificate that chained to the anchor bundle could enroll for ANY name the
// tenant profile admitted. One stolen device credential was tenant-wide in
// blast radius. The fail-closed default now refuses a CSR whose identifiers
// the protection identity does not assert — cross-device impersonation dies
// with a distinct 403, not a certificate.
func TestCMPDefaultRefusesCrossIdentityCSR(t *testing.T) {
	ca := newRSACA(t)
	ts := boundTestServer(t, ca, false)

	deviceCert, deviceKey := anchoredIdentity(t, ca, "device-alpha")
	victimCSR := csrFor(t, "device-beta")

	resp, err := http.Post(ts.URL+"/cmp", "application/pkixcmp",
		bytes.NewReader(buildRequest(t, deviceCert, deviceKey, victimCSR)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("device-alpha enrolled a certificate for device-beta (%d bytes); "+
			"one stolen credential reaches every name the profile admits", len(body))
	}
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "not authorized for protection identity") {
		t.Fatalf("cross-identity refusal = %d %q, want a distinct 403 naming the binding", resp.StatusCode, body)
	}
}

// TestCMPDefaultAllowsSelfRenewal pins the other half of the fail-closed
// contract: a device re-enrolling ITS OWN name must still succeed with no
// configuration, or the default would break every legitimate renewal.
func TestCMPDefaultAllowsSelfRenewal(t *testing.T) {
	ca := newRSACA(t)
	ts := boundTestServer(t, ca, false)

	deviceCert, deviceKey := anchoredIdentity(t, ca, "device-alpha")
	renewalCSR := csrFor(t, "device-alpha")

	resp, err := http.Post(ts.URL+"/cmp", "application/pkixcmp",
		bytes.NewReader(buildRequest(t, deviceCert, deviceKey, renewalCSR)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("self-renewal under the fail-closed default = %d %s; the default must not break legitimate renewals", resp.StatusCode, body)
	}
}

// TestCMPRAEnrollmentIsAnExplicitOptIn: with AllowRAEnrollment the SAME
// third-party request that the default refuses is admitted — the RFC 4210 RA
// model as a deployment decision rather than an accident.
func TestCMPRAEnrollmentIsAnExplicitOptIn(t *testing.T) {
	ca := newRSACA(t)
	ts := boundTestServer(t, ca, true)

	raCert, raKey := anchoredIdentity(t, ca, "enrollment-ra")
	thirdPartyCSR := csrFor(t, "device-gamma")

	resp, err := http.Post(ts.URL+"/cmp", "application/pkixcmp",
		bytes.NewReader(buildRequest(t, raCert, raKey, thirdPartyCSR)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("RA-style enrollment with the explicit opt-in = %d %s", resp.StatusCode, body)
	}
}
