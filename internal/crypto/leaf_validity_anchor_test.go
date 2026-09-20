// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestIssuedLeafValidityAnchorMatchesSignedBounds(t *testing.T) {
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	caDER, err := SelfSignedCACert(key, "validity anchor CA", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "anchor.test", DNSNames: []string{"anchor.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, ttl := range []time.Duration{time.Hour, 30 * 24 * time.Hour} {
		before := time.Now().UTC().Truncate(time.Microsecond)
		issued, err := SignLeafFromCSRWithValidity(caDER, key, csr, ttl, LeafProfile{ClampTTLToIssuer: true})
		if err != nil {
			t.Fatal(err)
		}
		if issued.ValidityAnchor.Before(before) || issued.ValidityAnchor.After(time.Now()) {
			t.Fatal("validity anchor is not the actual constructor clock")
		}
		cert, err := x509.ParseCertificate(issued.DER)
		if err != nil {
			t.Fatal(err)
		}
		caCert, err := x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}
		if err := cert.CheckSignatureFrom(caCert); err != nil {
			t.Fatal(err)
		}
		if !cert.NotBefore.Equal(IssuanceNotBefore(issued.ValidityAnchor).Truncate(time.Second)) {
			t.Fatal("anchor does not produce the actual backdated signed NotBefore")
		}
		if ttl == time.Hour && !cert.NotAfter.Equal(issued.ValidityAnchor.Add(ttl).Truncate(time.Second)) {
			t.Fatal("anchor does not produce the actual signed expiry")
		}
		if ttl > 2*time.Hour && cert.NotAfter.Sub(issued.ValidityAnchor) > 2*time.Hour {
			t.Fatal("effective lifetime ignored the issuing CA's clamp")
		}
	}
	failed, err := SignLeafFromCSRWithValidity(caDER, key, []byte("invalid CSR"), time.Hour, LeafProfile{})
	if err == nil || len(failed.DER) != 0 || !failed.ValidityAnchor.IsZero() {
		t.Fatal("failed issuance returned a certificate or validity anchor")
	}
}
