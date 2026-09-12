// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"
)

func TestLeafProfileMaximumIncludesBackdate(t *testing.T) {
	ca, key := clampTestCA(t, time.Hour)
	csr := clampTestCSR(t)
	spki, err := MarshalOpaqueSubjectPublicKeyInfo("1.3.6.1.4.1.59551.99.1", []byte("validity-test-public-key"))
	if err != nil {
		t.Fatal(err)
	}
	for _, opaque := range []bool{false, true} {
		for _, tc := range []struct {
			name         string
			maximum, ttl time.Duration
			refuse       bool
		}{
			{"maximum-includes-skew", 10 * time.Minute, 10 * time.Minute, false},
			{"shorter-request", 20 * time.Minute, 10 * time.Minute, false},
			{"unbounded-profile", 0, 10 * time.Minute, false},
			{"no-time-after-backdating", 2 * time.Minute, 2 * time.Minute, true},
			{"expiry-at-issuance", 5 * time.Minute, 5 * time.Minute, true},
		} {
			name := "classical/" + tc.name
			if opaque {
				name = "opaque/" + tc.name
			}
			t.Run(name, func(t *testing.T) {
				counted := &countingDigestSigner{DigestSigner: key}
				profile := LeafProfile{MaxValidity: tc.maximum}
				before := time.Now()
				var der []byte
				var err error
				if opaque {
					der, err = SignOpaqueLeafFromVerifiedRequestWithProfile(ca, counted, OpaqueLeafRequest{
						Info: CSRInfo{CommonName: "short.example"}, SubjectPublicKeyInfoDER: spki, SignatureOnly: true,
					}, tc.ttl, profile)
				} else {
					der, err = SignLeafFromCSRWithProfile(ca, counted, csr, tc.ttl, profile)
				}
				if tc.refuse {
					if !IsLeafProfileViolation(err) || len(der) != 0 || counted.calls != 0 {
						t.Fatalf("unusable profile must fail before signing: error=%v calls=%d", err, counted.calls)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if err = VerifyLeafSignedByCA(der, ca); err != nil {
					t.Fatal(err)
				}
				var notBefore, notAfter time.Time
				if opaque {
					var cert opaqueCertificate
					if _, err = asn1.Unmarshal(der, &cert); err != nil {
						t.Fatal(err)
					}
					notBefore, notAfter = cert.TBS.Validity.NotBefore, cert.TBS.Validity.NotAfter
				} else {
					cert, err := x509.ParseCertificate(der)
					if err != nil {
						t.Fatal(err)
					}
					notBefore, notAfter = cert.NotBefore, cert.NotAfter
				}
				if tc.maximum > 0 && notAfter.Sub(notBefore) > tc.maximum {
					t.Fatalf("signed lifetime %s exceeds maximum %s", notAfter.Sub(notBefore), tc.maximum)
				}
				if !notAfter.After(before) || notBefore.After(before.Add(-4*time.Minute)) {
					t.Fatalf("lost usable lifetime or clock skew protection: %s -> %s", notBefore, notAfter)
				}
				if counted.calls != 1 {
					t.Fatalf("CA signing calls=%d, want1", counted.calls)
				}
			})
		}
	}
}

func TestPreparedLeafProfileMaximumPreservesAnchorAndIssuer(t *testing.T) {
	ca, key := clampTestCA(t, 3*time.Minute)
	csr := clampTestCSR(t)
	prepared, err := NewLeafPreparation()
	if err != nil {
		t.Fatal(err)
	}
	prepared.ValidityAnchor = prepared.ValidityAnchor.Add(-30 * time.Second)
	issued, err := SignLeafFromCSRWithPreparation(ca, key, csr, 10*time.Minute, LeafProfile{MaxValidity: 10 * time.Minute, ClampTTLToIssuer: true}, prepared)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(issued.DER)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(ca)
	if err != nil {
		t.Fatal(err)
	}
	if !issued.ValidityAnchor.Equal(prepared.ValidityAnchor) || cert.NotAfter.After(issuer.NotAfter) || cert.NotAfter.Sub(cert.NotBefore) > 10*time.Minute {
		t.Fatal("prepared issuance lost its anchor, profile ceiling, or issuer ceiling")
	}
}
