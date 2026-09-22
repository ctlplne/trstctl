// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/x509"
	"testing"
	"time"
)

func opaquePreparationRequest(t *testing.T) OpaqueLeafRequest {
	t.Helper()
	spki, err := MarshalOpaqueSubjectPublicKeyInfo("1.3.6.1.4.1.59551.99.1", []byte("opaque-subject-public-key"))
	if err != nil {
		t.Fatal(err)
	}
	return OpaqueLeafRequest{Info: CSRInfo{CommonName: "prepared.example.test", DNSNames: []string{"prepared.example.test"}}, SubjectPublicKeyInfoDER: spki, SignatureOnly: true}
}

func TestOpaqueIssuerClampPreventsLeafOutlivingCA(t *testing.T) {
	ca, key := clampTestCA(t, time.Hour)
	issuer, err := x509.ParseCertificate(ca)
	if err != nil {
		t.Fatal(err)
	}
	for _, ttl := range []time.Duration{24 * time.Hour, 0} {
		der, err := SignOpaqueLeafFromVerifiedRequestWithProfile(ca, key, opaquePreparationRequest(t), ttl, LeafProfile{ClampTTLToIssuer: true})
		if err != nil {
			t.Fatalf("ttl=%v: %v", ttl, err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if leaf.NotAfter.After(issuer.NotAfter) || time.Until(leaf.NotAfter) < 55*time.Minute {
			t.Fatalf("ttl=%v: opaque leaf expires %s, issuer expires %s", ttl, leaf.NotAfter, issuer.NotAfter)
		}
	}
}

func TestOpaqueIssuerClampRejectsExpiredCABeforeSigning(t *testing.T) {
	ca, key := clampTestCA(t, -time.Hour)
	counted := &countingDigestSigner{DigestSigner: key}
	der, err := SignOpaqueLeafFromVerifiedRequestWithProfile(ca, counted, opaquePreparationRequest(t), time.Minute, LeafProfile{ClampTTLToIssuer: true})
	if !IsLeafProfileViolation(err) || len(der) != 0 || counted.calls != 0 {
		t.Fatalf("expired issuer: error=%v certificate bytes=%d CA operations=%d", err, len(der), counted.calls)
	}
}
