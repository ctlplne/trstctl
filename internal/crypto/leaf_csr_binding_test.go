// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"testing"
	"time"
)

func TestVerifyLeafBoundToCSRRejectsDifferentApprovedKeyAndIdentity(t *testing.T) {
	ca, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := SelfSignedCACert(ca, "offline test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyA, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer keyA.Destroy()
	keyB, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer keyB.Destroy()
	csrA, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "recovery.example.test", DNSNames: []string{"recovery.example.test"}}, keyA)
	if err != nil {
		t.Fatal(err)
	}
	csrOtherKey, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "recovery.example.test", DNSNames: []string{"recovery.example.test"}}, keyB)
	if err != nil {
		t.Fatal(err)
	}
	csrOtherSAN, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "recovery.example.test", DNSNames: []string{"other.example.test"}}, keyA)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Now().UTC()
	leaf, err := SignLeafFromCSR(caDER, ca, csrA, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLeafBoundToCSR(leaf, csrA, issuedAt, 10*time.Minute); err != nil {
		t.Fatalf("matching leaf: %v", err)
	}
	if err := VerifyLeafBoundToCSR(leaf, csrOtherKey, issuedAt, 10*time.Minute); err == nil {
		t.Fatal("accepted another subject key")
	}
	if err := VerifyLeafBoundToCSR(leaf, csrOtherSAN, issuedAt, 10*time.Minute); err == nil {
		t.Fatal("accepted another DNS SAN")
	}
	if err := VerifyLeafBoundToCSR(leaf, csrA, issuedAt, time.Minute); err == nil {
		t.Fatal("accepted a leaf beyond approved TTL")
	}
}

func FuzzVerifyLeafBoundToCSR(f *testing.F) {
	f.Add([]byte{0x30, 0x00}, []byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, certDER, csrDER []byte) {
		_ = VerifyLeafBoundToCSR(certDER, csrDER, time.Now(), time.Minute)
	})
}
