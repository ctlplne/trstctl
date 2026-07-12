// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"testing"
	"time"
)

func TestSignOpaqueLeafUsesOneCAOperationAndVerifies(t *testing.T) {
	caKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	caDER, err := SelfSignedCACert(caKey, "opaque-test-ca", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := MarshalOpaqueSubjectPublicKeyInfo("1.3.6.1.4.1.59551.99.1", []byte("public-subject-key"))
	if err != nil {
		t.Fatal(err)
	}
	counted := &countingDigestSigner{DigestSigner: caKey}
	leafDER, err := SignOpaqueLeafFromVerifiedRequestWithProfile(caDER, counted, OpaqueLeafRequest{
		Info:                    CSRInfo{CommonName: "opaque.example", DNSNames: []string{"opaque.example"}},
		SubjectPublicKeyInfoDER: spki,
		SignatureOnly:           true,
	}, time.Hour, LeafProfile{})
	if err != nil {
		t.Fatalf("SignOpaqueLeafFromVerifiedRequestWithProfile: %v", err)
	}
	if counted.calls != 1 {
		t.Fatalf("CA signer calls = %d, want exactly 1", counted.calls)
	}
	if err := VerifyLeafSignedByCA(leafDER, caDER); err != nil {
		t.Fatalf("VerifyLeafSignedByCA: %v", err)
	}
}

func TestSignOpaqueSignatureOnlyRejectsEncryptionUsage(t *testing.T) {
	caKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	caDER, err := SelfSignedCACert(caKey, "opaque-test-ca", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := MarshalOpaqueSubjectPublicKeyInfo("1.3.6.1.4.1.59551.99.1", []byte("public-subject-key"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = SignOpaqueLeafFromVerifiedRequestWithProfile(caDER, caKey, OpaqueLeafRequest{
		Info: CSRInfo{CommonName: "opaque.example"}, SubjectPublicKeyInfoDER: spki, SignatureOnly: true,
	}, time.Hour, LeafProfile{AllowedKeyUsages: &KeyUsages{DigitalSignature: true, KeyEncipherment: true}})
	if !IsLeafProfileViolation(err) {
		t.Fatalf("error = %v, want leaf profile violation", err)
	}
}

type countingDigestSigner struct {
	DigestSigner
	calls int
}

func (s *countingDigestSigner) SignDigest(digest []byte, opts SignOptions) ([]byte, error) {
	s.calls++
	return s.DigestSigner.SignDigest(digest, opts)
}

func FuzzInspectOpaqueCSR(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		_, _ = InspectOpaqueCSR(der)
	})
}
