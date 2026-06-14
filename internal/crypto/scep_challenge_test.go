package crypto

import (
	"encoding/asn1"
	"testing"
	"time"
)

// TestChallengePasswordFromCSR builds a minimal PKCS#10 carrying a challengePassword and
// confirms it is extracted; a CSR without one yields "".
func TestChallengePasswordFromCSR(t *testing.T) {
	// A CSR carrying challengePassword "s3cret" (signature irrelevant to extraction).
	pwTLV, err := asn1.Marshal("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	attr := scepCSRAttr{
		Type:   oidChallengePassword,
		Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: pwTLV},
	}
	emptySeq := asn1.RawValue{FullBytes: []byte{0x30, 0x00}}
	csr := scepCSR{
		Info:   scepCSRInfo{Version: 0, Subject: emptySeq, PublicKey: emptySeq, Attributes: []scepCSRAttr{attr}},
		SigAlg: emptySeq,
		Sig:    asn1.BitString{Bytes: []byte{0x00}, BitLength: 8},
	}
	der, err := asn1.Marshal(csr)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ChallengePasswordFromCSR(der)
	if err != nil {
		t.Fatalf("extract challenge: %v", err)
	}
	if got != "s3cret" {
		t.Fatalf("challengePassword = %q, want %q", got, "s3cret")
	}

	// A normal CSR has no challengePassword -> "".
	signer, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	plain, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "x"}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if pw, err := ChallengePasswordFromCSR(plain); err != nil || pw != "" {
		t.Fatalf("plain CSR challenge = %q, err %v; want empty", pw, err)
	}
	_ = time.Second
}
