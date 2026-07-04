// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/sha256"
	"testing"
)

func TestVerifyMessageECDSAandRSA(t *testing.T) {
	for _, alg := range []Algorithm{ECDSAP256, RSA2048} {
		k, err := GenerateLockedKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("attestation quote bytes")
		d := sha256.Sum256(msg)
		sig, err := k.SignDigest(d[:], SignOptions{Hash: SHA256, RSAPadding: RSAPKCS1v15})
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyMessage(k.Public().DER, msg, sig); err != nil {
			t.Fatalf("%s verify: %v", alg, err)
		}
		if err := VerifyMessage(k.Public().DER, []byte("tampered"), sig); err == nil {
			t.Errorf("%s accepted a wrong message", alg)
		}
		k.Destroy()
	}
}

func TestVerifyCMSRoundTripAndWrongRoot(t *testing.T) {
	content := []byte(`{"instanceId":"i-0abc","accountId":"111122223333","region":"us-east-1"}`)
	p7, root, err := SignCMS(content)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyCMSSignature(p7, [][]byte{root})
	if err != nil {
		t.Fatalf("VerifyCMSSignature: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content = %s", got)
	}
	_, otherRoot, _ := SignCMS(content)
	if _, err := VerifyCMSSignature(p7, [][]byte{otherRoot}); err == nil {
		t.Error("CMS verified against an untrusted root (must fail closed)")
	}
}
