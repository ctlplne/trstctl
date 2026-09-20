// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"testing"
)

func TestParsePublicKeyPEMClassifiesAndRejectsTrailingData(t *testing.T) {
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	pemBytes := MarshalPublicKeyPEM(key.Public().DER)
	parsed, err := ParsePublicKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM: %v", err)
	}
	if parsed.Algorithm != ECDSAP256 || !bytes.Equal(parsed.DER, key.Public().DER) {
		t.Fatalf("parsed public key = %+v, want ECDSA-P256 exact DER", parsed)
	}
	if _, err := ParsePublicKeyPEM(append(pemBytes, []byte("second trust object")...)); err == nil {
		t.Fatal("ParsePublicKeyPEM accepted trailing trust material")
	}
}

func TestParsePublicKeyPEMRejectsSkippedMaterialAndHeaders(t *testing.T) {
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	public := MarshalPublicKeyPEM(key.Public().DER)
	for name, input := range map[string][]byte{
		"leading-junk":          append([]byte("unexpected leading material\n"), public...),
		"malformed-first-block": append([]byte("-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n"), public...),
		"two-valid-keys":        append(append([]byte(nil), public...), public...),
		"pem-header":            pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"Untrusted": "ignored"}, Bytes: key.Public().DER}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePublicKeyPEM(input); err == nil {
				t.Fatal("ambiguous public-key material accepted")
			}
		})
	}
	for _, input := range [][]byte{
		append(append([]byte(" \t\r\n"), public...), []byte(" \r\n")...),
		bytes.ReplaceAll(public, []byte("\n"), []byte("\r\n")),
	} {
		got, err := ParsePublicKeyPEM(input)
		if err != nil || !bytes.Equal(got.DER, key.Public().DER) {
			t.Fatalf("ordinary whitespace or CRLF key rejected: %v", err)
		}
	}
}

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
