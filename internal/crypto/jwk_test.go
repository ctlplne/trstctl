// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

func TestPublicKeyFromRSAJWK(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PublicKeyFromJWK(JSONWebKey{
		KeyType: "RSA-HSM", N: key.N.Bytes(), E: big.NewInt(int64(key.E)).Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Algorithm != RSA2048 || len(got.DER) == 0 {
		t.Fatalf("public key = %+v", got)
	}
}

func TestNormalizeECDSASignatureConvertsP1363(t *testing.T) {
	raw := make([]byte, 64)
	raw[31], raw[63] = 1, 2
	der, err := NormalizeECDSASignature(ECDSAP256, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(der) == 0 || len(der) == len(raw) {
		t.Fatalf("DER signature length = %d", len(der))
	}
	if preserved, err := NormalizeECDSASignature(ECDSAP256, der); err != nil || string(preserved) != string(der) {
		t.Fatalf("preserve DER = %x, %v", preserved, err)
	}
}

func TestPublicKeyFromECJWK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PublicKeyFromJWK(JSONWebKey{
		KeyType: "EC", Curve: "P-256", X: key.X.Bytes(), Y: key.Y.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Algorithm != ECDSAP256 || len(got.DER) == 0 {
		t.Fatalf("public key = %+v", got)
	}
}

func TestPublicKeyFromJWKRejectsMalformedMaterial(t *testing.T) {
	for _, jwk := range []JSONWebKey{
		{KeyType: "oct"},
		{KeyType: "RSA", N: []byte{1}, E: []byte{2}},
		{KeyType: "EC", Curve: "P-256", X: []byte{1}, Y: []byte{1}},
	} {
		if _, err := PublicKeyFromJWK(jwk); err == nil {
			t.Fatalf("accepted malformed JWK %+v", jwk)
		}
	}
}
