// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"testing"
)

// P9-L3: a token's CKA_EC_PARAMS and CKA_EC_POINT (wrapped or bare) become the
// key's PKIX SubjectPublicKeyInfo, and a CKM_ECDSA r||s signature becomes the
// ASN.1 signature that verifies; malformed parameters, points and signatures
// are refused.
func TestPKCS11ECConversionsP9L3(t *testing.T) {
	for _, tc := range []struct {
		alg   Algorithm
		curve elliptic.Curve
	}{{ECDSAP256, elliptic.P256()}, {ECDSAP384, elliptic.P384()}} {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		want, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		point, err := key.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		params, err := PKCS11ECParams(tc.alg)
		if err != nil {
			t.Fatal(err)
		}
		wrapped, err := asn1.Marshal(point)
		if err != nil {
			t.Fatal(err)
		}
		for name, ecPoint := range map[string][]byte{"wrapped": wrapped, "bare": point} {
			der, alg, err := ECDSAPublicKeyDERFromPKCS11(params, ecPoint)
			if err != nil || alg != tc.alg || string(der) != string(want) {
				t.Fatalf("%s %s point: alg %s err %v", tc.alg, name, alg, err)
			}
		}
		digest := sha256.Sum256([]byte("p9-l3"))
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		size := (tc.curve.Params().BitSize + 7) / 8
		raw := make([]byte, 2*size)
		r.FillBytes(raw[:size])
		s.FillBytes(raw[size:])
		sig, err := ECDSASignatureDERFromRaw(raw, tc.alg)
		if err != nil || !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
			t.Fatalf("%s: raw signature did not convert to one that verifies: %v", tc.alg, err)
		}
		if err := VerifyDigest(PublicKey{DER: want}, digest[:], sig, SignOptions{Hash: SHA256}); err != nil {
			t.Fatalf("%s: VerifyDigest: %v", tc.alg, err)
		}
		if _, err := ECDSASignatureDERFromRaw(raw[1:], tc.alg); err == nil {
			t.Fatalf("%s: a short signature converted", tc.alg)
		}
		bad := append([]byte(nil), point...)
		bad[len(bad)-1] ^= 0x01
		if _, _, err := ECDSAPublicKeyDERFromPKCS11(params, bad); err == nil {
			t.Fatalf("%s: a point off the curve was accepted", tc.alg)
		}
	}
	p521, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 35})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ECDSAPublicKeyDERFromPKCS11(p521, []byte{4}); err == nil {
		t.Fatal("P-521 parameters were accepted")
	}
	if _, err := PKCS11ECParams(RSA2048); err == nil || IsPKCS11ECAlgorithm(RSA2048) || !IsPKCS11ECAlgorithm(ECDSAP384) {
		t.Fatal("RSA-2048 read as an EC algorithm")
	}
}
