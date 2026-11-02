// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func TestSignJWTWithPEMKeyRS256(t *testing.T) {
	signer, err := GenerateLockedKey(RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	pkcs8PEM, err := signer.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pkcs8PEM)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key := parsed.(*rsa.PrivateKey)
	// A GitHub App's downloaded key is PKCS #1 ("RSA PRIVATE KEY").
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	jwk, err := PublicJWK(signer.Public(), "")
	if err != nil {
		t.Fatal(err)
	}
	for name, keyPEM := range map[string][]byte{"PKCS #1": pkcs1, "PKCS #8": pkcs8PEM} {
		token, err := SignJWTWithPEMKey(keyPEM, "", map[string]any{"iss": "Iv1.lab", "iat": 1, "exp": 2})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		header, _, _ := strings.Cut(token, ".")
		if header != b64url([]byte(`{"alg":"RS256","typ":"JWT"}`)) {
			t.Fatalf("%s: header %q", name, header)
		}
		claims, err := VerifyJWT(token, JWKS{Keys: []JWK{jwk}})
		if err != nil {
			t.Fatalf("%s: the JWT does not verify against the key's public half: %v", name, err)
		}
		var got struct{ Iss string }
		if json.Unmarshal(claims, &got) != nil || got.Iss != "Iv1.lab" {
			t.Fatalf("%s: claims %s", name, claims)
		}
	}
	for name, keyPEM := range map[string][]byte{"PKCS #1": pkcs1, "PKCS #8": pkcs8PEM} {
		der, err := PublicKeyDERFromPEMKey(keyPEM)
		if err != nil || string(der) != string(signer.Public().DER) {
			t.Fatalf("%s: public key DER differs from the key's (%v)", name, err)
		}
	}
	if _, err := PublicKeyDERFromPEMKey([]byte("not a key")); err == nil {
		t.Fatal("read a public key from non-PEM bytes")
	}
	two := append(append([]byte{}, pkcs1...), pkcs1...)
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: x509.MarshalPKCS1PrivateKey(key)})
	for name, bad := range map[string][]byte{"empty": nil, "not PEM": []byte("ghs_not_a_key"), "two blocks": two, "encrypted": encrypted,
		"certificate": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})} {
		if _, err := SignJWTWithPEMKey(bad, "", map[string]any{"iss": "x"}); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}
