// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bytes"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestJWTBytesPreservesSignatureAndLegacyWire(t *testing.T) {
	key, err := GenerateLockedKey(RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	claims := map[string]any{"iss": "public-account.public-user", "iat": int64(100), "exp": int64(200)}
	raw, err := SignJWTBytes(key, "a263", claims)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(raw)
	legacy, err := SignJWT(key, "a263", claims)
	if err != nil || !bytes.Equal(raw, []byte(legacy)) {
		t.Fatal("byte-backed signing changed the existing RS256 wire format")
	}
	jwk, err := PublicJWK(key.Public(), "a263")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := VerifyJWTBytes(raw, JWKS{Keys: []JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(payload)
	var decoded map[string]any
	if json.Unmarshal(payload, &decoded) != nil || decoded["iss"] != claims["iss"] {
		t.Fatal("JWT claims changed")
	}
	pem, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(pem)
	fromPEM, err := SignJWTWithPEMKeyBytes(pem, "a263", claims)
	if err != nil || !bytes.Equal(raw, fromPEM) {
		t.Fatal("locked PEM signer changed JWT bytes")
	}
	secret.Wipe(fromPEM)
}

func TestJWTBytesRequiresCanonicalCompactSegments(t *testing.T) {
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	jwk, err := PublicJWK(key.Public(), "canonical")
	if err != nil {
		t.Fatal(err)
	}
	token, err := SignJWTBytes(key, "canonical", map[string]any{"sub": "workload"})
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(token)
	parts := bytes.Split(token, []byte("."))
	if len(parts) != 3 {
		t.Fatal("signed JWT is not compact")
	}
	for i := range parts {
		wire := make([]byte, 0, len(token)+1)
		for j, part := range parts {
			if j > 0 {
				wire = append(wire, '.')
			}
			wire = append(wire, part...)
			if i == j {
				wire = append(wire, '\n')
			}
		}
		claims, err := VerifyJWTBytes(wire, JWKS{Keys: []JWK{jwk}})
		secret.Wipe(claims)
		secret.Wipe(wire)
		if err == nil {
			t.Fatalf("compact JWT segment %d accepted a noncanonical encoding", i)
		}
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := token[len(token)-1]
	index := bytes.IndexByte([]byte(alphabet), last)
	if index < 0 || index%16 != 0 {
		t.Fatalf("unexpected final signature character %q", last)
	}
	wire := bytes.Clone(token)
	wire[len(wire)-1] = alphabet[index+1]
	claims, err := VerifyJWTBytes(wire, JWKS{Keys: []JWK{jwk}})
	secret.Wipe(claims)
	secret.Wipe(wire)
	if err == nil {
		t.Fatal("compact JWT accepted nonzero trailing bits")
	}
}
