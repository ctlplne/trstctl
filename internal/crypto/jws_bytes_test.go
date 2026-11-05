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
