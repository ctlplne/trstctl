// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// M4-L3: an RFC 9068 JWT access token carries the JOSE type "at+jwt" so a
// resource server tells it from a JWT-SVID signed by the same key; the
// signature verifies against the same key set, and a type that is not a
// media type name is refused before anything is signed.
func TestSignJWTTypedSetsTheJOSETypeM4L3(t *testing.T) {
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	claims := map[string]any{"sub": "spiffe://m4l3.test/ns/payments/sa/api", "client_id": "spiffe://m4l3.test/ns/payments/sa/api", "exp": int64(4102444800)}
	token, err := SignJWTTyped(key, "m4l3", "at+jwt", claims)
	if err != nil {
		t.Fatal(err)
	}
	header := func(tok string) map[string]string {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(strings.SplitN(tok, ".", 2)[0])
		if err != nil {
			t.Fatal(err)
		}
		var h map[string]string
		if err := json.Unmarshal(raw, &h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	if h := header(token); h["typ"] != "at+jwt" || h["alg"] != "ES256" || h["kid"] != "m4l3" {
		t.Fatalf("header = %v; want typ at+jwt, ES256, kid m4l3", h)
	}
	jwk, err := PublicJWK(key.Public(), "m4l3")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := VerifyJWT(token, JWKS{Keys: []JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if json.Unmarshal(payload, &decoded) != nil || decoded["client_id"] != claims["client_id"] {
		t.Fatalf("claims = %s", payload)
	}
	plain, err := SignJWT(key, "m4l3", claims)
	if err != nil || header(plain)["typ"] != "JWT" {
		t.Fatalf("SignJWT typ = %v %v; want JWT", header(plain), err)
	}
	for _, bad := range []string{"", "at jwt", `at"jwt`, strings.Repeat("a", 65)} {
		if _, err := SignJWTTyped(key, "m4l3", bad, claims); err == nil {
			t.Fatalf("typ %q was signed", bad)
		}
	}
}
