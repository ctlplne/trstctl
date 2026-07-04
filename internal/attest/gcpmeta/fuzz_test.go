// SPDX-License-Identifier: MPL-2.0

package gcpmeta

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// FuzzGCPMetaAttest hardens the GCP instance-identity attester's untrusted entry
// point (Attest), which takes an attacker-supplied identity JWT and runs it through
// crypto.VerifyJWT (which base64-decodes and JSON-parses the header/payload of
// untrusted bytes) and then JSON-decodes the gcpClaims document (FUZZ-003). No
// input — random bytes, a JWT-shaped-but-garbage token, a validly-signed token, or
// a signed token whose claim fields are the wrong JSON type — may panic. Attest
// must always return cleanly (an attestation or an error). Seeded with a valid GCE
// IIT token so the corpus exercises the claim-extraction happy path too.
func FuzzGCPMetaAttest(f *testing.F) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		f.Fatal(err)
	}
	defer signer.Destroy()
	jwk, err := crypto.PublicJWK(signer.Public(), "g1")
	if err != nil {
		f.Fatal(err)
	}

	mkClaims := func() map[string]any {
		return map[string]any{
			"iss": "https://accounts.google.com",
			"aud": "trstctl",
			"exp": time.Now().Add(time.Hour).Unix(),
			"sub": "1234567890",
			"google": map[string]any{
				"compute_engine": map[string]any{
					"instance_id":   "987654321",
					"project_id":    "my-project",
					"zone":          "us-central1-a",
					"instance_name": "web-1",
				},
			},
		}
	}
	if good, err := crypto.SignJWT(signer, "g1", mkClaims()); err == nil {
		f.Add([]byte(good))
	}
	// A validly signed token whose google block is the wrong JSON shape (a string
	// where an object is expected) — exercises the claim-decode error path.
	wrong := mkClaims()
	wrong["google"] = "not-an-object"
	if tok, err := crypto.SignJWT(signer, "g1", wrong); err == nil {
		f.Add([]byte(tok))
	}
	// A validly signed token with a deeply nested / oversized field.
	big := mkClaims()
	big["padding"] = string(make([]byte, 4096))
	if tok, err := crypto.SignJWT(signer, "g1", big); err == nil {
		f.Add([]byte(tok))
	}

	f.Add([]byte(nil))
	f.Add([]byte("not a jwt"))
	f.Add([]byte("aaa.bbb.ccc"))               // three base64-ish but invalid segments
	f.Add([]byte("eyJhbGciOiJFUzI1NiJ9..sig")) // header only, empty payload
	f.Add([]byte("{\"google\":{\"compute_engine\":{}}}"))

	a := &Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Issuer: "https://accounts.google.com", Audience: "trstctl"}
	f.Fuzz(func(t *testing.T, payload []byte) {
		// Only the absence of a panic is asserted; a forged, malformed, or
		// wrong-shaped token legitimately returns an error.
		_, _ = a.Attest(context.Background(), payload)
	})
}
