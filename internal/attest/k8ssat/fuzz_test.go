// SPDX-License-Identifier: BUSL-1.1

package k8ssat

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// FuzzK8sSATAttest hardens the Kubernetes projected ServiceAccount-token attester's
// untrusted entry point (Attest), which takes an attacker-supplied SAT through
// crypto.VerifyJWT (base64+JSON parse of untrusted header/payload) and then
// JSON-decodes the k8sClaims document — including the custom audience.UnmarshalJSON
// that accepts a string or array `aud` (FUZZ-003). No input — random bytes, a
// JWT-shaped-but-garbage token, a validly-signed token, or a signed token whose
// `aud` (or another claim) is the wrong JSON type — may panic. Attest must always
// return cleanly (an attestation or an error). Seeded with a valid SAT so the corpus
// exercises the claim-extraction happy path too.
func FuzzK8sSATAttest(f *testing.F) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		f.Fatal(err)
	}
	defer signer.Destroy()
	jwk, err := crypto.PublicJWK(signer.Public(), "k1")
	if err != nil {
		f.Fatal(err)
	}

	mkClaims := func() map[string]any {
		return map[string]any{
			"iss": "https://kubernetes.default.svc",
			"aud": []string{"trstctl"},
			"exp": time.Now().Add(time.Hour).Unix(),
			"sub": "system:serviceaccount:default:web",
			"kubernetes.io": map[string]any{
				"namespace": "default",
				"serviceaccount": map[string]any{
					"name": "web",
					"uid":  "uid-1",
				},
				"pod": map[string]any{"name": "web-abc", "uid": "uid-2"},
			},
		}
	}
	if good, err := crypto.SignJWT(signer, "k1", mkClaims()); err == nil {
		f.Add([]byte(good))
	}
	// `aud` encoded as a plain string (the other branch of audience.UnmarshalJSON).
	strAud := mkClaims()
	strAud["aud"] = "trstctl"
	if tok, err := crypto.SignJWT(signer, "k1", strAud); err == nil {
		f.Add([]byte(tok))
	}
	// `aud` encoded as a NUMBER — neither a string nor a []string, so the custom
	// UnmarshalJSON must return an error rather than panic.
	numAud := mkClaims()
	numAud["aud"] = 1234
	if tok, err := crypto.SignJWT(signer, "k1", numAud); err == nil {
		f.Add([]byte(tok))
	}
	// kubernetes.io block the wrong shape.
	wrong := mkClaims()
	wrong["kubernetes.io"] = "not-an-object"
	if tok, err := crypto.SignJWT(signer, "k1", wrong); err == nil {
		f.Add([]byte(tok))
	}

	f.Add([]byte(nil))
	f.Add([]byte("not a jwt"))
	f.Add([]byte("aaa.bbb.ccc"))
	f.Add([]byte("eyJhbGciOiJFUzI1NiJ9..sig"))
	f.Add([]byte("{\"aud\":42}"))

	a := &Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Issuer: "https://kubernetes.default.svc", Audience: "trstctl"}
	f.Fuzz(func(t *testing.T, payload []byte) {
		// Only the absence of a panic is asserted; a forged, malformed, or
		// wrong-shaped token legitimately returns an error.
		_, _ = a.Attest(context.Background(), payload)
	})
}
