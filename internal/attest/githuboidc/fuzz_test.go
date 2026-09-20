// SPDX-License-Identifier: BUSL-1.1

package githuboidc

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// FuzzGitHubOIDCAttest hardens the GitHub Actions OIDC attester's untrusted entry
// point (Attest), which takes an attacker-supplied OIDC token through
// crypto.VerifyJWT (base64+JSON parse of untrusted header/payload) and then
// JSON-decodes the ghClaims document and derives the Fulcio binding (FUZZ-003). No
// input — random bytes, a JWT-shaped-but-garbage token, a validly-signed token, or
// a signed token whose claim fields are the wrong JSON type — may panic. Attest
// must always return cleanly (an attestation or an error). Seeded with a valid
// GitHub OIDC token so the corpus exercises the claim/Fulcio happy path too.
func FuzzGitHubOIDCAttest(f *testing.F) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		f.Fatal(err)
	}
	defer signer.Destroy()
	jwk, err := crypto.PublicJWK(signer.Public(), "gh1")
	if err != nil {
		f.Fatal(err)
	}

	mkClaims := func() map[string]any {
		return map[string]any{
			"iss":              DefaultIssuer,
			"aud":              "trstctl",
			"exp":              time.Now().Add(time.Hour).Unix(),
			"sub":              "repo:octo/app:ref:refs/heads/main",
			"repository":       "octo/app",
			"repository_owner": "octo",
			"workflow":         "release",
			"ref":              "refs/heads/main",
			"sha":              "deadbeef",
			"job_workflow_ref": "octo/app/.github/workflows/release.yml@refs/heads/main",
		}
	}
	if good, err := crypto.SignJWT(signer, "gh1", mkClaims()); err == nil {
		f.Add([]byte(good))
	}
	// A validly signed token whose repository claim is the wrong JSON type.
	wrong := mkClaims()
	wrong["repository"] = []any{"not", "a", "string"}
	if tok, err := crypto.SignJWT(signer, "gh1", wrong); err == nil {
		f.Add([]byte(tok))
	}
	// Oversized field.
	big := mkClaims()
	big["workflow"] = string(make([]byte, 4096))
	if tok, err := crypto.SignJWT(signer, "gh1", big); err == nil {
		f.Add([]byte(tok))
	}

	f.Add([]byte(nil))
	f.Add([]byte("not a jwt"))
	f.Add([]byte("aaa.bbb.ccc"))
	f.Add([]byte("eyJhbGciOiJFUzI1NiJ9..sig"))
	f.Add([]byte("{\"repository\":\"octo/app\"}"))

	a := &Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Audience: "trstctl"}
	f.Fuzz(func(t *testing.T, payload []byte) {
		// Only the absence of a panic is asserted; a forged, malformed, or
		// wrong-shaped token legitimately returns an error.
		_, _ = a.Attest(context.Background(), payload)
	})
}
