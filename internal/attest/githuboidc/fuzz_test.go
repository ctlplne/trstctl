// SPDX-License-Identifier: BUSL-1.1

package githuboidc

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/githubidentity"
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
		return
	}
	defer signer.Destroy()
	jwk, err := crypto.PublicJWK(signer.Public(), "gh1")
	if err != nil {
		f.Fatal(err)
		return
	}

	mkClaims := func() map[string]any {
		return map[string]any{
			"iss":                 DefaultIssuer,
			"aud":                 "trstctl",
			"exp":                 time.Now().Add(time.Hour).Unix(),
			"sub":                 "repo:octo/app:ref:refs/heads/main",
			"repository":          "octo/app",
			"repository_owner":    "octo",
			"repository_owner_id": "123",
			"repository_id":       "456",
			"run_id":              "47001", "run_attempt": "1",
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
	for _, field := range []string{"run_id", "run_attempt", repositoryOwnerIDClaim, repositoryIDClaim} {
		for _, invalid := range []any{nil, "", "0", "01", "+1", "1e3", "18446744073709551616", 1, true} {
			claims := mkClaims()
			if invalid == nil && (field == "run_id" || field == "run_attempt") {
				delete(claims, field)
			} else {
				claims[field] = invalid
			}
			if token, err := crypto.SignJWT(signer, "gh1", claims); err == nil {
				f.Add([]byte(token))
			}
		}
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
		att, err := a.Attest(context.Background(), payload)
		if err != nil {
			return
		}
		if !githubidentity.ValidID(att.Claims["run_id"]) || !githubidentity.ValidID(att.Claims["run_attempt"]) {
			t.Fatal("accepted proof lost its canonical signed attempt coordinates")
		}
		for _, key := range []string{repositoryOwnerIDClaim, repositoryIDClaim} {
			if id, found := att.Claims[key]; found && !githubidentity.ValidID(id) {
				t.Errorf("accepted proof retained a malformed %s", key)
			}
		}
	})
}
