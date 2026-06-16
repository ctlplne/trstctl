package githuboidc

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
)

func ghToken(t *testing.T, signer crypto.DigestSigner, kid string, mut func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{
		"iss":                DefaultIssuer,
		"aud":                "trstctl",
		"exp":                time.Now().Add(time.Hour).Unix(),
		"sub":                "repo:acme/widgets:ref:refs/heads/main",
		"repository":         "acme/widgets",
		"repository_owner":   "acme",
		"workflow":           "release",
		"ref":                "refs/heads/main",
		"sha":                "deadbeef",
		"job_workflow_ref":   "acme/widgets/.github/workflows/release.yml@refs/heads/main",
		"runner_environment": "github-hosted",
	}
	if mut != nil {
		mut(claims)
	}
	tok, err := crypto.SignJWT(signer, kid, claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestGitHubOIDCConformsAndMapsFulcio(t *testing.T) {
	signer, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer signer.Destroy()
	jwk, _ := crypto.PublicJWK(signer.Public(), "gh1")
	a := &Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Audience: "trstctl"}

	good := ghToken(t, signer, "gh1", nil)
	attacker, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer attacker.Destroy()
	forged := ghToken(t, attacker, "gh1", nil)
	if err := attest.Conform(a, []byte(good), []byte(forged)); err != nil {
		t.Fatalf("Conform: %v", err)
	}
	att, err := a.Attest(context.Background(), []byte(good))
	if err != nil {
		t.Fatal(err)
	}
	fb := FulcioBindingFrom(att)
	if fb.Issuer != DefaultIssuer {
		t.Errorf("fulcio issuer = %q", fb.Issuer)
	}
	if fb.SAN != "acme/widgets/.github/workflows/release.yml@refs/heads/main" {
		t.Errorf("fulcio SAN = %q", fb.SAN)
	}
}

func TestGitHubOIDCOwnerAllowlist(t *testing.T) {
	signer, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer signer.Destroy()
	jwk, _ := crypto.PublicJWK(signer.Public(), "gh1")
	a := &Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Audience: "trstctl", AllowedOwners: map[string]bool{"trusted-org": true}}
	tok := ghToken(t, signer, "gh1", nil) // owner "acme" not allowed
	if _, err := a.Attest(context.Background(), []byte(tok)); err == nil {
		t.Error("attested a repository owner not on the allowlist")
	}
}
