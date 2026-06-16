package githuboidc

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func TestGitHubRejectsExpiredWrongIssuerMissingRepo(t *testing.T) {
	signer, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer signer.Destroy()
	jwk, _ := crypto.PublicJWK(signer.Public(), "gh1")
	a := &Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Audience: "trstctl"}

	expired := ghToken(t, signer, "gh1", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() })
	if _, err := a.Attest(context.Background(), []byte(expired)); err == nil {
		t.Error("expired token accepted")
	}
	wrongIss := ghToken(t, signer, "gh1", func(c map[string]any) { c["iss"] = "https://evil.example" })
	if _, err := a.Attest(context.Background(), []byte(wrongIss)); err == nil {
		t.Error("wrong issuer accepted")
	}
	noRepo := ghToken(t, signer, "gh1", func(c map[string]any) { delete(c, "repository") })
	if _, err := a.Attest(context.Background(), []byte(noRepo)); err == nil {
		t.Error("token missing repository accepted")
	}
	wrongAud := ghToken(t, signer, "gh1", func(c map[string]any) { c["aud"] = "someone-else" })
	if _, err := a.Attest(context.Background(), []byte(wrongAud)); err == nil {
		t.Error("wrong audience accepted")
	}
}
