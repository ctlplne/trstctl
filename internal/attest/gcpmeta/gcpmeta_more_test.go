package gcpmeta

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestGCPProjectAllowlistAndWrongIssuer(t *testing.T) {
	signer, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer signer.Destroy()
	jwk, _ := crypto.PublicJWK(signer.Public(), "g1")
	good := buildToken(t, signer, "g1", nil) // project my-project

	// Project not on the allowlist.
	a := &Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Issuer: "https://accounts.google.com", Audience: "trstctl", AllowedProjects: map[string]bool{"other-project": true}}
	if _, err := a.Attest(context.Background(), []byte(good)); err == nil {
		t.Error("project not on the allowlist accepted")
	}
	// Wrong issuer.
	a2 := &Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Issuer: "https://evil.example"}
	if _, err := a2.Attest(context.Background(), []byte(good)); err == nil {
		t.Error("wrong issuer accepted")
	}
}
