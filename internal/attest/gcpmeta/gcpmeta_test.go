package gcpmeta

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
)

func buildToken(t *testing.T, signer crypto.DigestSigner, kid string, mut func(map[string]any)) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": "https://accounts.google.com",
		"aud": "trstctl",
		"exp": now.Add(time.Hour).Unix(),
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
	if mut != nil {
		mut(claims)
	}
	tok, err := crypto.SignJWT(signer, kid, claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestGCPConformsAndExtracts(t *testing.T) {
	signer, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer signer.Destroy()
	jwk, _ := crypto.PublicJWK(signer.Public(), "g1")
	a := &Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Issuer: "https://accounts.google.com", Audience: "trstctl"}

	good := buildToken(t, signer, "g1", nil)
	attacker, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer attacker.Destroy()
	forged := buildToken(t, attacker, "g1", nil)

	if err := attest.Conform(a, []byte(good), []byte(forged)); err != nil {
		t.Fatalf("Conform: %v", err)
	}
	att, err := a.Attest(context.Background(), []byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if att.Subject != "987654321" {
		t.Errorf("subject = %q", att.Subject)
	}
}

func TestGCPRejectsExpiredAndWrongAudience(t *testing.T) {
	signer, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer signer.Destroy()
	jwk, _ := crypto.PublicJWK(signer.Public(), "g1")
	a := &Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Issuer: "https://accounts.google.com", Audience: "trstctl"}

	expired := buildToken(t, signer, "g1", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() })
	if _, err := a.Attest(context.Background(), []byte(expired)); err == nil {
		t.Error("accepted an expired token")
	}
	wrongAud := buildToken(t, signer, "g1", func(c map[string]any) { c["aud"] = "someone-else" })
	if _, err := a.Attest(context.Background(), []byte(wrongAud)); err == nil {
		t.Error("accepted a token with the wrong audience")
	}
}
