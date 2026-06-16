package k8ssat

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
)

func satToken(t *testing.T, signer crypto.DigestSigner, kid string, mut func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{
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
	if mut != nil {
		mut(claims)
	}
	tok, err := crypto.SignJWT(signer, kid, claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestK8sSATConformsAndExtracts(t *testing.T) {
	signer, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer signer.Destroy()
	jwk, _ := crypto.PublicJWK(signer.Public(), "k1")
	a := &Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Issuer: "https://kubernetes.default.svc", Audience: "trstctl"}

	good := satToken(t, signer, "k1", nil)
	attacker, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer attacker.Destroy()
	forged := satToken(t, attacker, "k1", nil)
	if err := attest.Conform(a, []byte(good), []byte(forged)); err != nil {
		t.Fatalf("Conform: %v", err)
	}
	att, err := a.Attest(context.Background(), []byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if att.Subject != "ns/default/sa/web" {
		t.Errorf("subject = %q", att.Subject)
	}
}

func TestK8sSATAudienceAndNamespace(t *testing.T) {
	signer, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer signer.Destroy()
	jwk, _ := crypto.PublicJWK(signer.Public(), "k1")
	a := &Attestor{
		JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Issuer: "https://kubernetes.default.svc",
		Audience: "trstctl", AllowedNamespaces: map[string]bool{"prod": true},
	}
	// default namespace not allowed
	tok := satToken(t, signer, "k1", nil)
	if _, err := a.Attest(context.Background(), []byte(tok)); err == nil {
		t.Error("attested a namespace not on the allowlist")
	}
	// wrong audience
	wrong := satToken(t, signer, "k1", func(c map[string]any) { c["aud"] = []string{"other"} })
	if _, err := a.Attest(context.Background(), []byte(wrong)); err == nil {
		t.Error("accepted a token without the required audience")
	}
}
