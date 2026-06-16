package k8ssat

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestK8sRejectsWrongIssuerAndMissingServiceAccount(t *testing.T) {
	signer, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer signer.Destroy()
	jwk, _ := crypto.PublicJWK(signer.Public(), "k1")
	a := &Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Issuer: "https://kubernetes.default.svc", Audience: "trstctl"}

	wrongIss := satToken(t, signer, "k1", func(c map[string]any) { c["iss"] = "https://evil" })
	if _, err := a.Attest(context.Background(), []byte(wrongIss)); err == nil {
		t.Error("wrong issuer accepted")
	}
	noSA := satToken(t, signer, "k1", func(c map[string]any) {
		c["kubernetes.io"] = map[string]any{"namespace": "default"} // no serviceaccount
	})
	if _, err := a.Attest(context.Background(), []byte(noSA)); err == nil {
		t.Error("token missing serviceaccount accepted")
	}
}
