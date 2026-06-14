package authmethod

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/crypto"
)

func TestTokenMethodLoginAndReject(t *testing.T) {
	secret := []byte("s3cret")
	mac := hex.EncodeToString(crypto.HMACSHA256(secret, []byte("app1")))
	rec := &auditsink.Recorder{}
	m, _ := New(Config{TenantID: "t1", Audit: rec, Methods: []Method{
		TokenMethod{Secret: secret, Scopes: map[string][]string{"app1": {"read:db"}}},
	}})
	sess, err := m.Login(context.Background(), "token", []byte("app1."+mac))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if sess.TenantID != "t1" || sess.Principal != "app1" || len(sess.Scopes) != 1 {
		t.Errorf("session = %+v", sess)
	}
	if _, err := m.Login(context.Background(), "token", []byte("app1.deadbeef")); err == nil {
		t.Error("invalid token MAC accepted")
	}
	if rec.Count("auth.rejected") != 1 || rec.Count("auth.session.issued") != 1 {
		t.Error("auth events not audited as expected")
	}
}

func TestOIDCMethodLoginAndReject(t *testing.T) {
	signer, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer signer.Destroy()
	jwk, _ := crypto.PublicJWK(signer.Public(), "k1")
	jwks := crypto.JWKS{Keys: []crypto.JWK{jwk}}
	tok, _ := crypto.SignJWT(signer, "k1", map[string]any{
		"iss": "https://idp", "aud": "trustctl", "sub": "svc-1",
		"exp": time.Now().Add(time.Hour).Unix(), "scopes": []string{"read"},
	})
	m, _ := New(Config{TenantID: "t1", Methods: []Method{OIDCMethod{JWKS: jwks, Issuer: "https://idp", Audience: "trustctl"}}})
	sess, err := m.Login(context.Background(), "oidc", []byte(tok))
	if err != nil {
		t.Fatalf("OIDC login: %v", err)
	}
	if sess.Principal != "svc-1" {
		t.Errorf("principal = %q", sess.Principal)
	}
	attacker, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer attacker.Destroy()
	forged, _ := crypto.SignJWT(attacker, "k1", map[string]any{"iss": "https://idp", "aud": "trustctl", "sub": "evil", "exp": time.Now().Add(time.Hour).Unix()})
	if _, err := m.Login(context.Background(), "oidc", []byte(forged)); err == nil {
		t.Error("forged OIDC token accepted")
	}
}

func TestUnknownMethodRejected(t *testing.T) {
	m, _ := New(Config{TenantID: "t1"})
	if _, err := m.Login(context.Background(), "nope", nil); err == nil {
		t.Error("unknown method accepted")
	}
}
