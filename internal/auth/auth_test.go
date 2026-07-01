package auth_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const (
	testIssuer   = "https://idp.example.com"
	testClientID = "trstctl-ui"
)

// idToken signs an OIDC id_token with the given claims using sk (simulating the
// IdP), returning the compact JWT.
func idToken(t *testing.T, sk *jose.SigningKey, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := sk.Sign(payload)
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	return tok
}

// TestOIDCLoginIssuesSession is the acceptance: a valid OIDC id_token is verified
// and exchanged for a session.
func TestOIDCLoginIssuesSession(t *testing.T) {
	sk, err := jose.GenerateRSASigningKey("idp-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	verifier := auth.OIDCVerifier{
		Issuer: testIssuer, ClientID: testClientID, Keys: sk.JWKS(),
		Now: func() time.Time { return now },
	}
	raw := idToken(t, sk, map[string]any{
		"iss": testIssuer, "aud": testClientID, "sub": "user-123",
		"email": "alice@example.com", "nonce": "n-abc",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
	})

	claims, err := verifier.Verify(raw, "n-abc")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "user-123" || claims.Email != "alice@example.com" {
		t.Errorf("claims = %+v", claims)
	}

	issuer := auth.NewSessionIssuer([]byte("0123456789abcdef0123456789abcdef"), time.Hour)
	issuer.Now = func() time.Time { return now }
	sess, err := issuer.Issue(claims.Subject, "tenant-1", claims.Email, []string{"viewer"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := issuer.Verify(sess)
	if err != nil {
		t.Fatalf("session Verify: %v", err)
	}
	if got.Subject != "user-123" || got.TenantID != "tenant-1" {
		t.Errorf("session = %+v", got)
	}
}

func TestOIDCRejectsBadToken(t *testing.T) {
	sk, _ := jose.GenerateRSASigningKey("idp-1")
	now := time.Unix(1_700_000_000, 0)
	v := auth.OIDCVerifier{Issuer: testIssuer, ClientID: testClientID, Keys: sk.JWKS(), Now: func() time.Time { return now }}

	cases := map[string]map[string]any{
		"wrong issuer":   {"iss": "https://evil", "aud": testClientID, "sub": "u", "nonce": "n", "exp": now.Add(time.Hour).Unix()},
		"wrong audience": {"iss": testIssuer, "aud": "someone-else", "sub": "u", "nonce": "n", "exp": now.Add(time.Hour).Unix()},
		"expired":        {"iss": testIssuer, "aud": testClientID, "sub": "u", "nonce": "n", "exp": now.Add(-time.Hour).Unix()},
	}
	for name, claims := range cases {
		if _, err := v.Verify(idToken(t, sk, claims), "n"); err == nil {
			t.Errorf("%s: Verify accepted an invalid id_token", name)
		}
	}
	// Wrong nonce.
	good := idToken(t, sk, map[string]any{"iss": testIssuer, "aud": testClientID, "sub": "u", "nonce": "real", "exp": now.Add(time.Hour).Unix()})
	if _, err := v.Verify(good, "expected-different"); err == nil {
		t.Error("Verify accepted a mismatched nonce")
	}
}

func TestSessionRejectsExpired(t *testing.T) {
	issuer := auth.NewSessionIssuer([]byte("0123456789abcdef0123456789abcdef"), time.Hour)
	base := time.Unix(1_700_000_000, 0)
	issuer.Now = func() time.Time { return base }
	sess, err := issuer.Issue("u", "t", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer.Now = func() time.Time { return base.Add(2 * time.Hour) } // past expiry
	if _, err := issuer.Verify(sess); err == nil {
		t.Error("Verify accepted an expired session")
	}
}

// TestAPITokenScopesBecomePrincipal is the acceptance core for scope enforcement:
// an API token's scopes resolve to a principal that can do exactly those actions.
func TestAPITokenScopesBecomePrincipal(t *testing.T) {
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || hash == "" {
		t.Fatal("empty token or hash")
	}
	if !bytes.HasPrefix(raw, []byte(auth.TokenPrefix)) {
		t.Fatalf("raw token %q does not carry prefix %q", raw, auth.TokenPrefix)
	}
	// The hash is derived deterministically from the raw token for lookup.
	if h, _ := auth.HashAPIToken(raw); h != hash {
		t.Errorf("HashAPIToken(raw) = %q, want %q", h, hash)
	}
	rawCopy := append([]byte(nil), raw...)
	secret.Wipe(raw)
	if bytes.Contains(raw, []byte(auth.TokenPrefix)) {
		t.Fatalf("wiped raw token still contains prefix bytes: %q", raw)
	}
	if h, _ := auth.HashAPIToken(rawCopy); h != hash {
		t.Errorf("HashAPIToken(rawCopy) after wipe = %q, want %q", h, hash)
	}
	secret.Wipe(rawCopy)

	tok := auth.APIToken{TenantID: "tenant-1", Subject: "ci-bot", Scopes: []string{"identities:read"}}
	p := tok.Principal()
	if p.TenantID != "tenant-1" || p.Subject != "ci-bot" {
		t.Errorf("principal = %+v", p)
	}
	scope := authz.Scope{TenantID: "tenant-1"}
	if !p.Can(authz.IdentitiesRead, scope) {
		t.Error("read-scoped token must be allowed identities:read")
	}
	if p.Can(authz.IdentitiesWrite, scope) {
		t.Error("read-scoped token must be denied identities:write")
	}
}
