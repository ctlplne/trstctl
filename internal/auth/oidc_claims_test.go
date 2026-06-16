package auth_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// TestOIDCVerifierExtractsTenantClaim: when a tenant claim is configured, Verify
// surfaces its value (and groups) into Claims so the served login can map the user
// to a tenant (TENANT-004). The JWT is parsed once, inside Verify (AN-3).
func TestOIDCVerifierExtractsTenantClaim(t *testing.T) {
	sk, err := jose.GenerateRSASigningKey("idp-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	v := auth.OIDCVerifier{
		Issuer: testIssuer, ClientID: testClientID, Keys: sk.JWKS(),
		Now:         func() time.Time { return now },
		TenantClaim: "tenant",
		GroupsClaim: "groups",
	}
	raw := idToken(t, sk, map[string]any{
		"iss": testIssuer, "aud": testClientID, "sub": "user-9", "nonce": "n",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"tenant": "acme-corp",
		"groups": []string{"platform-eng", "oncall"},
	})
	claims, err := v.Verify(raw, "n")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Tenant != "acme-corp" {
		t.Errorf("Tenant = %q, want acme-corp", claims.Tenant)
	}
	if len(claims.Groups) != 2 || claims.Groups[0] != "platform-eng" {
		t.Errorf("Groups = %v, want [platform-eng oncall]", claims.Groups)
	}
}

// TestOIDCVerifierTemporalValidity exercises nbf/iat (GAP-002/003): a token whose
// nbf is in the future, or whose iat is implausibly ahead of now, is rejected; a
// token within the clock-skew leeway is accepted.
func TestOIDCVerifierTemporalValidity(t *testing.T) {
	sk, _ := jose.GenerateRSASigningKey("idp-1")
	now := time.Unix(1_700_000_000, 0)
	v := auth.OIDCVerifier{Issuer: testIssuer, ClientID: testClientID, Keys: sk.JWKS(), Now: func() time.Time { return now }}

	base := map[string]any{"iss": testIssuer, "aud": testClientID, "sub": "u", "nonce": "n", "exp": now.Add(time.Hour).Unix()}

	// nbf far in the future -> rejected.
	nbfFuture := cloneClaims(base)
	nbfFuture["nbf"] = now.Add(time.Hour).Unix()
	if _, err := v.Verify(idToken(t, sk, nbfFuture), "n"); err == nil {
		t.Error("Verify accepted a token whose nbf is in the future")
	}

	// iat far in the future -> rejected (a forged/mis-clocked issuer).
	iatFuture := cloneClaims(base)
	iatFuture["iat"] = now.Add(time.Hour).Unix()
	if _, err := v.Verify(idToken(t, sk, iatFuture), "n"); err == nil {
		t.Error("Verify accepted a token issued in the future (iat)")
	}

	// nbf just past (valid), iat = now -> accepted.
	valid := cloneClaims(base)
	valid["nbf"] = now.Add(-time.Minute).Unix()
	valid["iat"] = now.Unix()
	if _, err := v.Verify(idToken(t, sk, valid), "n"); err != nil {
		t.Errorf("Verify rejected a temporally-valid token: %v", err)
	}

	// missing exp -> rejected.
	noExp := map[string]any{"iss": testIssuer, "aud": testClientID, "sub": "u", "nonce": "n"}
	if _, err := v.Verify(idToken(t, sk, noExp), "n"); err == nil {
		t.Error("Verify accepted a token with no exp")
	}
}

func cloneClaims(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
