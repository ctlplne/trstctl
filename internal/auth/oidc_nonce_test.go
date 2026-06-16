package auth_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// TestOIDCNonceIsMandatory closes the replay window the audit flagged: the
// verifier must reject an id_token unless a non-empty expected nonce is supplied
// AND matches the token's nonce. An empty expected nonce (the old skip path) is
// itself a rejection.
func TestOIDCNonceIsMandatory(t *testing.T) {
	sk, err := jose.GenerateRSASigningKey("idp-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	v := auth.OIDCVerifier{Issuer: testIssuer, ClientID: testClientID, Keys: sk.JWKS(), Now: func() time.Time { return now }}

	withNonce := idToken(t, sk, map[string]any{
		"iss": testIssuer, "aud": testClientID, "sub": "u", "nonce": "n-abc",
		"exp": now.Add(time.Hour).Unix(),
	})
	// An empty expected nonce must NOT skip the check — it is a rejection.
	if _, err := v.Verify(withNonce, ""); err == nil {
		t.Error("Verify accepted a token with an empty expected nonce (replay window must be closed)")
	}
	// A correct, non-empty nonce still verifies.
	if _, err := v.Verify(withNonce, "n-abc"); err != nil {
		t.Errorf("Verify rejected a correct nonce: %v", err)
	}
	// A token with no nonce claim is rejected even when a nonce is expected.
	noNonce := idToken(t, sk, map[string]any{
		"iss": testIssuer, "aud": testClientID, "sub": "u",
		"exp": now.Add(time.Hour).Unix(),
	})
	if _, err := v.Verify(noNonce, "n-abc"); err == nil {
		t.Error("Verify accepted a token carrying no nonce")
	}
}
