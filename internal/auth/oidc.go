// Package auth implements authentication for certctl: OIDC login (UI/CLI),
// session issuance, and scoped API tokens (CI/CD). All cryptography routes
// through the internal/crypto boundary (AN-3): JWS/JWKS via internal/crypto/jose,
// hashing/RNG via internal/crypto. Nothing here is gated — every auth method is
// in the open-source build. Interactive SSO is OIDC only; SAML 2.0 is not a
// supported login method (see docs/limitations.md, "Single sign-on (OIDC only)").
package auth

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"certctl.io/certctl/internal/crypto/jose"
)

// Claims are the verified, relevant fields of an OIDC id_token.
type Claims struct {
	Subject   string
	Email     string
	Issuer    string
	Audience  string
	Nonce     string
	ExpiresAt int64
	IssuedAt  int64
}

type idTokenClaims struct {
	Iss   string `json:"iss"`
	Aud   any    `json:"aud"` // string or []string per OIDC
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Nonce string `json:"nonce"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
}

// OIDCVerifier verifies id_tokens from a configured provider.
type OIDCVerifier struct {
	Issuer   string
	ClientID string
	Keys     *jose.JWKSet
	Now      func() time.Time
}

func (v OIDCVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify checks an id_token's signature (against the provider JWKS) and its
// issuer, audience, expiry, and nonce, returning the claims.
func (v OIDCVerifier) Verify(rawIDToken, expectedNonce string) (Claims, error) {
	payload, err := v.Keys.Verify(rawIDToken)
	if err != nil {
		return Claims{}, fmt.Errorf("auth: id_token signature: %w", err)
	}
	var c idTokenClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, fmt.Errorf("auth: id_token claims: %w", err)
	}
	if c.Iss != v.Issuer {
		return Claims{}, fmt.Errorf("auth: id_token issuer %q is not %q", c.Iss, v.Issuer)
	}
	if !audienceMatches(c.Aud, v.ClientID) {
		return Claims{}, fmt.Errorf("auth: id_token audience does not include %q", v.ClientID)
	}
	if c.Exp <= v.now().Unix() {
		return Claims{}, fmt.Errorf("auth: id_token has expired")
	}
	// The nonce is mandatory: an empty expected nonce is a rejection, not a skip
	// (closing the replay window). The token must carry a nonce that matches.
	if expectedNonce == "" {
		return Claims{}, fmt.Errorf("auth: id_token verification requires a nonce")
	}
	if c.Nonce != expectedNonce {
		return Claims{}, fmt.Errorf("auth: id_token nonce mismatch")
	}
	return Claims{
		Subject: c.Sub, Email: c.Email, Issuer: c.Iss, Audience: v.ClientID,
		Nonce: c.Nonce, ExpiresAt: c.Exp, IssuedAt: c.Iat,
	}, nil
}

func audienceMatches(aud any, clientID string) bool {
	switch a := aud.(type) {
	case string:
		return a == clientID
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

// AuthCodeURL builds an OIDC authorization-code request URL for redirecting the
// user agent to the provider.
func AuthCodeURL(authEndpoint, clientID, redirectURI, state, nonce string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("nonce", nonce)
	return authEndpoint + "?" + q.Encode()
}
