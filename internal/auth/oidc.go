// Package auth implements authentication for trustctl: OIDC login (UI/CLI),
// session issuance, and scoped API tokens (CI/CD). All cryptography routes
// through the internal/crypto boundary (AN-3): JWS/JWKS via internal/crypto/jose,
// hashing/RNG via internal/crypto. Nothing here is gated — every auth method is
// in the one source-available build. Interactive SSO is OIDC only; SAML 2.0 is not a
// supported login method (see docs/limitations.md, "Single sign-on (OIDC only)").
package auth

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"trustctl.io/trustctl/internal/crypto/jose"
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
	// Tenant is the value of the verifier's configured tenant claim
	// (OIDCVerifier.TenantClaim), extracted from the id_token during Verify, or ""
	// when no tenant claim is configured or the token does not carry it. It is the
	// per-user → tenant mapping input the served login uses to scope a session to the
	// right tenant (TENANT-004 / RED-004) instead of collapsing every user to one
	// DefaultTenant. The claim's value is read out of the verified payload so the JWT
	// is parsed in exactly one place (AN-3: JOSE stays behind the crypto boundary).
	Tenant string
	// Groups is the value of the verifier's configured groups claim
	// (OIDCVerifier.GroupsClaim), extracted as a string slice when present (a single
	// string is treated as a one-element slice). It lets the served login map an
	// IdP group → tenant/roles when no direct tenant claim is carried.
	Groups []string
}

type idTokenClaims struct {
	Iss   string `json:"iss"`
	Aud   any    `json:"aud"` // string or []string per OIDC
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Nonce string `json:"nonce"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	// Nbf/Jti are validated (GAP-002/003) when present; not surfaced in Claims.
	Nbf int64  `json:"nbf"`
	Jti string `json:"jti"`
}

// OIDCVerifier verifies id_tokens from a configured provider.
type OIDCVerifier struct {
	Issuer   string
	ClientID string
	Keys     *jose.JWKSet
	Now      func() time.Time
	// TenantClaim, when set, names the id_token claim whose value scopes the
	// authenticated user to a tenant (e.g. "tenant", "org_id", "https://trustctl/tenant").
	// Verify extracts it into Claims.Tenant. Empty means no tenant claim is read (the
	// caller maps by subject/groups or falls back to a default).
	TenantClaim string
	// GroupsClaim, when set, names the id_token claim carrying the user's group
	// memberships (a JSON string or array of strings), extracted into Claims.Groups
	// for an IdP-group → tenant/role mapping. Empty means groups are not read.
	GroupsClaim string
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
	now := v.now().Unix()
	// Temporal validity (GAP-002/003), with a small clock-skew leeway so a benign
	// clock difference between the IdP and trustctl does not reject a valid token:
	//   - exp: the token must not have expired (mandatory; a token with no exp is
	//     rejected because an OIDC id_token MUST carry one);
	//   - nbf: when present, the token must not be used before its not-before;
	//   - iat: when present, it must not be implausibly in the future (a token issued
	//     "later than now+leeway" indicates a forged/мis-clocked issuer).
	const leeway = 60 // seconds
	if c.Exp == 0 {
		return Claims{}, fmt.Errorf("auth: id_token missing exp")
	}
	if c.Exp+leeway <= now {
		return Claims{}, fmt.Errorf("auth: id_token has expired")
	}
	if c.Nbf != 0 && now+leeway < c.Nbf {
		return Claims{}, fmt.Errorf("auth: id_token is not yet valid (nbf)")
	}
	if c.Iat != 0 && c.Iat > now+leeway {
		return Claims{}, fmt.Errorf("auth: id_token issued in the future (iat)")
	}
	// The nonce is mandatory: an empty expected nonce is a rejection, not a skip
	// (closing the replay window). The token must carry a nonce that matches.
	if expectedNonce == "" {
		return Claims{}, fmt.Errorf("auth: id_token verification requires a nonce")
	}
	if c.Nonce != expectedNonce {
		return Claims{}, fmt.Errorf("auth: id_token nonce mismatch")
	}
	out := Claims{
		Subject: c.Sub, Email: c.Email, Issuer: c.Iss, Audience: v.ClientID,
		Nonce: c.Nonce, ExpiresAt: c.Exp, IssuedAt: c.Iat,
	}
	// Per-user → tenant mapping inputs (TENANT-004): extract the configured tenant /
	// groups claims out of the SAME verified payload (no second JWT parse, AN-3). A
	// missing claim yields the zero value, which the caller maps/rejects.
	if v.TenantClaim != "" || v.GroupsClaim != "" {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(payload, &raw); err != nil {
			return Claims{}, fmt.Errorf("auth: id_token claims: %w", err)
		}
		if v.TenantClaim != "" {
			out.Tenant = stringClaim(raw[v.TenantClaim])
		}
		if v.GroupsClaim != "" {
			out.Groups = stringsClaim(raw[v.GroupsClaim])
		}
	}
	return out, nil
}

// stringClaim decodes a JSON claim value as a string. A non-string (number,
// object, absent) yields "".
func stringClaim(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// stringsClaim decodes a JSON claim value as a slice of strings, accepting either
// a JSON array of strings or a single string (treated as a one-element slice).
func stringsClaim(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	if s := stringClaim(raw); s != "" {
		return []string{s}
	}
	return nil
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
