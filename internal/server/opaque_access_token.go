// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/tenantseal"
)

// Opaque access tokens (M4-L3). For an audience in
// protocols.spiffe.opaque_token_audiences the exchange's access token is a
// reference instead of a JWT: the token's claims sealed under the tenant's
// own key (the tenant key domain every tenant-owned secret uses), so nothing
// is stored and only this tenant's introspection opens it. The resource
// server posts it to POST /api/v1/workloads/tokens/introspect (RFC 7662).

// opaqueAccessTokenPrefix marks an opaque access token.
const opaqueAccessTokenPrefix = "trsto_" // #nosec G101 -- a token prefix, not a credential (CWE-798)

// opaqueAccessTokenMaxEncoded bounds an introspected token before decoding.
const opaqueAccessTokenMaxEncoded = 8 << 10

// opaqueAccessTokenClaims are what an opaque access token carries, sealed.
type opaqueAccessTokenClaims struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	ClientID string   `json:"client_id"`
	Aud      []string `json:"aud"`
	Scope    string   `json:"scope,omitempty"`
	Iat      int64    `json:"iat"`
	Exp      int64    `json:"exp"`
	JTI      string   `json:"jti"`
}

// opaqueAccessTokenAAD binds a sealed token to its purpose and tenant, so no
// other value sealed under the tenant's key opens as a token.
func opaqueAccessTokenAAD(tenantID string) []byte {
	return []byte("trstctl.opaque-access-token.v1\x00" + tenantID)
}

// opaqueAccessTokenFor reports whether an access token for audience is
// opaque: every audience is listed. A request mixing listed audiences with
// others is refused, since one token cannot be both.
func opaqueAccessTokenFor(sp *spiffeProtocol, issued string, audience []string) (bool, error) {
	if issued != tokenTypeAccessToken || len(sp.opaqueAudiences) == 0 {
		return false, nil
	}
	listed := 0
	for _, aud := range audience {
		if sp.opaqueAudiences[aud] {
			listed++
		}
	}
	switch listed {
	case 0:
		return false, nil
	case len(audience):
		return true, nil
	default:
		return false, oauthFail(http.StatusBadRequest, "invalid_target",
			"an audience that takes opaque access tokens cannot share a token with others; ask for it on its own")
	}
}

// sealOpaqueAccessToken seals claims under the tenant's key, under the same
// tenant service checks that sign its JWTs.
func (s *Server) sealOpaqueAccessToken(ctx context.Context, sp *spiffeProtocol, tenantID string, claims opaqueAccessTokenClaims) (string, error) {
	if s.tenantCrypto == nil {
		return "", oauthFail(http.StatusServiceUnavailable, "temporarily_unavailable",
			"opaque access tokens are sealed under the tenant's key, and this control plane has no tenant key domain (configure the credential-store KEK)")
	}
	ctx, release, err := sp.issuer.work.Begin(ctx, tenantID)
	if err != nil {
		return "", err
	}
	defer release()
	if err := sp.issuer.check.Check(ctx, tenantID); err != nil {
		return "", err
	}
	plain, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(plain)
	var sealed []byte
	if err := s.tenantCrypto.WithTenant(ctx, tenantID, func(c tenantseal.Cipher) error {
		var sealErr error
		sealed, sealErr = c.Seal(plain, opaqueAccessTokenAAD(tenantID))
		return sealErr
	}); err != nil {
		return "", err
	}
	return opaqueAccessTokenPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// IntrospectAccessToken implements api.TokenIntrospector: a token this
// tenant's key does not open, or one that has expired, is inactive.
func (s *Server) IntrospectAccessToken(ctx context.Context, tenantID string, token []byte) (api.TokenIntrospection, error) {
	inactive := api.TokenIntrospection{Active: false}
	encoded, ok := bytes.CutPrefix(token, []byte(opaqueAccessTokenPrefix))
	if !ok || len(encoded) == 0 || len(encoded) > opaqueAccessTokenMaxEncoded || s.tenantCrypto == nil {
		return inactive, nil
	}
	sealed := make([]byte, base64.RawURLEncoding.DecodedLen(len(encoded)))
	n, err := base64.RawURLEncoding.Decode(sealed, encoded)
	if err != nil {
		return inactive, nil
	}
	var claims opaqueAccessTokenClaims
	opened := false
	if err := s.tenantCrypto.WithTenant(ctx, tenantID, func(c tenantseal.Cipher) error {
		plain, openErr := c.Open(sealed[:n], opaqueAccessTokenAAD(tenantID))
		if openErr != nil {
			return nil // another tenant's, altered, or not a token: inactive
		}
		defer secret.Wipe(plain)
		opened = json.Unmarshal(plain, &claims) == nil && claims.Exp > 0
		return nil
	}); err != nil {
		return api.TokenIntrospection{}, err
	}
	if !opened || time.Now().Unix() >= claims.Exp {
		return inactive, nil
	}
	return api.TokenIntrospection{
		Active: true, Scope: claims.Scope, ClientID: claims.ClientID, Sub: claims.Sub, Aud: claims.Aud,
		Iss: claims.Iss, Exp: claims.Exp, Iat: claims.Iat, JTI: claims.JTI, TokenType: "Bearer",
	}, nil
}

// opaqueTokenAudiences lists protocols.spiffe.opaque_token_audiences.
func (s *Server) opaqueTokenAudiences() []string {
	sp := s.spiffeForExchange()
	out := []string{}
	if sp == nil {
		return out
	}
	for aud := range sp.opaqueAudiences {
		out = append(out, aud)
	}
	slices.Sort(out)
	return out
}
