// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
)

// N5: trstctl as the OpenID issuer a cloud trusts for workload federation.
// AWS (an IAM OIDC identity provider and AssumeRoleWithWebIdentity), Google
// (workload identity federation's STS token exchange) and Azure (a federated
// identity credential) each trust an issuer URL: they fetch
// <issuer>/.well-known/openid-configuration, then its jwks_uri, and accept a
// token whose iss is that issuer and whose signature verifies. With
// protocols.spiffe.oidc_issuer_url set, each tenant has its own issuer,
// <base>/oidc/<tenant-id>, and the tokens POST /oauth2/token exchanges for that
// tenant carry it as iss. One signer-held key signs the tokens; iss is a signed
// claim the server takes from the tenant whose login method verified the
// subject token, so a cloud trust registered for one tenant's issuer never
// accepts another tenant's token. The exchange serves the SPIFFE protocol's
// tenant (protocols.spiffe.tenant_id), so that tenant's issuer is the one
// published; any other tenant has none. The documents are public, like the
// JWT bundle.

const oidcIssuerPathPrefix = "/oidc/"

// oidcIssuer is the tenant's published issuer, or "" when none is configured.
func (sp *spiffeProtocol) oidcIssuer(tenantID string) string {
	if sp == nil || sp.oidcIssuerBase == "" || tenantID == "" {
		return ""
	}
	return sp.oidcIssuerBase + oidcIssuerPathPrefix + tenantID
}

// oidcIssuerDocumentHandler serves GET /oidc/{tenant}/.well-known/openid-configuration.
func (s *Server) oidcIssuerDocumentHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer, ok := s.publishedOIDCIssuer(r.PathValue("tenant"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"jwks_uri":                              issuer + "/jwks.json",
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": s.oidcIssuerAlgorithms(r),
			"claims_supported":                      []string{"iss", "sub", "aud", "iat", "exp", "jti", "scope", "act"},
		})
	})
}

// oidcIssuerJWKSHandler serves GET /oidc/{tenant}/jwks.json: the key the
// tenant's exchanged tokens verify against.
func (s *Server) oidcIssuerJWKSHandler() http.Handler {
	jwks := s.tokenExchangeJWKSHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.publishedOIDCIssuer(r.PathValue("tenant")); !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=300")
		jwks.ServeHTTP(w, r)
	})
}

// publishedOIDCIssuer is the tenant's issuer when this control plane publishes
// one and the tenant is the one the token exchange serves.
func (s *Server) publishedOIDCIssuer(tenantID string) (string, bool) {
	sp := s.spiffeForExchange()
	if _, err := uuid.Parse(tenantID); err != nil || sp == nil || sp.oidcIssuerBase == "" || tenantID != sp.tenantID {
		return "", false
	}
	return sp.oidcIssuer(tenantID), true
}

// oidcIssuerAlgorithms names the signing algorithm of each key in the JWT
// bundle.
func (s *Server) oidcIssuerAlgorithms(r *http.Request) []string {
	sp := s.spiffeForExchange()
	if sp == nil {
		return []string{}
	}
	set, err := sp.issuer.JWTBundle(r.Context())
	if err != nil {
		return []string{}
	}
	algs := []string{}
	for _, key := range set.Keys {
		if key.Alg != "" && !slices.Contains(algs, key.Alg) {
			algs = append(algs, key.Alg)
		}
	}
	return algs
}

// OIDCIssuerFor reports the tenant's published issuer for the API (N5).
func (s *Server) OIDCIssuerFor(r *http.Request, tenantID string) (api.OIDCIssuerInfo, bool) {
	issuer, ok := s.publishedOIDCIssuer(tenantID)
	if !ok {
		return api.OIDCIssuerInfo{}, false
	}
	return api.OIDCIssuerInfo{ // #nosec G101 -- the token endpoint's path and the token lifetime, no credential (CWE-798)
		Issuer: issuer, DiscoveryURL: issuer + "/.well-known/openid-configuration", JWKSURI: issuer + "/jwks.json",
		Algorithms: s.oidcIssuerAlgorithms(r), TokenEndpoint: "/oauth2/token", TokenLifetimeSeconds: int(tokenExchangeTTL.Seconds()),
	}, true
}
