// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"

	"trstctl.com/trstctl/internal/authz"
)

// OIDCIssuerInfo is a tenant's published OpenID issuer (N5): the issuer URL a
// cloud registers (AWS IAM OIDC identity provider, Google workload identity
// pool provider, Azure federated identity credential), its discovery document
// and key set, the signing algorithms, and where workloads exchange a platform
// token for one this issuer signs.
type OIDCIssuerInfo struct {
	Issuer               string   `json:"issuer"`
	DiscoveryURL         string   `json:"discovery_url"`
	JWKSURI              string   `json:"jwks_uri"`
	Algorithms           []string `json:"algorithms"`
	TokenEndpoint        string   `json:"token_endpoint"`
	TokenLifetimeSeconds int      `json:"token_lifetime_seconds"`
}

// OIDCIssuerSource reports the tenant's published issuer; ok is false when the
// control plane publishes none.
type OIDCIssuerSource interface {
	OIDCIssuerFor(r *http.Request, tenantID string) (OIDCIssuerInfo, bool)
}

// WithOIDCIssuer serves GET /api/v1/workloads/oidc-issuer.
func WithOIDCIssuer(source OIDCIssuerSource) Option {
	return func(c *config) { c.oidcIssuer = source }
}

func (a *API) oidcIssuerRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/workloads/oidc-issuer", opID: "getOIDCIssuer", summary: "Show this tenant's published OpenID issuer: the URL a cloud registers to trust the tokens POST /oauth2/token exchanges, its discovery document and key set", handler: a.getOIDCIssuer, resSchema: "OIDCIssuer", successCode: "200", perm: authz.CertsRead},
	}
}

func (a *API) getOIDCIssuer(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.oidcIssuer == nil {
		a.writeError(w, errStatus(http.StatusNotFound, "this control plane publishes no OpenID issuer: set protocols.spiffe.oidc_issuer_url"))
		return
	}
	info, published := a.oidcIssuer.OIDCIssuerFor(r, tenantID)
	if !published {
		a.writeError(w, errStatus(http.StatusNotFound, "no OpenID issuer is published for this tenant: set protocols.spiffe.oidc_issuer_url; the issuer belongs to the tenant whose workloads exchange tokens (protocols.spiffe.tenant_id)"))
		return
	}
	a.writeJSON(w, http.StatusOK, info)
}

func oidcIssuerSchemas() map[string]*Schema {
	str := func() *Schema { return &Schema{Type: "string"} }
	return map[string]*Schema{
		"OIDCIssuer": {Type: "object", Properties: map[string]*Schema{
			"issuer":        {Type: "string", Description: "the issuer URL a cloud registers; exchanged tokens carry it as iss"},
			"discovery_url": str(), "jwks_uri": str(),
			"algorithms":             {Type: "array", Items: str(), Description: "the signing algorithms of the issuer's keys"},
			"token_endpoint":         {Type: "string", Description: "where a workload exchanges its platform token (RFC 8693) for one this issuer signs"},
			"token_lifetime_seconds": {Type: "integer"},
		}, Required: []string{"issuer", "discovery_url", "jwks_uri", "algorithms", "token_endpoint", "token_lifetime_seconds"}},
	}
}
