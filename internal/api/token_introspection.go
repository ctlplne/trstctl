// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Token introspection (RFC 7662, M4-L3). An opaque access token the exchange
// issued for an audience in protocols.spiffe.opaque_token_audiences says
// nothing to the resource server that receives it; the resource server posts
// it here with its own trstctl API token (issuers:read) and learns whether it
// is active and, if so, its subject, client, audience, scope and expiry.

// TokenIntrospection is RFC 7662's answer: active, and the token's claims
// only when it is.
type TokenIntrospection struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	Iss       string   `json:"iss,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	JTI       string   `json:"jti,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
}

// TokenIntrospector opens a tenant's opaque access token. A token that is not
// one of the tenant's, was altered or has expired is inactive, never an error.
type TokenIntrospector interface {
	IntrospectAccessToken(ctx context.Context, tenantID string, token []byte) (TokenIntrospection, error)
}

// WithTokenIntrospector serves POST /api/v1/workloads/tokens/introspect.
func WithTokenIntrospector(i TokenIntrospector) Option {
	return func(c *config) { c.tokenIntrospector = i }
}

const tokenIntrospectionMaxBody = 16 << 10

func (a *API) tokenIntrospectionRoute() route {
	return route{method: "POST", path: "/api/v1/workloads/tokens/introspect", opID: "introspectWorkloadToken",
		summary:   "Introspect an opaque access token the token exchange issued (RFC 7662): whether it is active and, if so, its subject, client, audience, scope and expiry",
		handler:   a.introspectWorkloadToken,
		reqSchema: "TokenIntrospectionRequest", reqContentType: "application/x-www-form-urlencoded",
		resSchema: "TokenIntrospection", successCode: "200", perm: authz.IssuersRead}
}

func (a *API) introspectWorkloadToken(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.tokenIntrospector == nil {
		a.writeError(w, errStatus(http.StatusNotFound, "token introspection is not served here: the token exchange issues no opaque access tokens"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, tokenIntrospectionMaxBody)
	if err := r.ParseForm(); err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "the request must be a form of at most 16 KiB"))
		return
	}
	token := []byte(strings.TrimSpace(r.PostForm.Get("token")))
	defer secret.Wipe(token)
	if len(token) == 0 {
		a.writeError(w, errStatus(http.StatusBadRequest, "token is required"))
		return
	}
	out, err := a.tokenIntrospector.IntrospectAccessToken(r.Context(), tenantID, token)
	if err != nil {
		a.writeError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	a.writeJSON(w, http.StatusOK, out)
}

func tokenIntrospectionSchemas() map[string]*Schema {
	str := func() *Schema { return &Schema{Type: "string"} }
	return map[string]*Schema{
		"TokenIntrospectionRequest": {Type: "object", Properties: map[string]*Schema{
			"token":           {Type: "string", Description: "the opaque access token a workload presented"},
			"token_type_hint": {Type: "string", Description: "optional; access_token"},
		}, Required: []string{"token"}},
		"TokenIntrospection": {Type: "object", Properties: map[string]*Schema{
			"active":     {Type: "boolean", Description: "false for a token that is not this tenant's, was altered or has expired; the other fields appear only when true"},
			"scope":      str(),
			"client_id":  {Type: "string", Description: "the workload's SPIFFE ID"},
			"sub":        {Type: "string", Description: "the workload's SPIFFE ID"},
			"aud":        {Type: "array", Items: str()},
			"iss":        {Type: "string", Description: "the tenant's published issuer"},
			"exp":        {Type: "integer"},
			"iat":        {Type: "integer"},
			"jti":        str(),
			"token_type": {Type: "string", Description: "Bearer"},
		}, Required: []string{"active"}},
	}
}
