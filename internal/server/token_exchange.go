// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// OAuth 2.0 Token Exchange (RFC 8693, M4). A workload posts the JWT its
// platform gave it — a Kubernetes projected service-account token, a CI
// provider's id_token — to POST /oauth2/token and receives a JWT-SVID for its
// SPIFFE ID that lives five minutes, names the requested audience and carries
// the scopes its login method grants (or fewer, if it asks for fewer). The
// subject token is verified by the tenant's configured machine-login method for
// its issuer and is single-use: presenting it again is refused. The JWT-SVID is
// signed by the SPIFFE JWT key in the isolated signer, so relying parties verify
// it offline against GET /oauth2/jwks. Every exchange is recorded as
// token.exchanged.

const (
	tokenExchangeGrant   = "urn:ietf:params:oauth:grant-type:token-exchange" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	tokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"            // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	tokenTypeIDToken     = "urn:ietf:params:oauth:token-type:id_token"       // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	tokenExchangeTTL     = 5 * time.Minute
	tokenExchangeMaxBody = 64 << 10
	// tokenExchangeMaxClients bounds the per-client limiter's table (M4-L6).
	tokenExchangeMaxClients = 10000
	// tokenTypeAccessToken asks for an RFC 9068 JWT access token (M4-L3).
	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
)

type oauthError struct {
	status int
	code   string
	detail string
	// retryAfter, when set, is sent as Retry-After (M4-L2).
	retryAfter time.Duration
}

func (e *oauthError) Error() string { return e.code + ": " + e.detail }

func oauthFail(status int, code, detail string) *oauthError {
	return &oauthError{status: status, code: code, detail: detail}
}

// tokenExchangeHandler serves POST /oauth2/token.
func (s *Server) tokenExchangeHandler(methods func(string) []authmethod.Method) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		// M4-L6: each client address's requests are bounded before the
		// subject token is read, so no one client can keep the verifier busy.
		if sp := s.spiffeForExchange(); sp != nil && sp.exchangeLimiter != nil {
			if wait, ok := sp.exchangeLimiter.allow(netsec.ClientIP(r), time.Now()); !ok {
				w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "temporarily_unavailable",
					"error_description": "too many token requests from this client; retry after the Retry-After interval"})
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, tokenExchangeMaxBody)
		out, err := s.exchangeToken(r, methods)
		if err != nil {
			var oe *oauthError
			if !errors.As(err, &oe) {
				oe = oauthFail(http.StatusServiceUnavailable, "temporarily_unavailable", "the exchange could not be completed")
			}
			if oe.retryAfter > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(oe.retryAfter.Seconds()))))
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(oe.status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": oe.code, "error_description": oe.detail})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out) // #nosec G117 -- the token endpoint's response is the issued token, returned once to the caller that proved the subject token (CWE-200)
	})
}

// tokenExchangeJWKSHandler serves GET /oauth2/jwks: the public key the
// exchanged JWT-SVIDs verify against — the SPIFFE surface's tenant's, or with
// ?tenant_id= another tenant the exchange serves (M4-L5).
func (s *Server) tokenExchangeJWKSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sp := s.spiffeForExchange()
		if sp == nil {
			http.NotFound(w, r)
			return
		}
		tenantID := sp.tenantID
		if asked := r.URL.Query().Get("tenant_id"); asked != "" {
			tenantID = asked
		}
		ex := s.exchangeFor(tenantID)
		if ex == nil {
			http.NotFound(w, r)
			return
		}
		jwks, err := ex.issuer.JWTBundle(r.Context())
		if err != nil {
			http.Error(w, "the JWT bundle is unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jwks)
	})
}

func (s *Server) spiffeForExchange() *spiffeProtocol {
	if s.protocols == nil || s.protocols.spiffe == nil || s.protocols.spiffe.trustDomain == "" {
		return nil
	}
	return s.protocols.spiffe
}

type tokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
}

func (s *Server) exchangeToken(r *http.Request, methods func(string) []authmethod.Method) (tokenExchangeResponse, error) {
	if err := r.ParseForm(); err != nil {
		return tokenExchangeResponse{}, oauthFail(http.StatusBadRequest, "invalid_request", "the request must be a form")
	}
	form := r.PostForm
	if form.Get("grant_type") != tokenExchangeGrant {
		return tokenExchangeResponse{}, oauthFail(http.StatusBadRequest, "unsupported_grant_type", "only token exchange is supported")
	}
	tenantID := strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	subject := form.Get("subject_token")
	if tenantID == "" || subject == "" {
		return tokenExchangeResponse{}, oauthFail(http.StatusBadRequest, "invalid_request", "X-Tenant-ID and subject_token are required")
	}
	if t := form.Get("subject_token_type"); t != tokenTypeJWT && t != tokenTypeIDToken {
		return tokenExchangeResponse{}, oauthFail(http.StatusBadRequest, "invalid_request", "subject_token_type must be a JWT or an id_token")
	}
	issued := tokenTypeJWT
	switch t := form.Get("requested_token_type"); t {
	case "", tokenTypeJWT:
	case tokenTypeAccessToken:
		// M4-L3: an RFC 9068 JWT access token, for a resource server that
		// accepts OAuth access tokens rather than JWT-SVIDs.
		issued = tokenTypeAccessToken
	default:
		return tokenExchangeResponse{}, oauthFail(http.StatusBadRequest, "invalid_request", "requested_token_type must be a JWT or an access token")
	}
	audience := form["audience"]
	if len(audience) == 0 {
		audience = form["resource"]
	}
	if len(audience) == 0 || slices.Contains(audience, "") {
		return tokenExchangeResponse{}, oauthFail(http.StatusBadRequest, "invalid_target", "name the audience the token is for")
	}
	sp, ex := s.spiffeForExchange(), s.exchangeFor(tenantID)
	if sp == nil || ex == nil || methods == nil || s.store == nil || s.orch == nil {
		return tokenExchangeResponse{}, oauthFail(http.StatusBadRequest, "invalid_request", "token exchange is not configured for this tenant")
	}
	// An access token names its issuer (RFC 9068 requires iss), and a relying
	// party finds the issuer's keys from its published metadata.
	if issued == tokenTypeAccessToken && sp.oidcIssuer(tenantID) == "" {
		return tokenExchangeResponse{}, oauthFail(http.StatusBadRequest, "invalid_request",
			"access tokens need this tenant's published issuer: set protocols.spiffe.oidc_issuer_url")
	}
	opaque, err := opaqueAccessTokenFor(sp, issued, audience)
	if err != nil {
		return tokenExchangeResponse{}, err
	}
	method, issuer := exchangeMethodFor(methods(tenantID), []byte(subject))
	if method == nil {
		return tokenExchangeResponse{}, oauthFail(http.StatusBadRequest, "invalid_grant", "no login method trusts the subject token's issuer")
	}
	// Verify first (no single-use record yet), check the whole request, and
	// record the single use last, so a refused request never uses up the token.
	method = withReplayGuard(method, nil)
	principal, granted, err := method.Authenticate(r.Context(), []byte(subject))
	if err != nil {
		return tokenExchangeResponse{}, oauthFail(http.StatusBadRequest, "invalid_grant", "the subject token was not accepted")
	}
	scopes := granted
	if requested := strings.Fields(form.Get("scope")); len(requested) > 0 {
		scopes = nil
		for _, scope := range requested {
			if slices.Contains(granted, scope) && !slices.Contains(scopes, scope) {
				scopes = append(scopes, scope)
			}
		}
		if len(scopes) == 0 {
			return tokenExchangeResponse{}, oauthFail(http.StatusBadRequest, "invalid_scope", "none of the requested scopes is granted")
		}
	}
	key, keyExpiry, err := authmethod.UseKey([]byte(subject))
	if err != nil {
		return tokenExchangeResponse{}, oauthFail(http.StatusBadRequest, "invalid_grant", "the subject token was not accepted")
	}
	guard := machineCredentialReplayGuard{store: s.store, tenantID: tenantID, limit: s.machineCredentialUseLimit}
	var full *store.SingleUseLimitError
	if first, err := guard.FirstUse(r.Context(), method.Name(), key, keyExpiry); errors.As(err, &full) {
		// M4-L2: the tenant's single-use records are at their limit; the
		// subject token is not used up and works once older ones expire.
		oe := oauthFail(http.StatusTooManyRequests, "temporarily_unavailable",
			"this tenant's single-use token records are at their limit; retry after the Retry-After interval")
		oe.retryAfter = max(time.Until(full.RetryAt), time.Second)
		return tokenExchangeResponse{}, oe
	} else if err != nil {
		return tokenExchangeResponse{}, err
	} else if !first {
		return tokenExchangeResponse{}, oauthFail(http.StatusBadRequest, "invalid_grant", "the subject token was already used")
	}
	spiffeID := exchangeSPIFFEID(ex.trustDomain, method.Name(), principal)
	jti := uuid.NewString()
	expires := time.Now().UTC().Add(tokenExchangeTTL).Truncate(time.Second)
	claims := map[string]any{
		"jti": jti, "scope": strings.Join(scopes, " "),
		"act": map[string]any{"sub": principal, "iss": issuer},
	}
	if published := sp.oidcIssuer(tenantID); published != "" {
		// N5: the tenant's published OpenID issuer, which a cloud trusts.
		claims["iss"] = published
	}
	var token string
	switch {
	case opaque:
		// M4-L3: a reference only this tenant's key opens; the resource
		// server introspects it.
		token, err = s.sealOpaqueAccessToken(r.Context(), ex, opaqueAccessTokenClaims{
			Iss: sp.oidcIssuer(tenantID), Sub: spiffeID, ClientID: spiffeID, Aud: audience, Scope: strings.Join(scopes, " "),
			Iat: expires.Add(-tokenExchangeTTL).Unix(), Exp: expires.Unix(), JTI: jti,
		})
	case issued == tokenTypeAccessToken:
		// RFC 9068: the client is the workload itself, named by its SPIFFE ID.
		claims["client_id"] = spiffeID
		token, err = ex.issuer.SignJWTAccessToken(r.Context(), spiffeID, audience, tokenExchangeTTL, claims)
	default:
		token, err = ex.issuer.SignJWTSVIDWithClaims(r.Context(), spiffeID, audience, tokenExchangeTTL, claims)
	}
	if err != nil {
		return tokenExchangeResponse{}, err
	}
	if err := s.orch.RecordTokenExchange(r.Context(), tenantID, projections.TokenExchanged{
		Method: method.Name(), Principal: principal, SPIFFEID: spiffeID, Audience: audience, Scopes: scopes,
		JTI: jti, ExpiresAt: expires, SubjectTokenDigest: crypto.SHA256Hex([]byte(subject)), IssuedTokenType: issued, Opaque: opaque,
	}); err != nil {
		return tokenExchangeResponse{}, err
	}
	return tokenExchangeResponse{
		AccessToken: token, IssuedTokenType: issued, TokenType: "Bearer",
		ExpiresIn: int(tokenExchangeTTL / time.Second), Scope: strings.Join(scopes, " "),
	}, nil
}

// exchangeMethodFor picks the JWT-family login method whose issuer the subject
// token names. The unverified issuer only selects; the method then verifies.
func exchangeMethodFor(methods []authmethod.Method, token []byte) (authmethod.Method, string) {
	parts := bytes.Split(token, []byte("."))
	if len(parts) != 3 {
		return nil, ""
	}
	payload := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[1])))
	n, err := base64.RawURLEncoding.Decode(payload, parts[1])
	if err != nil {
		return nil, ""
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(payload[:n], &claims) != nil || claims.Iss == "" {
		return nil, ""
	}
	for _, m := range methods {
		if jwtMethodIssuer(m) == claims.Iss {
			return m, claims.Iss
		}
	}
	return nil, ""
}

func jwtMethodIssuer(m authmethod.Method) string {
	switch v := m.(type) {
	case authmethod.OIDCMethod:
		return v.Issuer
	case authmethod.JWTMethod:
		return v.Issuer
	case authmethod.KubernetesSATMethod:
		return v.Issuer
	case authmethod.GCPMethod:
		return v.Issuer
	case authmethod.AzureMethod:
		return v.Issuer
	default:
		return ""
	}
}

// withReplayGuard sets (or, with nil, clears) a method's durable single-use
// guard. The exchange verifies with none and records the use itself, last.
func withReplayGuard(m authmethod.Method, guard authmethod.ReplayGuard) authmethod.Method {
	switch v := m.(type) {
	case authmethod.OIDCMethod:
		v.Guard = guard
		return v
	case authmethod.JWTMethod:
		v.Guard = guard
		return v
	case authmethod.KubernetesSATMethod:
		v.Guard = guard
		return v
	case authmethod.GCPMethod:
		v.Guard = guard
		return v
	case authmethod.AzureMethod:
		v.Guard = guard
		return v
	default:
		return m
	}
}

// exchangeSPIFFEID is the workload's SPIFFE ID: a Kubernetes service account
// maps to /ns/<namespace>/sa/<name>; any other principal to
// /machine/<method>/<escaped principal>.
func exchangeSPIFFEID(trustDomain, method, principal string) string {
	if rest, ok := strings.CutPrefix(principal, "system:serviceaccount:"); ok {
		if ns, sa, ok := strings.Cut(rest, ":"); ok && ns != "" && sa != "" && !strings.Contains(sa, ":") {
			return "spiffe://" + trustDomain + "/ns/" + url.PathEscape(ns) + "/sa/" + url.PathEscape(sa)
		}
	}
	return "spiffe://" + trustDomain + "/machine/" + url.PathEscape(method) + "/" + url.PathEscape(principal)
}

// exchangeRequestsPerMinute is the configured per-client limit, or the default.
func exchangeRequestsPerMinute(cfg config.SPIFFEProtocol) int {
	if cfg.ExchangeRequestsPerMinute <= 0 {
		return config.DefaultExchangeRequestsPerMinute
	}
	return cfg.ExchangeRequestsPerMinute
}
