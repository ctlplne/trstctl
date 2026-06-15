// This file wires the served OIDC browser-login + session + per-user → tenant
// mapping (EXC-WIRE-01) into the control-plane composition, closing the served-vs-
// library gap behind SEC-001 / WIRE-001 / SURFACE-002 / TENANT-004 and the RED-004
// "loaded gun". Until now the OIDC code flow, id_token verification, the session
// cookie, and the tenant mapper were library-complete (internal/auth) but
// api.WithAuth was never called by the served binary — every /auth/* route 404'd
// and the browser login was dead. Build now constructs api.WithAuth from config so
// the running binary serves /auth/login → /auth/callback → an HttpOnly+SameSite
// session cookie that authorizes API calls under the SAME RBAC + RLS tenant scoping
// (AN-1) as an API token. The signer/crypto boundaries are untouched: id_token
// verification routes through internal/auth (JOSE behind AN-3) and the session HMAC
// secret is loaded as []byte, never logged.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trustctl.io/trustctl/internal/api"
	"trustctl.io/trustctl/internal/auth"
	"trustctl.io/trustctl/internal/config"
	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/crypto/jose"
)

// maxTokenResponseBytes bounds the IdP token-endpoint response we read, so a
// misbehaving/compromised endpoint cannot drive unbounded allocation.
const maxTokenResponseBytes = 1 << 20 // 1 MiB

// decodeIDToken extracts the id_token from an RFC 6749 token-endpoint JSON
// response, reading at most maxTokenResponseBytes.
func decodeIDToken(resp *http.Response) (string, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if err != nil {
		return "", fmt.Errorf("server: read oidc token response: %w", err)
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("server: decode oidc token response: %w", err)
	}
	return tr.IDToken, nil
}

// buildOIDCAuth constructs the served OIDC login option from config (EXC-WIRE-01).
// It returns (nil, nil) when OIDC is disabled — the binary then authenticates only
// with scoped API tokens, exactly as before. When enabled it fails closed: a
// misconfigured block (already rejected by config.Validate, but re-checked here so
// Build is safe to call directly) returns an error rather than a half-wired login.
//
// secure marks the session/CSRF/state cookies Secure when the control plane serves
// TLS (so a session cookie is never sent in the clear). httpClient performs the
// code→token exchange (an SSRF-bounded outbound call to the IdP token endpoint); a
// test may inject a loopback-capable client without weakening production.
func buildOIDCAuth(o config.OIDC, secure bool, httpClient *http.Client) (api.Option, error) {
	if !o.Enabled {
		return nil, nil
	}
	if err := o.ValidateEnabled(); err != nil {
		return nil, fmt.Errorf("server: OIDC login enabled but misconfigured (fail closed): %w", err)
	}

	// IdP signing keys (offline verification — no JWKS fetch on the hot path).
	keys, err := loadOIDCKeys(o)
	if err != nil {
		return nil, err
	}
	verifier := auth.OIDCVerifier{
		Issuer:      o.Issuer,
		ClientID:    o.ClientID,
		Keys:        keys,
		TenantClaim: o.TenantClaim,
		GroupsClaim: o.GroupsClaim,
	}

	// Persistent session HMAC secret: a restart must not log users out, and HA
	// replicas must verify each other's cookies (so the secret is a shared file, not
	// process-random). Held only as []byte (AN-8) and never logged.
	secret, err := loadOrCreateSessionSecret(o.SessionSecretFile)
	if err != nil {
		return nil, err
	}
	ttl, err := o.SessionTTLDuration()
	if err != nil { // already validated, but keep Build self-contained
		return nil, fmt.Errorf("server: auth.oidc.session_ttl: %w", err)
	}
	sessions := auth.NewSessionIssuer(secret, ttl)

	// Per-user → tenant mapping (TENANT-004 / RED-004): each authenticated user is
	// mapped to its real tenant; an unmapped user is rejected (fail closed). The
	// single-DefaultTenant collapse is gone.
	mapper := tenantMapperFromConfig(o)

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	cfg := api.AuthConfig{
		AuthEndpoint:  o.AuthEndpoint,
		ClientID:      o.ClientID,
		RedirectURI:   o.RedirectURI,
		DefaultTenant: o.DefaultTenant, // legacy field; applied ONLY via the mapper's AllowDefault
		DefaultRoles:  o.DefaultRoles,
		Exchange:      oidcExchange(o, httpClient),
		VerifyIDToken: verifier.Verify,
		ResolveTenant: mapper.ResolveTenant,
		Sessions:      sessions,
		LoginRedirect: o.LoginRedirect,
		Secure:        secure,
	}
	return api.WithAuth(cfg), nil
}

// tenantMapperFromConfig builds the auth.TenantMapper from the config OIDC block.
func tenantMapperFromConfig(o config.OIDC) auth.TenantMapper {
	mappings := make([]auth.TenantMapping, 0, len(o.TenantMappings))
	for _, m := range o.TenantMappings {
		mappings = append(mappings, auth.TenantMapping{
			Subject: m.Subject, Claim: m.Claim, Group: m.Group,
			TenantID: m.TenantID, Roles: m.Roles,
		})
	}
	return auth.TenantMapper{
		Mappings:      mappings,
		ClaimIsTenant: o.ClaimIsTenant,
		DefaultTenant: o.DefaultTenant,
		DefaultRoles:  o.DefaultRoles,
		AllowDefault:  o.AllowDefaultTenant,
	}
}

// loadOIDCKeys parses the IdP JWKS from the inline JSON or the file path.
func loadOIDCKeys(o config.OIDC) (*jose.JWKSet, error) {
	switch {
	case strings.TrimSpace(o.JWKSJSON) != "":
		return jose.ParseJWKSet([]byte(o.JWKSJSON))
	case strings.TrimSpace(o.JWKSFile) != "":
		data, err := os.ReadFile(o.JWKSFile)
		if err != nil {
			return nil, fmt.Errorf("server: read auth.oidc.jwks_file %q: %w", o.JWKSFile, err)
		}
		return jose.ParseJWKSet(data)
	default:
		return nil, errors.New("server: auth.oidc requires jwks_file or jwks_json")
	}
}

// oidcExchange returns the authorization-code → id_token exchange against the IdP
// token endpoint (RFC 6749 §4.1.3). It posts the code and returns the id_token from
// the response. The IdP host is the operator-configured token_endpoint (already
// validated as an absolute https URL), so this is not an attacker-chosen fetch.
func oidcExchange(o config.OIDC, client *http.Client) func(context.Context, string) (string, error) {
	return func(ctx context.Context, code string) (string, error) {
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", o.RedirectURI)
		form.Set("client_id", o.ClientID)
		if o.ClientSecret != "" {
			form.Set("client_secret", o.ClientSecret)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.TokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("server: oidc token exchange: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("server: oidc token endpoint returned %d", resp.StatusCode)
		}
		idToken, err := decodeIDToken(resp)
		if err != nil {
			return "", err
		}
		if idToken == "" {
			return "", errors.New("server: oidc token response carried no id_token")
		}
		return idToken, nil
	}
}

// loadOrCreateSessionSecret returns the HMAC secret that signs session cookies,
// persisted at path so a restart does not invalidate live sessions and HA replicas
// share one secret. It is created (0600, in a 0700 dir) with 32 bytes of CSPRNG
// output on first boot if absent. The secret is returned as []byte and is never
// logged (AN-8). Randomness routes through the crypto boundary (AN-3).
func loadOrCreateSessionSecret(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("server: auth.oidc.session_secret_file is required to persist the session secret")
	}
	switch data, err := os.ReadFile(path); {
	case err == nil:
		if len(data) < 32 {
			return nil, fmt.Errorf("server: session secret %q is too short (%d bytes); want >= 32", path, len(data))
		}
		return data, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("server: read session secret %q: %w", path, err)
	}
	secret, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("server: create session secret directory: %w", err)
		}
	}
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		return nil, fmt.Errorf("server: write session secret %q: %w", path, err)
	}
	return secret, nil
}
