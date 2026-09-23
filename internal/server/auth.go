// SPDX-License-Identifier: BUSL-1.1

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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// maxTokenResponseBytes bounds the IdP token-endpoint response we read, so a
// misbehaving/compromised endpoint cannot drive unbounded allocation.
const maxTokenResponseBytes = 1 << 20 // 1 MiB

type oidcClientSecretSource func(context.Context) ([]byte, error)

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
	cfg, err := buildOIDCAuthConfig(o, secure, httpClient, nil, nil)
	if err != nil || cfg == nil {
		return nil, err
	}
	return api.WithAuth(*cfg), nil
}

func buildBrowserAuth(d Deps) ([]api.Option, error) {
	if err := requireTenantAuthAttachment(d); err != nil {
		return nil, err
	}
	oidcCfg, err := buildOIDCAuthConfig(d.OIDC, d.SecurityHeaders.TLS, d.AuthHTTPClient, d.Store, d.KEK, d.TenantCrypto)
	if err != nil {
		return nil, err
	}
	var extra editionseam.TenantAuthConfig
	if d.TenantAuthFactory != nil {
		extra, err = d.TenantAuthFactory(editionseam.TenantAuthDeps{
			SAML: d.SAML, LDAP: d.LDAP, SCIM: d.SCIM, Secure: d.SecurityHeaders.TLS,
			NewSessionIssuer: func(secret []byte, ttl time.Duration) *auth.SessionIssuer {
				return newBrowserSessionIssuer(secret, ttl, d.Store)
			},
		})
		if err != nil {
			return nil, err
		}
	}
	base := oidcCfg
	if base == nil {
		base = extra.SAML
	} else if extra.SAML != nil {
		mergeSAMLAuthConfig(base, extra.SAML)
	}
	if base == nil {
		base = extra.LDAP
	} else if extra.LDAP != nil {
		mergeLDAPAuthConfig(base, extra.LDAP)
	}
	var options []api.Option
	if base != nil {
		options = append(options, api.WithAuth(*base))
	}
	if extra.SCIM != nil {
		options = append(options, api.WithSCIM(*extra.SCIM))
	}
	return options, nil
}

func buildOIDCAuthConfig(o config.OIDC, secure bool, httpClient *http.Client, st *store.Store, kek sealKeyWrapper, tenantCrypto ...tenantseal.Access) (*api.AuthConfig, error) {
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
	logoutVerifier := auth.OIDCLogoutVerifier{
		Issuer: o.Issuer, ClientID: o.ClientID, Keys: keys, Replay: auth.NewLogoutReplayCache(),
	}

	// Persistent session HMAC secret: a restart must not log users out, and HA
	// replicas must verify each other's cookies (so the secret is a shared file, not
	// process-random). Held only as []byte (AN-8) and never logged.
	secret, err := loadOrCreateNamedSessionSecret("auth.oidc.session_secret_file", o.SessionSecretFile)
	if err != nil {
		return nil, err
	}
	ttl, err := o.SessionTTLDuration()
	if err != nil { // already validated, but keep Build self-contained
		return nil, fmt.Errorf("server: auth.oidc.session_ttl: %w", err)
	}
	sessions := newBrowserSessionIssuer(secret, ttl, st)

	// Per-user → tenant mapping (TENANT-004 / RED-004): each authenticated user is
	// mapped to its real tenant; an unmapped user is rejected (fail closed). The
	// single-DefaultTenant collapse is gone.
	mapper := tenantMapperFromConfig(o)

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	secretSource, err := buildOIDCClientSecretSource(o, st, kek, tenantCrypto...)
	if err != nil {
		return nil, err
	}
	cfg := &api.AuthConfig{
		OIDCEnabled:                            o.Enabled,
		Issuer:                                 o.Issuer,
		AuthEndpoint:                           o.AuthEndpoint,
		ClientID:                               o.ClientID,
		RedirectURI:                            o.RedirectURI,
		AuthorizationResponseIssParamSupported: o.AuthorizationResponseIssParamSupported,
		DefaultTenant:                          o.DefaultTenant, // legacy field; applied ONLY via the mapper's AllowDefault
		DefaultRoles:                           o.DefaultRoles,
		TenantClaim:                            o.TenantClaim,
		GroupsClaim:                            o.GroupsClaim,
		ClaimIsTenant:                          o.ClaimIsTenant,
		TenantMappings:                         authMappingsForAPI(o),
		AllowDefaultTenant:                     o.AllowDefaultTenant,
		Exchange:                               oidcExchange(o, httpClient, secretSource),
		VerifyIDToken:                          verifier.Verify,
		VerifyOIDCLogoutToken:                  logoutVerifier.Verify,
		ResolveTenant:                          mapper.ResolveTenant,
		Sessions:                               sessions,
		LoginRedirect:                          o.LoginRedirect,
		Secure:                                 secure,
	}
	return cfg, nil
}

func buildOIDCClientSecretSource(o config.OIDC, st *store.Store, kek sealKeyWrapper, tenantCrypto ...tenantseal.Access) (oidcClientSecretSource, error) {
	if strings.TrimSpace(o.ClientSecretRef) == "" {
		return nil, nil
	}
	if st == nil {
		return nil, errors.New("server: auth.oidc.client_secret_ref requires a credential store")
	}
	if kek == nil {
		return nil, errors.New("server: auth.oidc.client_secret_ref requires a credential KEK")
	}
	var access tenantseal.Access
	if len(tenantCrypto) > 0 {
		access = tenantCrypto[0]
	}
	tenantID := strings.TrimSpace(o.ClientSecretTenant)
	ref := strings.TrimSpace(o.ClientSecretRef)
	return func(ctx context.Context) ([]byte, error) {
		var plaintext []byte
		err := withTenantCipher(ctx, access, kek, tenantID, func(scoped context.Context, cipher tenantseal.Cipher) (err error) {
			record, err := st.GetCredential(scoped, tenantID, auth.OIDCClientSecretScope, ref, auth.OIDCClientSecretName)
			if err != nil {
				return err
			}
			plaintext, err = cipher.Open(record.Sealed, oidcClientSecretAAD(tenantID, ref))
			return err
		})
		if err != nil {
			secret.Wipe(plaintext)
			return nil, err
		}
		return plaintext, nil
	}, nil
}

func oidcClientSecretAAD(tenantID, ref string) []byte {
	// Keep this exact wire scope compatible with internal/secrets.Vault. The
	// tenant cipher owns the open after migration; a deployment-only Vault cannot.
	return []byte(tenantID + "/" + auth.OIDCClientSecretScope + "/" + ref + "/" + auth.OIDCClientSecretName)
}

func mergeSAMLAuthConfig(dst, src *api.AuthConfig) {
	dst.SAMLEnabled = src.SAMLEnabled
	dst.SAMLLoginRedirect = src.SAMLLoginRedirect
	dst.VerifySAMLResponse = src.VerifySAMLResponse
	dst.ResolveSAMLTenant = src.ResolveSAMLTenant
	dst.SAMLMetadata = src.SAMLMetadata
	if dst.LoginRedirect == "" {
		dst.LoginRedirect = src.LoginRedirect
	}
	if dst.Sessions == nil {
		dst.Sessions = src.Sessions
	}
}

func mergeLDAPAuthConfig(dst, src *api.AuthConfig) {
	dst.LDAPEnabled = src.LDAPEnabled
	dst.VerifyLDAPLogin = src.VerifyLDAPLogin
	dst.ResolveLDAPTenant = src.ResolveLDAPTenant
	if dst.LoginRedirect == "" {
		dst.LoginRedirect = src.LoginRedirect
	}
	if dst.Sessions == nil {
		dst.Sessions = src.Sessions
	}
}

func authMappingsForAPI(o config.OIDC) []api.AuthTenantMapping {
	out := make([]api.AuthTenantMapping, 0, len(o.TenantMappings))
	for _, m := range o.TenantMappings {
		out = append(out, api.AuthTenantMapping{
			Subject: m.Subject, Claim: m.Claim, Group: m.Group,
			TenantID: m.TenantID, Roles: append([]string(nil), m.Roles...),
		})
	}
	return out
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
func oidcExchange(o config.OIDC, client *http.Client, secretSource oidcClientSecretSource) func(context.Context, string, string) (string, error) {
	return func(ctx context.Context, code, pkceVerifier string) (string, error) {
		if pkceVerifier == "" {
			return "", errors.New("server: oidc PKCE verifier is required")
		}
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("code_verifier", pkceVerifier)
		form.Set("redirect_uri", o.RedirectURI)
		form.Set("client_id", o.ClientID)
		clientSecret, err := oidcClientSecretBytes(ctx, o, secretSource)
		if err != nil {
			return "", err
		}
		if len(clientSecret) > 0 {
			defer secret.Wipe(clientSecret)
		}
		body := oidcTokenRequestBody(form, clientSecret)
		defer secret.Wipe(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.TokenEndpoint, bytes.NewReader(body))
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

func oidcClientSecretBytes(ctx context.Context, o config.OIDC, source oidcClientSecretSource) ([]byte, error) {
	if source != nil {
		b, err := source(ctx)
		if err != nil {
			return nil, fmt.Errorf("server: load oidc client secret: %w", err)
		}
		return b, nil
	}
	if len(o.ClientSecret) == 0 {
		return nil, nil
	}
	// Return an OWNED copy. The caller wipes whatever it gets back (see the
	// `defer secret.Wipe(clientSecret)` in oidcExchange), and the config field has
	// to survive for the next exchange — so the derived buffer is what gets wiped,
	// never the operator-supplied one. The previous []byte(string) conversion
	// copied by accident; this copies on purpose.
	return append([]byte(nil), o.ClientSecret...), nil
}

func oidcTokenRequestBody(form url.Values, clientSecret []byte) []byte {
	body := []byte(form.Encode())
	if len(clientSecret) == 0 {
		return body
	}
	if len(body) > 0 {
		body = append(body, '&')
	}
	body = append(body, "client_secret="...)
	return appendFormEscapedBytes(body, clientSecret)
}

func appendFormEscapedBytes(dst, value []byte) []byte {
	const hex = "0123456789ABCDEF"
	for _, b := range value {
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '-', b == '_', b == '.', b == '~':
			dst = append(dst, b)
		case b == ' ':
			dst = append(dst, '+')
		default:
			dst = append(dst, '%', hex[b>>4], hex[b&0x0f])
		}
	}
	return dst
}

// loadOrCreateSessionSecret returns the HMAC secret that signs session cookies,
// persisted at path so a restart does not invalidate live sessions and HA replicas
// share one secret. It is created (0600, in a 0700 dir) with 32 bytes of CSPRNG
// output on first boot if absent. The secret is returned as []byte and is never
// logged (AN-8). Randomness routes through the crypto boundary (AN-3).
func loadOrCreateSessionSecret(path string) ([]byte, error) {
	return loadOrCreateNamedSessionSecret("auth.oidc.session_secret_file", path)
}

func loadOrCreateNamedSessionSecret(field, path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("server: %s is required to persist the session secret", field)
	}
	secret, err := secretfile.LoadOrCreate(path, func() ([]byte, error) {
		return crypto.RandomBytes(32)
	})
	if err != nil {
		return nil, fmt.Errorf("server: load session secret %q: %w", path, err)
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("server: session secret %q is too short (%d bytes); want >= 32", path, len(secret))
	}
	return secret, nil
}
