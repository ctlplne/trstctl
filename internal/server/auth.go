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
	cryptosamlsp "trstctl.com/trstctl/internal/crypto/samlsp"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/secrets"
	"trstctl.com/trstctl/internal/store"
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

func buildBrowserAuth(o config.OIDC, s config.SAML, l config.LDAP, secure bool, httpClient *http.Client, st *store.Store, kek sealKeyWrapper) (api.Option, error) {
	oidcCfg, err := buildOIDCAuthConfig(o, secure, httpClient, st, kek)
	if err != nil {
		return nil, err
	}
	samlCfg, err := buildSAMLAuthConfig(s, secure)
	if err != nil {
		return nil, err
	}
	ldapCfg, err := buildLDAPAuthConfig(l, secure)
	if err != nil {
		return nil, err
	}
	base := oidcCfg
	if base == nil {
		base = samlCfg
	} else if samlCfg != nil {
		mergeSAMLAuthConfig(base, samlCfg)
	}
	if base == nil {
		base = ldapCfg
	} else if ldapCfg != nil {
		mergeLDAPAuthConfig(base, ldapCfg)
	}
	if base == nil {
		return nil, nil
	}
	return api.WithAuth(*base), nil
}

func buildOIDCAuthConfig(o config.OIDC, secure bool, httpClient *http.Client, st *store.Store, kek sealKeyWrapper) (*api.AuthConfig, error) {
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
	sessions := auth.NewSessionIssuer(secret, ttl)

	// Per-user → tenant mapping (TENANT-004 / RED-004): each authenticated user is
	// mapped to its real tenant; an unmapped user is rejected (fail closed). The
	// single-DefaultTenant collapse is gone.
	mapper := tenantMapperFromConfig(o)

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	secretSource, err := buildOIDCClientSecretSource(o, st, kek)
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

func buildOIDCClientSecretSource(o config.OIDC, st *store.Store, kek sealKeyWrapper) (oidcClientSecretSource, error) {
	if strings.TrimSpace(o.ClientSecretRef) == "" {
		return nil, nil
	}
	if st == nil {
		return nil, errors.New("server: auth.oidc.client_secret_ref requires a credential store")
	}
	if kek == nil {
		return nil, errors.New("server: auth.oidc.client_secret_ref requires a credential KEK")
	}
	vault := secrets.NewVault(kek, st)
	return auth.OIDCClientSecretSource(vault, o.ClientSecretTenant, o.ClientSecretRef), nil
}

func buildSAMLAuthConfig(s config.SAML, secure bool) (*api.AuthConfig, error) {
	if !s.Enabled {
		return nil, nil
	}
	if err := s.ValidateEnabled(); err != nil {
		return nil, fmt.Errorf("server: SAML login enabled but misconfigured (fail closed): %w", err)
	}
	metadata, err := loadSAMLMetadata(s)
	if err != nil {
		return nil, err
	}
	provider, err := cryptosamlsp.NewServiceProvider(cryptosamlsp.Config{
		EntityID:       s.EntityID,
		MetadataURL:    s.MetadataURL,
		ACSURL:         s.ACSURL,
		IDPMetadataXML: metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("server: configure SAML SP: %w", err)
	}
	secret, err := loadOrCreateNamedSessionSecret("auth.saml.session_secret_file", s.SessionSecretFile)
	if err != nil {
		return nil, err
	}
	ttl, err := s.SessionTTLDuration()
	if err != nil {
		return nil, fmt.Errorf("server: auth.saml.session_ttl: %w", err)
	}
	sessions := auth.NewSessionIssuer(secret, ttl)
	mapper := tenantMapperFromSAMLConfig(s)
	verifier := auth.SAMLVerifier{
		Provider:         provider,
		SubjectAttribute: s.SubjectAttribute,
		EmailAttribute:   s.EmailAttribute,
		TenantClaim:      s.TenantClaim,
		GroupsClaim:      s.GroupsClaim,
	}
	cfg := &api.AuthConfig{
		SAMLEnabled:        s.Enabled,
		TenantClaim:        s.TenantClaim,
		GroupsClaim:        s.GroupsClaim,
		ClaimIsTenant:      s.ClaimIsTenant,
		TenantMappings:     samlMappingsForAPI(s),
		AllowDefaultTenant: s.AllowDefaultTenant,
		DefaultTenant:      s.DefaultTenant,
		DefaultRoles:       s.DefaultRoles,
		SAMLLoginRedirect: func(relayState string) (string, string, error) {
			redirect, err := verifier.LoginRedirect(relayState)
			if err != nil {
				return "", "", err
			}
			return redirect.URL, redirect.RequestID, nil
		},
		VerifySAMLResponse: verifier.Verify,
		ResolveSAMLTenant:  mapper.ResolveTenant,
		SAMLMetadata:       verifier.MetadataXML,
		Sessions:           sessions,
		LoginRedirect:      s.LoginRedirect,
		Secure:             secure,
	}
	return cfg, nil
}

func buildLDAPAuthConfig(l config.LDAP, secure bool) (*api.AuthConfig, error) {
	if !l.Enabled {
		return nil, nil
	}
	if err := l.ValidateEnabled(); err != nil {
		return nil, fmt.Errorf("server: LDAP login enabled but misconfigured (fail closed): %w", err)
	}
	var bindPassword []byte
	var err error
	if strings.TrimSpace(l.BindPasswordFile) != "" {
		bindPassword, err = secretfile.Load(l.BindPasswordFile)
		if err != nil {
			return nil, fmt.Errorf("server: read auth.ldap.bind_password_file %q: %w", l.BindPasswordFile, err)
		}
	}
	secret, err := loadOrCreateNamedSessionSecret("auth.ldap.session_secret_file", l.SessionSecretFile)
	if err != nil {
		return nil, err
	}
	ttl, err := l.SessionTTLDuration()
	if err != nil {
		return nil, fmt.Errorf("server: auth.ldap.session_ttl: %w", err)
	}
	timeout, err := l.TimeoutDuration()
	if err != nil {
		return nil, fmt.Errorf("server: auth.ldap.timeout: %w", err)
	}
	sessions := auth.NewSessionIssuer(secret, ttl)
	mapper := tenantMapperFromLDAPConfig(l)
	verifier := auth.LDAPVerifier{
		URL:                l.URL,
		UserDNTemplate:     l.UserDNTemplate,
		BindDN:             l.BindDN,
		BindPassword:       bindPassword,
		UserSearchBaseDN:   l.UserSearchBaseDN,
		UserFilter:         l.UserFilter,
		GroupSearchBaseDN:  l.GroupSearchBaseDN,
		GroupFilter:        l.GroupFilter,
		GroupNameAttribute: l.GroupNameAttribute,
		EmailAttribute:     l.EmailAttribute,
		Timeout:            timeout,
	}
	cfg := &api.AuthConfig{
		LDAPEnabled:        l.Enabled,
		TenantMappings:     ldapMappingsForAPI(l),
		AllowDefaultTenant: l.AllowDefaultTenant,
		DefaultTenant:      l.DefaultTenant,
		DefaultRoles:       l.DefaultRoles,
		VerifyLDAPLogin:    verifier.Verify,
		ResolveLDAPTenant:  mapper.ResolveTenant,
		Sessions:           sessions,
		LoginRedirect:      l.LoginRedirect,
		Secure:             secure,
	}
	return cfg, nil
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

func samlMappingsForAPI(s config.SAML) []api.AuthTenantMapping {
	out := make([]api.AuthTenantMapping, 0, len(s.TenantMappings))
	for _, m := range s.TenantMappings {
		out = append(out, api.AuthTenantMapping{
			Subject: m.Subject, Claim: m.Claim, Group: m.Group,
			TenantID: m.TenantID, Roles: append([]string(nil), m.Roles...),
		})
	}
	return out
}

func ldapMappingsForAPI(l config.LDAP) []api.AuthTenantMapping {
	out := make([]api.AuthTenantMapping, 0, len(l.TenantMappings))
	for _, m := range l.TenantMappings {
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

func tenantMapperFromSAMLConfig(s config.SAML) auth.TenantMapper {
	mappings := make([]auth.TenantMapping, 0, len(s.TenantMappings))
	for _, m := range s.TenantMappings {
		mappings = append(mappings, auth.TenantMapping{
			Subject: m.Subject, Claim: m.Claim, Group: m.Group,
			TenantID: m.TenantID, Roles: m.Roles,
		})
	}
	return auth.TenantMapper{
		Mappings:      mappings,
		ClaimIsTenant: s.ClaimIsTenant,
		DefaultTenant: s.DefaultTenant,
		DefaultRoles:  s.DefaultRoles,
		AllowDefault:  s.AllowDefaultTenant,
	}
}

func tenantMapperFromLDAPConfig(l config.LDAP) auth.TenantMapper {
	mappings := make([]auth.TenantMapping, 0, len(l.TenantMappings))
	for _, m := range l.TenantMappings {
		mappings = append(mappings, auth.TenantMapping{
			Subject: m.Subject, Claim: m.Claim, Group: m.Group,
			TenantID: m.TenantID, Roles: m.Roles,
		})
	}
	return auth.TenantMapper{
		Mappings:      mappings,
		DefaultTenant: l.DefaultTenant,
		DefaultRoles:  l.DefaultRoles,
		AllowDefault:  l.AllowDefaultTenant,
	}
}

func loadSAMLMetadata(s config.SAML) (string, error) {
	switch {
	case strings.TrimSpace(s.IDPMetadataXML) != "":
		return s.IDPMetadataXML, nil
	case strings.TrimSpace(s.IDPMetadataFile) != "":
		data, err := os.ReadFile(s.IDPMetadataFile)
		if err != nil {
			return "", fmt.Errorf("server: read auth.saml.idp_metadata_file %q: %w", s.IDPMetadataFile, err)
		}
		return string(data), nil
	default:
		return "", errors.New("server: auth.saml requires idp_metadata_file or idp_metadata_xml")
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
	if o.ClientSecret == "" {
		return nil, nil
	}
	return []byte(o.ClientSecret), nil
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
