// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

// oauthRefPrefix marks the provider reference of an OAuth access-token lease:
// "oauth:<first 32 hex of the token's SHA-256>:<native expiry, Unix seconds>".
// It names the token without carrying it.
const oauthRefPrefix = "oauth:"

// maxOAuthResponse bounds a token or revocation response body.
const maxOAuthResponse = 64 << 10

// OAuthClientCredentialsConfig configures the OAuth 2.0 client-credentials
// provider (A239): each lease is a new access token from the authorization
// server's token endpoint (RFC 6749 section 4.4), requested with the scopes the
// lease's role is bound to. With a revocation endpoint (RFC 7009) revoking the
// lease revokes the token there; without one, revocation is TTL-only and the
// lease records the expiry the authorization server gave the token.
type OAuthClientCredentialsConfig struct {
	TokenURL      string
	RevocationURL string
	ClientID      string
	ClientSecret  []byte
	// ClientAuth is how the client authenticates to the token and
	// revocation endpoints (A239-L7): OAuthClientSecretBasic (the default,
	// with ClientSecret) or OAuthPrivateKeyJWT (RFC 7523 section 2.2: a JWT
	// the client signs with ClientKeyPEM, its private key, through the
	// crypto boundary; ClientKeyID is the JWS kid, when the authorization
	// server names the key).
	ClientAuth   string
	ClientKeyPEM []byte
	ClientKeyID  string
	// RefreshToken is the provider's refresh token (A239-L7): an operator
	// obtained it once (an authorization-code or device grant) for an API
	// that issues no client-credentials tokens. Each lease of a role in
	// RefreshRoles is an access token drawn with it (RFC 6749 section 6),
	// asking for the role's scopes as a narrowed scope. It is configuration,
	// like the client secret: never handed to a lease holder, revoked or
	// replaced.
	RefreshToken []byte
	RefreshRoles []string
	// RoleScopes maps each allowed role to its space-separated scopes.
	RoleScopes map[string]string
	// MaxLifetime is the longest token lifetime the operator declared for this
	// client; a token issued for longer is refused (and revoked when possible).
	MaxLifetime time.Duration
	// AllowInsecureLoopback permits http:// endpoints on a loopback address,
	// the lab exception every HTTP provider shares.
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
	Now                   func() time.Time
}

// Client authentication methods (A239-L7).
const (
	OAuthClientSecretBasic = "client_secret_basic"
	OAuthPrivateKeyJWT     = "private_key_jwt"
)

// oauthJWTBearerAssertion is RFC 7523's client_assertion_type.
const oauthJWTBearerAssertion = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" // #nosec G101 -- a registered URN naming the assertion type, not a credential (CWE-798)

// oauthAssertionLifetime is how long a client assertion is valid: one
// request's worth.
const oauthAssertionLifetime = time.Minute

// OAuthClientCredentialsBackend issues access tokens for one confidential client.
type OAuthClientCredentialsBackend struct {
	tokenURL      string
	revocationURL string
	clientID      string
	clientAuth    string
	clientSecret  *secret.Buffer
	clientKey     *secret.Buffer
	clientKeyID   string
	refreshToken  *secret.Buffer
	refreshRoles  map[string]bool
	roleScopes    map[string][]string
	maxLifetime   time.Duration
	client        *http.Client
	now           func() time.Time
}

// NewOAuthClientCredentialsBackend validates cfg.
func NewOAuthClientCredentialsBackend(cfg OAuthClientCredentialsConfig) (*OAuthClientCredentialsBackend, error) {
	if err := oauthEndpointURL("token", cfg.TokenURL, false, cfg.AllowInsecureLoopback); err != nil {
		return nil, err
	}
	if err := oauthEndpointURL("revocation", cfg.RevocationURL, true, cfg.AllowInsecureLoopback); err != nil {
		return nil, err
	}
	auth := strings.TrimSpace(cfg.ClientAuth)
	if auth == "" {
		auth = OAuthClientSecretBasic
	}
	switch {
	case strings.TrimSpace(cfg.ClientID) == "":
		return nil, errors.New("dynsecret oauth: client_id is required")
	case auth == OAuthClientSecretBasic && len(cfg.ClientSecret) == 0:
		return nil, errors.New("dynsecret oauth: client_secret_basic needs the client secret")
	case auth == OAuthPrivateKeyJWT && len(cfg.ClientKeyPEM) == 0:
		return nil, errors.New("dynsecret oauth: private_key_jwt needs the client's private key")
	case auth != OAuthClientSecretBasic && auth != OAuthPrivateKeyJWT:
		return nil, fmt.Errorf("dynsecret oauth: client authentication %q is client_secret_basic or private_key_jwt", auth)
	}
	if cfg.HTTPClient == nil {
		return nil, errors.New("dynsecret oauth: an HTTP client is required")
	}
	if cfg.MaxLifetime <= 0 {
		return nil, errors.New("dynsecret oauth: the maximum token lifetime is required")
	}
	b := &OAuthClientCredentialsBackend{
		tokenURL: cfg.TokenURL, revocationURL: cfg.RevocationURL, clientID: cfg.ClientID, clientAuth: auth,
		clientKeyID: strings.TrimSpace(cfg.ClientKeyID), refreshRoles: map[string]bool{},
		roleScopes: map[string][]string{}, maxLifetime: cfg.MaxLifetime, client: cfg.HTTPClient, now: cfg.Now,
	}
	if b.now == nil {
		b.now = time.Now
	}
	for role, raw := range cfg.RoleScopes {
		scopes, err := ParseOAuthScopes(raw)
		if err != nil {
			return nil, fmt.Errorf("dynsecret oauth: role %q: %w", role, err)
		}
		b.roleScopes[role] = scopes
	}
	for _, role := range cfg.RefreshRoles {
		if _, ok := b.roleScopes[role]; !ok {
			return nil, fmt.Errorf("dynsecret oauth: refresh-token role %q has no scopes", role)
		}
		b.refreshRoles[role] = true
	}
	switch {
	case len(b.refreshRoles) > 0 && len(bytes.TrimSpace(cfg.RefreshToken)) == 0:
		return nil, errors.New("dynsecret oauth: refresh-token roles need the provider's refresh token")
	case len(b.refreshRoles) == 0 && len(cfg.RefreshToken) > 0:
		return nil, errors.New("dynsecret oauth: a refresh token is configured but no role draws on it")
	}
	var err error
	if auth == OAuthPrivateKeyJWT {
		// Proven before the first lease: a key the crypto boundary cannot sign
		// with is refused here.
		if _, err := crypto.SignJWTWithPEMKeyBytes(cfg.ClientKeyPEM, b.clientKeyID, map[string]any{"probe": true}); err != nil {
			return nil, fmt.Errorf("dynsecret oauth: the client's private key: %w", err)
		}
		b.clientKey, err = secret.NewFrom(cfg.ClientKeyPEM)
	} else {
		b.clientSecret, err = secret.NewFrom(cfg.ClientSecret)
	}
	if err == nil && len(cfg.RefreshToken) > 0 {
		// Surrounding whitespace (a file's trailing newline) is not part of
		// the token.
		b.refreshToken, err = secret.NewFrom(bytes.TrimSpace(cfg.RefreshToken))
	}
	if err != nil {
		b.Close()
		return nil, err
	}
	return b, nil
}

func oauthEndpointURL(name, raw string, optional, allowInsecureLoopback bool) error {
	if raw == "" && optional {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" ||
		netsec.ValidateHTTPSOrInsecureLoopbackURL(raw, allowInsecureLoopback) != nil {
		return fmt.Errorf("dynsecret oauth: the %s endpoint must be an https URL without credentials or fragment", name)
	}
	return nil
}

// ParseOAuthScopes splits a space-separated scope string into RFC 6749
// scope-tokens (%x21 / %x23-5B / %x5D-7E), refusing an empty or malformed one.
func ParseOAuthScopes(raw string) ([]string, error) {
	scopes := strings.Fields(raw)
	if len(scopes) == 0 {
		return nil, errors.New("at least one scope is required")
	}
	for _, scope := range scopes {
		for _, c := range []byte(scope) {
			if c < 0x21 || c == 0x22 || c == 0x5c || c > 0x7e {
				return nil, fmt.Errorf("scope %q is not an RFC 6749 scope-token", scope)
			}
		}
	}
	return scopes, nil
}

// RevocationConfirmed reports whether revocation calls the authorization server
// (a revocation endpoint is configured) instead of waiting for the token's expiry.
func (b *OAuthClientCredentialsBackend) RevocationConfirmed() bool { return b.revocationURL != "" }

// Create implements Backend.
func (b *OAuthClientCredentialsBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend: one token request with the role's
// scopes, by the client-credentials grant or, for a refresh-token role
// (A239-L7), the refresh-token grant with the provider's refresh token. A token
// whose type, lifetime or granted scopes differ from the request is refused,
// and revoked first when a revocation endpoint is configured.
func (b *OAuthClientCredentialsBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret oauth: static credentials are not served")
	}
	scopes, ok := b.roleScopes[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret oauth: role %q has no scopes", req.Role)
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {strings.Join(scopes, " ")}}
	refresh := b.refreshRoles[req.Role]
	if refresh {
		// RFC 6749 section 6: the role's scopes narrow the refresh token's
		// grant; an authorization server that grants more is refused below.
		if err := b.refreshToken.Use(func(refreshToken []byte) error {
			form.Set("grant_type", "refresh_token")
			form.Set("refresh_token", string(refreshToken))
			return nil
		}); err != nil {
			return "", nil, err
		}
	}
	issuedAt := b.now().UTC()
	body, status, err := b.post(ctx, b.tokenURL, form)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(body)
	if status != http.StatusOK {
		code := oauthErrorCode(body)
		if refresh && code == ": invalid_grant" {
			return "", nil, fmt.Errorf("dynsecret oauth: the token endpoint answered %d%s: the provider's refresh token has expired or been revoked, "+
				"or the authorization server rotated it on use, which this provider does not follow; configure a new refresh_token_ref", status, code)
		}
		return "", nil, fmt.Errorf("dynsecret oauth: the token endpoint answered %d%s", status, code)
	}
	var token struct {
		AccessToken  secret.JSONBytes `json:"access_token"`
		TokenType    string           `json:"token_type"`
		ExpiresIn    json.Number      `json:"expires_in"`
		Scope        *string          `json:"scope"`
		RefreshToken secret.JSONBytes `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &token); err != nil || len(token.AccessToken) == 0 {
		return "", nil, errors.New("dynsecret oauth: the token response carries no access_token")
	}
	defer secret.Wipe(token.AccessToken)
	// A token response may carry a refresh token: one a client-credentials
	// grant adds (Keycloak's per-client setting), or a refresh grant's
	// rotated one. No lease holds it and it is not revoked (on some servers
	// that ends the session the access token belongs to): it is wiped here,
	// never kept (A239-L7).
	secret.Wipe(token.RefreshToken)
	token.RefreshToken = nil
	refuse := func(reason string) (string, []byte, error) {
		if b.revocationURL != "" {
			if err := b.revokeToken(ctx, token.AccessToken); err != nil {
				return "", nil, fmt.Errorf("dynsecret oauth: %s, and revoking the token failed: %w", reason, err)
			}
			return "", nil, fmt.Errorf("dynsecret oauth: %s; the token was revoked", reason)
		}
		return "", nil, fmt.Errorf("dynsecret oauth: %s", reason)
	}
	if !strings.EqualFold(token.TokenType, "bearer") {
		return refuse(fmt.Sprintf("the token type is %q, not Bearer", token.TokenType))
	}
	seconds, err := strconv.ParseInt(token.ExpiresIn.String(), 10, 64)
	if err != nil || seconds <= 0 {
		return refuse("the token response has no expires_in, so the token's lifetime is unknown")
	}
	lifetime := time.Duration(seconds) * time.Second
	if lifetime > b.maxLifetime {
		return refuse(fmt.Sprintf("the token is valid for %s, beyond the declared maximum %s", lifetime, b.maxLifetime))
	}
	if req.TTL > lifetime {
		return refuse(fmt.Sprintf("the token is valid for %s, shorter than the %s lease", lifetime, req.TTL))
	}
	granted := scopes
	if token.Scope != nil {
		if granted, err = ParseOAuthScopes(*token.Scope); err != nil {
			return refuse("the granted scope is malformed")
		}
		if extra := oauthScopesBeyond(granted, scopes); len(extra) > 0 {
			return refuse(fmt.Sprintf("the authorization server granted scopes beyond the role: %s", strings.Join(extra, " ")))
		}
	}
	expiresAt := issuedAt.Add(lifetime).Truncate(time.Second)
	// #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
	credential, err := json.Marshal(struct {
		AccessToken secret.JSONBytes `json:"access_token"`
		TokenType   string           `json:"token_type"`
		ExpiresAt   time.Time        `json:"expires_at"`
		Scope       string           `json:"scope"`
	}{AccessToken: token.AccessToken, TokenType: "Bearer", ExpiresAt: expiresAt, Scope: strings.Join(granted, " ")})
	if err != nil {
		return "", nil, err
	}
	return oauthRefPrefix + oauthTokenDigest(token.AccessToken) + ":" + strconv.FormatInt(expiresAt.Unix(), 10), credential, nil
}

// oauthTokenDigest names a token in its lease's provider reference: the first
// 128 bits of its SHA-256, in hex.
func oauthTokenDigest(token []byte) string { return crypto.SHA256Hex(token)[:32] }

func oauthScopesBeyond(granted, requested []string) []string {
	allowed := map[string]bool{}
	for _, s := range requested {
		allowed[s] = true
	}
	var extra []string
	for _, s := range granted {
		if !allowed[s] {
			extra = append(extra, s)
		}
	}
	return extra
}

// OAuthExpiration reads the native expiry from an OAuth lease's provider
// reference.
func OAuthExpiration(ref string) (time.Time, bool) {
	rest, ok := strings.CutPrefix(ref, oauthRefPrefix)
	if !ok {
		return time.Time{}, false
	}
	digest, unix, ok := strings.Cut(rest, ":")
	if !ok || len(digest) != 32 {
		return time.Time{}, false
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return time.Time{}, false
	}
	seconds, err := strconv.ParseInt(unix, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0).UTC(), true
}

// Revoke implements Backend for a lease whose token is not at hand: without a
// revocation endpoint the token lapses at its native expiry, which is what
// revocation waits for.
func (b *OAuthClientCredentialsBackend) Revoke(_ context.Context, ref string) error {
	return CheckNativeExpiration(ref, b.now())
}

// RevokeCredential revokes the lease's token at the revocation endpoint (RFC
// 7009). credential is the lease's credential JSON; its token must be the one
// ref names. Without a revocation endpoint it is Revoke.
func (b *OAuthClientCredentialsBackend) RevokeCredential(ctx context.Context, ref string, credential []byte) error {
	if b.revocationURL == "" {
		return b.Revoke(ctx, ref)
	}
	var lease struct {
		AccessToken secret.JSONBytes `json:"access_token"`
	}
	if err := json.Unmarshal(credential, &lease); err != nil || len(lease.AccessToken) == 0 {
		return errors.New("dynsecret oauth: the revocation carries no access token")
	}
	defer secret.Wipe(lease.AccessToken)
	if !strings.HasPrefix(ref, oauthRefPrefix+oauthTokenDigest(lease.AccessToken)+":") {
		return errors.New("dynsecret oauth: the revocation's token is not the lease's")
	}
	return b.revokeToken(ctx, lease.AccessToken)
}

// revokeToken revokes a lease's access token at the revocation endpoint (RFC
// 7009 section 2.1); the provider's refresh token is never sent there.
func (b *OAuthClientCredentialsBackend) revokeToken(ctx context.Context, token []byte) error {
	form := url.Values{"token": {string(token)}, "token_type_hint": {"access_token"}}
	body, status, err := b.post(ctx, b.revocationURL, form)
	secret.Wipe(body)
	if err != nil {
		return err
	}
	// RFC 7009 section 2.2: 200 whether or not the token was still valid.
	if status != http.StatusOK {
		return fmt.Errorf("dynsecret oauth: the revocation endpoint answered %d", status)
	}
	return nil
}

// post sends a form with the client's authentication and returns the bounded
// body: HTTP Basic (RFC 6749 section 2.3.1: form-encoded client_id and
// secret), or a client assertion (RFC 7523 section 2.2) the client signs with
// its private key, fresh for each request.
func (b *OAuthClientCredentialsBackend) post(ctx context.Context, endpoint string, form url.Values) ([]byte, int, error) {
	if b.clientAuth == OAuthPrivateKeyJWT {
		assertion, err := b.clientAssertion()
		if err != nil {
			return nil, 0, err
		}
		defer secret.Wipe(assertion)
		form.Set("client_id", b.clientID)
		form.Set("client_assertion_type", oauthJWTBearerAssertion)
		form.Set("client_assertion", string(assertion))
	}
	encoded := form.Encode()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(encoded))
	if err != nil {
		return nil, 0, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")
	if b.clientAuth == OAuthClientSecretBasic {
		if err := b.clientSecret.Use(func(clientSecret []byte) error {
			httpReq.SetBasicAuth(url.QueryEscape(b.clientID), url.QueryEscape(string(clientSecret)))
			return nil
		}); err != nil {
			return nil, 0, err
		}
	}
	resp, err := b.client.Do(httpReq) // #nosec G704 -- the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918)
	if err != nil {
		return nil, 0, fmt.Errorf("dynsecret oauth: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthResponse+1))
	if err != nil {
		return nil, 0, fmt.Errorf("dynsecret oauth: read the response: %w", err)
	}
	if len(body) > maxOAuthResponse {
		secret.Wipe(body)
		return nil, 0, errors.New("dynsecret oauth: the response is larger than 64 KiB")
	}
	return body, resp.StatusCode, nil
}

// oauthErrorCode returns ": <error>" for an RFC 6749 section 5.2 error response,
// with only the registered code's characters kept.
func oauthErrorCode(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil || e.Error == "" || len(e.Error) > 64 {
		return ""
	}
	for _, c := range e.Error {
		if c != '_' && (c < 'a' || c > 'z') {
			return ""
		}
	}
	return ": " + e.Error
}

// clientAssertion is a JWT the client signs with its private key (RFC 7523
// section 3; OpenID Connect Core section 9): issuer and subject the client,
// audience the token endpoint, a unique jti, valid for one minute.
func (b *OAuthClientCredentialsBackend) clientAssertion() ([]byte, error) {
	jti, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	now := b.now().UTC()
	claims := map[string]any{
		"iss": b.clientID, "sub": b.clientID, "aud": b.tokenURL, "jti": hex.EncodeToString(jti),
		"iat": now.Unix(), "exp": now.Add(oauthAssertionLifetime).Unix(),
	}
	var assertion []byte
	err = b.clientKey.Use(func(keyPEM []byte) error {
		var signErr error
		assertion, signErr = crypto.SignJWTWithPEMKeyBytes(keyPEM, b.clientKeyID, claims)
		return signErr
	})
	if err != nil {
		return nil, fmt.Errorf("dynsecret oauth: sign the client assertion: %w", err)
	}
	return assertion, nil
}

// ClientAuth is how the client authenticates (A239-L7).
func (b *OAuthClientCredentialsBackend) ClientAuth() string { return b.clientAuth }

// RefreshRoles are the roles whose leases are drawn with the provider's
// refresh token (A239-L7).
func (b *OAuthClientCredentialsBackend) RefreshRoles() []string {
	roles := make([]string, 0, len(b.refreshRoles))
	for role := range b.refreshRoles {
		roles = append(roles, role)
	}
	slices.Sort(roles)
	return roles
}

// Close wipes the client secret or key and the refresh token.
func (b *OAuthClientCredentialsBackend) Close() {
	for _, buf := range []*secret.Buffer{b.clientSecret, b.clientKey, b.refreshToken} {
		if buf != nil {
			buf.Destroy()
		}
	}
}
