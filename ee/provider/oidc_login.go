// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A222: Provider console sign-in with the OIDC authorization code flow, so
// operators stop pasting bearer tokens. The login carries state, nonce and a
// PKCE S256 challenge in short-lived HttpOnly cookies; the callback exchanges
// the code at the configured token endpoint and verifies the ID token with the
// same offline verifier as Provider bearers (pinned JWKS, issuer, audience =
// the client id, expiry, role and MFA claims, directory binding) plus the
// nonce. The tokens from the exchange are never sent to the browser or kept:
// the browser gets a server-side Provider session in an HttpOnly, host-only,
// SameSite=Strict cookie and the readable double-submit CSRF cookie SAML
// already uses. The session holds the IdP role; every request re-reads the
// directory row, so a SCIM leaver or a role revocation bites at once.

const (
	providerOIDCSessionCookie    = "__Host-trstctl_provider_oidc_session"
	providerDevOIDCSessionCookie = "trstctl_provider_oidc_session"
	providerOIDCStateCookie      = "trstctl_provider_oidc_state"
	providerOIDCNonceCookie      = "trstctl_provider_oidc_nonce"
	providerOIDCVerifierCookie   = "trstctl_provider_oidc_pkce"
	providerOIDCCookiePath       = "/provider/v1/auth/oidc"
	maxProviderOIDCTokenResponse = 1 << 20
)

// OIDCLoginConfig configures the Provider console's OIDC code flow. The
// endpoints are configured, never discovered at request time, and the keys
// stay the pinned JWKS in Verifier.
type OIDCLoginConfig struct {
	Verifier              OIDCAuthenticatorConfig
	AuthorizationEndpoint string
	TokenEndpoint         string
	ClientID              string
	ClientSecret          []byte
	RedirectURL           string
	// HTTPClient reaches the token endpoint; the attach seam builds it with
	// the outbound SSRF policy for that endpoint.
	HTTPClient    *http.Client
	SessionSecret []byte
	SessionTTL    time.Duration
	LoginRedirect string
	Secure        bool
}

// OIDCLogin serves the Provider OIDC login and callback and authenticates the
// session it mints.
type OIDCLogin struct {
	cfg      OIDCLoginConfig
	verifier *OIDCAuthenticator
	sessions *auth.SessionIssuer
}

// NewOIDCLogin is nil unless the code flow is fully configured.
func NewOIDCLogin(cfg OIDCLoginConfig) *OIDCLogin {
	if strings.TrimSpace(cfg.AuthorizationEndpoint) == "" || strings.TrimSpace(cfg.TokenEndpoint) == "" ||
		strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(cfg.RedirectURL) == "" ||
		len(cfg.ClientSecret) == 0 || len(cfg.SessionSecret) < 32 || cfg.HTTPClient == nil {
		return nil
	}
	verifierCfg := cfg.Verifier
	verifierCfg.Audience = cfg.ClientID // an ID token is issued to the client
	verifier := NewOIDCAuthenticator(verifierCfg)
	if verifier == nil {
		return nil
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if strings.TrimSpace(cfg.LoginRedirect) == "" {
		cfg.LoginRedirect = "/provider"
	}
	return &OIDCLogin{cfg: cfg, verifier: verifier, sessions: auth.NewSessionIssuer(cfg.SessionSecret, cfg.SessionTTL)}
}

// ServeLogin redirects to the IdP's authorization endpoint.
func (l *OIDCLogin) ServeLogin(w http.ResponseWriter, r *http.Request) {
	state, err := auth.RandomState()
	if err != nil {
		writeProviderError(w, err)
		return
	}
	nonce, err := auth.RandomState()
	if err != nil {
		writeProviderError(w, err)
		return
	}
	verifier, err := auth.GeneratePKCEVerifier()
	if err != nil {
		writeProviderError(w, err)
		return
	}
	target, err := auth.AuthCodeURL(l.cfg.AuthorizationEndpoint, l.cfg.ClientID, l.cfg.RedirectURL, state, nonce, auth.PKCEChallengeS256(verifier))
	if err != nil {
		writeProviderError(w, err)
		return
	}
	l.setTransientCookie(w, providerOIDCStateCookie, state)
	l.setTransientCookie(w, providerOIDCNonceCookie, nonce)
	l.setTransientCookie(w, providerOIDCVerifierCookie, verifier)
	http.Redirect(w, r, target, http.StatusFound)
}

// ServeCallback finishes the code flow and mints the Provider session.
func (l *OIDCLogin) ServeCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	state, code := strings.TrimSpace(query.Get("state")), strings.TrimSpace(query.Get("code"))
	stateCookie, stateErr := r.Cookie(providerOIDCStateCookie)
	nonceCookie, nonceErr := r.Cookie(providerOIDCNonceCookie)
	verifierCookie, verifierErr := r.Cookie(providerOIDCVerifierCookie)
	for _, name := range []string{providerOIDCStateCookie, providerOIDCNonceCookie, providerOIDCVerifierCookie} {
		l.clearCookie(w, name)
	}
	if query.Get("error") != "" || state == "" || code == "" || stateErr != nil || nonceErr != nil || verifierErr != nil ||
		stateCookie.Value == "" || nonceCookie.Value == "" || verifierCookie.Value == "" ||
		!crypto.ConstantTimeEqual([]byte(stateCookie.Value), []byte(state)) {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	idToken, err := l.exchange(r.Context(), code, verifierCookie.Value)
	if err != nil {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	operator, ok := l.verifyIDToken(r.Context(), idToken, nonceCookie.Value)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	// The session keeps the IdP role (the ceiling); the directory row is
	// applied again on every request.
	roles := []string{string(operator.Ceiling)}
	if operator.MFA {
		roles = append(roles, "mfa")
	}
	token, err := l.sessions.Issue(operator.ID, providerAuthorityTenant, operator.Email, roles)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- credential cookie is HttpOnly, host-only, strict, and Secure follows the served TLS mode.
		Name: l.sessionCookieName(), Value: token, Path: "/", HttpOnly: true,
		Secure: l.cfg.Secure, SameSite: http.SameSiteStrictMode, MaxAge: int(l.cfg.SessionTTL.Seconds()),
	})
	csrf, err := auth.RandomState()
	if err != nil {
		writeProviderError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- non-HttpOnly by design for double-submit CSRF; it is not a credential without the HttpOnly session.
		Name: providerCSRFCookie, Value: csrf, Path: "/provider", Secure: l.cfg.Secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(l.cfg.SessionTTL.Seconds()),
	})
	http.Redirect(w, r, l.cfg.LoginRedirect, http.StatusFound)
}

// exchange redeems the code at the token endpoint with the PKCE verifier and
// client_secret_basic, and returns only the ID token.
func (l *OIDCLogin) exchange(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {l.cfg.RedirectURL},
		"client_id": {l.cfg.ClientID}, "code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(l.cfg.ClientID), url.QueryEscape(string(l.cfg.ClientSecret)))
	resp, err := l.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderOIDCTokenResponse+1))
	if err != nil {
		return "", err
	}
	defer secret.Wipe(body)
	if resp.StatusCode != http.StatusOK || len(body) > maxProviderOIDCTokenResponse {
		return "", errors.New("provider: OIDC token exchange refused")
	}
	var out struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || strings.TrimSpace(out.IDToken) == "" {
		return "", errors.New("provider: OIDC token response has no id_token")
	}
	return out.IDToken, nil
}

// verifyIDToken checks the nonce and then holds the ID token to the bearer
// path's checks.
func (l *OIDCLogin) verifyIDToken(ctx context.Context, idToken, nonce string) (Operator, bool) {
	claimsJSON, err := crypto.VerifyJWT(idToken, l.cfg.Verifier.JWKS)
	if err != nil {
		return Operator{}, false
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if json.Unmarshal(claimsJSON, &claims) != nil || claims.Nonce == "" ||
		!crypto.ConstantTimeEqual([]byte(claims.Nonce), []byte(nonce)) {
		return Operator{}, false
	}
	probe, err := http.NewRequestWithContext(ctx, http.MethodGet, "/provider/v1/auth/session", nil)
	if err != nil {
		return Operator{}, false
	}
	probe.Header.Set("Authorization", "Bearer "+idToken)
	return l.verifier.AuthenticateOperator(probe)
}

// AuthenticateOperator authenticates the OIDC-minted Provider session.
func (l *OIDCLogin) AuthenticateOperator(r *http.Request) (Operator, bool) {
	if l == nil || r == nil {
		return Operator{}, false
	}
	session, ok := l.session(r, false)
	if !ok {
		return Operator{}, false
	}
	operator := Operator{ID: session.Subject, Email: session.Email, Session: session.ID}
	for _, value := range session.Roles {
		switch value {
		case string(OperatorAdmin):
			operator.Role = OperatorAdmin
		case string(OperatorOperator):
			if operator.Role == "" {
				operator.Role = OperatorOperator
			}
		case "mfa":
			operator.MFA = true
		}
	}
	if !validOperatorRole(operator.Role) {
		return Operator{}, false
	}
	operator.Ceiling = operator.Role
	return l.bindDirectory(r.Context(), operator)
}

// AuthenticateLogout recognizes a signed, unexpired session whose server-side
// record was already revoked, so a repeated logout replays its result.
func (l *OIDCLogin) AuthenticateLogout(r *http.Request) (Operator, bool) {
	if l == nil || r == nil {
		return Operator{}, false
	}
	session, ok := l.session(r, true)
	if !ok || session.ID == "" || session.Subject == "" {
		return Operator{}, false
	}
	return Operator{ID: session.Subject, Email: session.Email, Session: session.ID}, true
}

func (l *OIDCLogin) session(r *http.Request, forLogout bool) (auth.Session, bool) {
	cookie, err := r.Cookie(l.sessionCookieName())
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return auth.Session{}, false
	}
	verify := l.sessions.Verify
	if forLogout {
		verify = func(token string) (auth.Session, error) { return l.sessions.VerifyForLogoutContext(r.Context(), token) }
	}
	session, err := verify(cookie.Value)
	if err != nil || session.TenantID != providerAuthorityTenant {
		return auth.Session{}, false
	}
	return session, true
}

// holdsSession reports whether the request carries this login's cookie.
func (l *OIDCLogin) holdsSession(r *http.Request) bool {
	if l == nil || r == nil {
		return false
	}
	cookie, err := r.Cookie(l.sessionCookieName())
	return err == nil && strings.TrimSpace(cookie.Value) != ""
}

// bindDirectory applies the directory row exactly as the bearer path does.
func (l *OIDCLogin) bindDirectory(ctx context.Context, operator Operator) (Operator, bool) {
	directory := l.cfg.Verifier.Directory
	if directory == nil {
		return operator, !l.cfg.Verifier.RequireDirectory
	}
	identity, err := directory.ResolveOperator(ctx, operator.ID)
	if err != nil {
		return operator, !l.cfg.Verifier.RequireDirectory && errors.Is(err, ErrNotFound)
	}
	if !identity.Active {
		return Operator{}, false
	}
	role, ceiling := effectiveRole(operator.Role, identity.Role)
	if role == "" {
		return Operator{}, false
	}
	operator.ID, operator.Role, operator.Ceiling = identity.ID, role, ceiling
	if strings.TrimSpace(identity.Email) != "" {
		operator.Email = strings.TrimSpace(identity.Email)
	}
	return operator, true
}

// RevokeSession ends the server-side session and expires both cookies.
func (l *OIDCLogin) RevokeSession(ctx context.Context, w http.ResponseWriter, sessionID string) error {
	if l == nil {
		return errors.New("provider: OIDC session issuer is not configured")
	}
	if strings.TrimSpace(sessionID) != "" {
		if err := l.sessions.RevokeContext(ctx, providerAuthorityTenant, sessionID); err != nil && !errors.Is(err, auth.ErrSessionNotFound) {
			return err
		}
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- deletion preserves the HttpOnly, strict, host-only session policy; Secure is false only in explicit loopback development mode (CWE-614).
		Name: l.sessionCookieName(), Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: l.cfg.Secure, SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- this non-credential double-submit cookie must remain JavaScript-readable; strict and served-mode Secure still apply (CWE-614).
		Name: providerCSRFCookie, Path: "/provider", MaxAge: -1,
		Secure: l.cfg.Secure, SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func (l *OIDCLogin) sessionCookieName() string {
	if l != nil && !l.cfg.Secure {
		return providerDevOIDCSessionCookie
	}
	return providerOIDCSessionCookie
}

// setTransientCookie holds login state for the IdP round trip. The callback is
// a top-level GET from the IdP, so the cookie is SameSite=Lax, not Strict.
func (l *OIDCLogin) setTransientCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- short-lived login state, HttpOnly; Lax so the IdP's top-level GET redirect returns it (CWE-614).
		Name: name, Value: value, Path: providerOIDCCookiePath, HttpOnly: true,
		Secure: l.cfg.Secure, SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
}

func (l *OIDCLogin) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- expiring login state (CWE-614).
		Name: name, Path: providerOIDCCookiePath, MaxAge: -1, HttpOnly: true,
		Secure: l.cfg.Secure, SameSite: http.SameSiteLaxMode,
	})
}
