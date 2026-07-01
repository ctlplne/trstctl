package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto"
)

// Cookie names for the browser SSO login + session flow.
const (
	sessionCookieName       = "__Host-trstctl_session"
	preLoginCookieName      = "trstctl_oidc_prelogin"
	stateCookieName         = "trstctl_oidc_state"
	nonceCookieName         = "trstctl_oidc_nonce"
	pkceCookieName          = "trstctl_oidc_pkce"
	samlStateCookieName     = "trstctl_saml_state"
	samlRequestIDCookieName = "trstctl_saml_request_id"
	// csrfCookieName carries the double-submit CSRF token. Unlike the session
	// cookie it is NOT HttpOnly: the SPA reads it and echoes it in the
	// X-CSRF-Token header on every mutating request, which a cross-site attacker
	// cannot do (they can ride the cookie but cannot read it to set the header).
	csrfCookieName = "trstctl_csrf"
	// csrfHeaderName is the header the SPA echoes the CSRF token in.
	csrfHeaderName = "X-CSRF-Token"
	// maxSAMLResponseBytes bounds ACS form parsing. A SAML response is XML and
	// signature material; 2 MiB is generous for enterprise assertions while still
	// preventing unbounded reads on the public ACS endpoint.
	maxSAMLResponseBytes = 2 << 20
	// maxLDAPLoginBytes bounds the public username/password login body.
	maxLDAPLoginBytes = 16 << 10
)

// AuthTenantMapping is the non-secret part of an OIDC tenant mapping published
// by the access-admin status route.
type AuthTenantMapping struct {
	Subject  string   `json:"subject,omitempty"`
	Claim    string   `json:"claim,omitempty"`
	Group    string   `json:"group,omitempty"`
	TenantID string   `json:"tenant_id"`
	Roles    []string `json:"roles,omitempty"`
}

// AuthConfig configures the browser OIDC login and session bridge the web UI
// uses (F12). The OIDC machinery itself is S3.6's: the code exchange and
// id_token verification are seams so production wires the real provider while
// tests inject fakes.
type AuthConfig struct {
	OIDCEnabled  bool
	Issuer       string // provider issuer expected in id_token and, when advertised, callback iss
	AuthEndpoint string // provider authorization endpoint
	ClientID     string
	RedirectURI  string // this server's /auth/callback URL, registered with the provider
	// AuthorizationResponseIssParamSupported mirrors the provider discovery
	// metadata. When true, RFC 9207 requires the callback's iss query parameter to
	// be present and equal to Issuer before trstctl exchanges the code.
	AuthorizationResponseIssParamSupported bool
	// DefaultTenant / DefaultRoles are the LEGACY single-tenant fallback. They are no
	// longer applied directly at session issue — the per-user → tenant mapping
	// (ResolveTenant) is authoritative (TENANT-004). They remain so a deployment that
	// has not configured mappings can still opt into a single-tenant default through
	// the mapper (auth.TenantMapper{AllowDefault:true, DefaultTenant:...}); the served
	// composition passes them through the mapper, never around it.
	DefaultTenant      string   // legacy single-tenant fallback (only via TenantMapper.AllowDefault)
	DefaultRoles       []string // default RBAC roles when a mapping names none
	TenantClaim        string
	GroupsClaim        string
	ClaimIsTenant      bool
	TenantMappings     []AuthTenantMapping
	AllowDefaultTenant bool
	// Exchange swaps an authorization code and matching PKCE verifier for an
	// id_token at the provider.
	Exchange func(ctx context.Context, code, pkceVerifier string) (idToken string, err error)
	// VerifyIDToken validates an id_token against the expected nonce and returns
	// its claims (production: auth.OIDCVerifier.Verify).
	VerifyIDToken func(idToken, nonce string) (auth.Claims, error)
	// ResolveTenant maps a verified user's claims to the tenant its session is scoped
	// to and the RBAC roles it holds (TENANT-004 / RED-004). It REPLACES the single
	// DefaultTenant collapse: each authenticated subject/claim/group is mapped to its
	// real tenant, and a user that maps to no tenant is rejected (the served login
	// fails closed rather than minting a session in a fallback tenant). Production
	// wires auth.TenantMapper.ResolveTenant; a returned auth.ErrNoTenant becomes a 403.
	// When nil, the login fails closed (no tenant can be resolved) — the composition
	// always sets it when OIDC is enabled.
	ResolveTenant func(auth.Claims) (tenantID string, roles []string, err error)
	// PreLoginTTL bounds the server-side OIDC pre-login row that stores state,
	// nonce, PKCE verifier, and the browser binding. Zero uses a 10-minute default.
	PreLoginTTL time.Duration
	// DisablePreLoginUserAgentBinding / DisablePreLoginIPBinding are compatibility
	// escape hatches for deployments with rewriting proxies or unstable source IPs.
	// They default to false: callback User-Agent and IP must match the login request.
	DisablePreLoginUserAgentBinding bool
	DisablePreLoginIPBinding        bool
	// RecordPreLoginMismatch records a non-secret event/audit signal when the
	// callback fails the UA/IP binding check. It is optional; the request still fails.
	RecordPreLoginMismatch func(ctx context.Context, reason string)
	// VerifyOIDCLogoutToken validates an OIDC Back-Channel Logout logout_token and
	// enforces JTI replay protection.
	VerifyOIDCLogoutToken func(raw string) (auth.LogoutTokenClaims, error)

	SAMLEnabled bool
	// SAMLLoginRedirect creates an SP-initiated AuthnRequest redirect URL and returns
	// the generated request ID, so the ACS can correlate the signed response.
	SAMLLoginRedirect func(relayState string) (redirectURL string, requestID string, err error)
	// VerifySAMLResponse validates the ACS POST's SAMLResponse and returns claims in
	// the same shape as OIDC. Production wires auth.SAMLVerifier.Verify.
	VerifySAMLResponse func(r *http.Request, possibleRequestIDs []string) (auth.Claims, error)
	// ResolveSAMLTenant maps SAML claims to the tenant/roles for the browser session.
	ResolveSAMLTenant func(auth.Claims) (tenantID string, roles []string, err error)
	// SAMLMetadata returns the SP metadata document served at /auth/saml/metadata.
	SAMLMetadata func() ([]byte, error)

	LDAPEnabled bool
	// VerifyLDAPLogin binds the supplied directory credentials and returns normalized
	// claims with directory groups. Production wires auth.LDAPVerifier.Verify.
	VerifyLDAPLogin func(ctx context.Context, username string, password []byte) (auth.Claims, error)
	// ResolveLDAPTenant maps LDAP claims/groups to the tenant/roles for the browser
	// session.
	ResolveLDAPTenant func(auth.Claims) (tenantID string, roles []string, err error)

	Sessions      *auth.SessionIssuer
	LoginRedirect string // where to send the browser after login (default "/")
	Secure        bool   // set the Secure flag on cookies (true behind TLS)
}

type meResponse struct {
	Subject     string   `json:"subject"`
	TenantID    string   `json:"tenant_id"`
	Email       string   `json:"email,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Locale      string   `json:"locale,omitempty"`
	TimeZone    string   `json:"time_zone,omitempty"`
}

type ldapLoginRequest struct {
	Username string       `json:"username"`
	Password ldapPassword `json:"password"`
}

type ldapPassword []byte

func (p *ldapPassword) UnmarshalJSON(raw []byte) error {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	*p = append((*p)[:0], []byte(s)...)
	return nil
}

func (p ldapPassword) wipe() {
	for i := range p {
		p[i] = 0
	}
	runtime.KeepAlive(p)
}

// authLogin starts the OIDC flow: it sets short-lived state and nonce cookies
// and redirects the browser to the provider.
func (a *API) authLogin(w http.ResponseWriter, r *http.Request) {
	if !a.allowSpecialRouteRequest(w, r, specialRouteAbuseRequest{}) {
		return
	}
	state, err := auth.RandomState()
	if err != nil {
		a.writeError(w, err)
		return
	}
	nonce, err := auth.RandomState()
	if err != nil {
		a.writeError(w, err)
		return
	}
	pkceVerifier, err := auth.GeneratePKCEVerifier()
	if err != nil {
		a.writeError(w, err)
		return
	}
	pkceChallenge := auth.PKCEChallengeS256(pkceVerifier)
	if a.oidcPreLogin == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "OIDC pre-login store is not configured"))
		return
	}
	preLoginID, err := a.oidcPreLogin.create(state, nonce, pkceVerifier, requestClientIP(r), r.UserAgent())
	if err != nil {
		var capacityErr oidcPreLoginCapacityError
		if errors.As(err, &capacityErr) {
			a.writeRateLimitExceeded(w, capacityErr.retryAfter)
			return
		}
		a.writeError(w, err)
		return
	}
	a.setTransientCookie(w, preLoginCookieName, preLoginID)
	a.setTransientCookie(w, stateCookieName, state)
	a.setTransientCookie(w, nonceCookieName, nonce)
	a.setTransientCookie(w, pkceCookieName, pkceVerifier)
	redirectURL, err := auth.AuthCodeURL(a.auth.AuthEndpoint, a.auth.ClientID, a.auth.RedirectURI, state, nonce, pkceChallenge)
	if err != nil {
		a.writeError(w, err)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// authCallback completes the flow: verify state, exchange the code, verify the
// id_token against the nonce, mint a session, and redirect to the UI.
func (a *API) authCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	preLoginCookie, err := r.Cookie(preLoginCookieName)
	if err != nil || preLoginCookie.Value == "" || a.oidcPreLogin == nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid OIDC pre-login state"))
		return
	}
	preLogin, err := a.oidcPreLogin.consume(preLoginCookie.Value)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid OIDC pre-login state"))
		return
	}
	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil || stateCookie.Value == "" ||
		!crypto.ConstantTimeEqual([]byte(stateCookie.Value), []byte(q.Get("state"))) ||
		!crypto.ConstantTimeEqual([]byte(preLogin.State), []byte(q.Get("state"))) {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid OIDC state"))
		return
	}
	if err := a.checkPreLoginBinding(r, preLogin); err != nil {
		a.writeError(w, err)
		return
	}
	if err := a.checkAuthorizationResponseIssuer(q.Get("iss")); err != nil {
		a.writeError(w, err)
		return
	}
	code := q.Get("code")
	if code == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "missing authorization code"))
		return
	}
	pkceCookie, err := r.Cookie(pkceCookieName)
	if err != nil || pkceCookie.Value == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "missing OIDC PKCE verifier"))
		return
	}
	if !crypto.ConstantTimeEqual([]byte(pkceCookie.Value), []byte(preLogin.PKCEVerifier)) {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid OIDC PKCE verifier"))
		return
	}
	idToken, err := a.auth.Exchange(r.Context(), code, preLogin.PKCEVerifier)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadGateway, "token exchange failed"))
		return
	}
	// The nonce cookie is mandatory: without it, verification cannot bind the
	// id_token to this login attempt, so reject rather than proceed with an empty
	// (skipped) nonce (closing the replay window).
	nonceCookie, err := r.Cookie(nonceCookieName)
	if err != nil || nonceCookie.Value == "" || !crypto.ConstantTimeEqual([]byte(nonceCookie.Value), []byte(preLogin.Nonce)) {
		a.writeError(w, errStatus(http.StatusBadRequest, "missing OIDC nonce"))
		return
	}
	claims, err := a.auth.VerifyIDToken(idToken, preLogin.Nonce)
	if err != nil {
		a.writeError(w, errStatus(http.StatusUnauthorized, "id_token verification failed"))
		return
	}
	// Per-user → tenant mapping (TENANT-004 / RED-004): resolve THIS user's tenant and
	// roles from its verified claims, replacing the single-DefaultTenant collapse. A
	// user that maps to no tenant is rejected (fail closed) rather than dropped into a
	// fallback tenant — so a misconfigured/unknown principal cannot silently land in
	// the wrong tenant. RLS then confines the minted session to exactly this tenant
	// (AN-1).
	tenantID, roles, err := a.resolveLoginTenant(claims)
	if err != nil {
		a.writeProblem(w, problem.New(http.StatusForbidden, "no tenant for this user"))
		return
	}
	a.issueLoginSession(w, r, claims, tenantID, roles, preLoginCookieName, stateCookieName, nonceCookieName, pkceCookieName)
}

func (a *API) checkAuthorizationResponseIssuer(callbackIssuer string) error {
	if a.auth == nil || !a.auth.AuthorizationResponseIssParamSupported {
		return nil
	}
	if callbackIssuer == "" {
		return errStatus(http.StatusBadRequest, "missing OIDC issuer parameter")
	}
	if a.auth.Issuer == "" || !crypto.ConstantTimeEqual([]byte(callbackIssuer), []byte(a.auth.Issuer)) {
		return errStatus(http.StatusBadRequest, "invalid OIDC issuer parameter")
	}
	return nil
}

func (a *API) checkPreLoginBinding(r *http.Request, preLogin oidcPreLoginEntry) error {
	if a.auth == nil {
		return nil
	}
	if !a.auth.DisablePreLoginUserAgentBinding && preLogin.UserAgent != "" &&
		!crypto.ConstantTimeEqual([]byte(r.UserAgent()), []byte(preLogin.UserAgent)) {
		a.recordPreLoginMismatch(r.Context(), "user_agent")
		return errStatus(http.StatusBadRequest, "OIDC pre-login browser binding mismatch")
	}
	if !a.auth.DisablePreLoginIPBinding && preLogin.ClientIP != "" &&
		!crypto.ConstantTimeEqual([]byte(requestClientIP(r)), []byte(preLogin.ClientIP)) {
		a.recordPreLoginMismatch(r.Context(), "client_ip")
		return errStatus(http.StatusBadRequest, "OIDC pre-login browser binding mismatch")
	}
	return nil
}

func (a *API) recordPreLoginMismatch(ctx context.Context, reason string) {
	if a.auth == nil || a.auth.RecordPreLoginMismatch == nil {
		return
	}
	a.auth.RecordPreLoginMismatch(ctx, reason)
}

// authSAMLLogin starts an SP-initiated SAML flow and redirects the browser to the
// IdP's SSO endpoint.
func (a *API) authSAMLLogin(w http.ResponseWriter, r *http.Request) {
	if a.auth.SAMLLoginRedirect == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "SAML login is not configured"))
		return
	}
	if !a.allowSpecialRouteRequest(w, r, specialRouteAbuseRequest{}) {
		return
	}
	state, err := auth.RandomState()
	if err != nil {
		a.writeError(w, err)
		return
	}
	redirectURL, requestID, err := a.auth.SAMLLoginRedirect(state)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadGateway, "SAML AuthnRequest failed"))
		return
	}
	a.setTransientCookie(w, samlStateCookieName, state)
	a.setTransientCookie(w, samlRequestIDCookieName, requestID)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// authSAMLACS completes both SP-initiated and IdP-initiated SAML POST-binding
// login, then mints the normal browser session.
func (a *API) authSAMLACS(w http.ResponseWriter, r *http.Request) {
	if a.auth.VerifySAMLResponse == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "SAML login is not configured"))
		return
	}
	if !a.allowSpecialRouteRequest(w, r, specialRouteAbuseRequest{}) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSAMLResponseBytes)
	if err := r.ParseForm(); err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid SAML response"))
		return
	}
	var possibleRequestIDs []string
	clearCookies := []string{}
	if relayState := r.Form.Get("RelayState"); relayState != "" {
		stateCookie, err := r.Cookie(samlStateCookieName)
		if err != nil || stateCookie.Value == "" || stateCookie.Value != relayState {
			a.writeError(w, errStatus(http.StatusBadRequest, "invalid SAML state"))
			return
		}
		requestIDCookie, err := r.Cookie(samlRequestIDCookieName)
		if err != nil || requestIDCookie.Value == "" {
			a.writeError(w, errStatus(http.StatusBadRequest, "missing SAML request ID"))
			return
		}
		possibleRequestIDs = []string{requestIDCookie.Value}
		clearCookies = []string{samlStateCookieName, samlRequestIDCookieName}
	}
	claims, err := a.auth.VerifySAMLResponse(r, possibleRequestIDs)
	if err != nil {
		a.writeError(w, errStatus(http.StatusUnauthorized, "SAML response verification failed"))
		return
	}
	resolve := a.auth.ResolveSAMLTenant
	if resolve == nil {
		resolve = a.auth.ResolveTenant
	}
	tenantID, roles, err := a.resolveLoginTenantWith(claims, resolve)
	if err != nil {
		a.writeProblem(w, problem.New(http.StatusForbidden, "no tenant for this user"))
		return
	}
	a.issueLoginSession(w, r, claims, tenantID, roles, clearCookies...)
}

func (a *API) authSAMLMetadata(w http.ResponseWriter, _ *http.Request) {
	if a.auth.SAMLMetadata == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "SAML metadata is not configured"))
		return
	}
	data, err := a.auth.SAMLMetadata()
	if err != nil {
		a.writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(data)
}

// authLDAPLogin completes a username/password directory bind, maps directory
// groups to tenant roles, then mints the normal browser session.
func (a *API) authLDAPLogin(w http.ResponseWriter, r *http.Request) {
	if a.auth.VerifyLDAPLogin == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "LDAP login is not configured"))
		return
	}
	if !a.allowSpecialRouteRequest(w, r, specialRouteAbuseRequest{}) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLDAPLoginBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req ldapLoginRequest
	if err := dec.Decode(&req); err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid LDAP login request"))
		return
	}
	defer req.Password.wipe()
	claims, err := a.auth.VerifyLDAPLogin(r.Context(), req.Username, []byte(req.Password))
	if err != nil {
		a.writeError(w, errStatus(http.StatusUnauthorized, "LDAP bind failed"))
		return
	}
	resolve := a.auth.ResolveLDAPTenant
	if resolve == nil {
		resolve = a.auth.ResolveTenant
	}
	tenantID, roles, err := a.resolveLoginTenantWith(claims, resolve)
	if err != nil {
		a.writeProblem(w, problem.New(http.StatusForbidden, "no tenant for this user"))
		return
	}
	a.issueLoginSession(w, r, claims, tenantID, roles)
}

func (a *API) issueLoginSession(w http.ResponseWriter, r *http.Request, claims auth.Claims, tenantID string, roles []string, clearCookies ...string) {
	token, err := a.auth.Sessions.Issue(claims.Subject, tenantID, claims.Email, roles)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.setSessionCookie(w, token)
	// Issue a fresh double-submit CSRF token bound to this session (SEC-007). The SPA
	// reads it from the non-HttpOnly cookie and echoes it in X-CSRF-Token on every
	// mutating request; enforceCSRF rejects a session-authenticated mutation whose
	// header does not match the cookie, so a cross-site forged POST (which cannot read
	// the cookie to set the header) fails closed.
	csrf, err := auth.RandomState()
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.setCSRFCookie(w, csrf)
	for _, name := range clearCookies {
		a.clearCookie(w, name)
	}
	redirect := a.auth.LoginRedirect
	if redirect == "" {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// resolveLoginTenant maps a verified OIDC user to its tenant and RBAC roles
// (TENANT-004). It delegates to the configured ResolveTenant mapper; when that is
// unset it fails closed (no tenant can be resolved) rather than falling back to a
// single default — a session is never minted without a real, per-user tenant. A
// resolved-but-empty tenant is also rejected (fail closed under RLS, AN-1).
func (a *API) resolveLoginTenant(claims auth.Claims) (string, []string, error) {
	return a.resolveLoginTenantWith(claims, a.auth.ResolveTenant)
}

func (a *API) resolveLoginTenantWith(claims auth.Claims, resolve func(auth.Claims) (string, []string, error)) (string, []string, error) {
	if resolve == nil {
		return "", nil, auth.ErrNoTenant
	}
	tenantID, roles, err := resolve(claims)
	if err != nil {
		return "", nil, err
	}
	if tenantID == "" {
		return "", nil, auth.ErrNoTenant
	}
	return tenantID, roles, nil
}

// authMe returns the current session's principal, or 401 if unauthenticated.
func (a *API) authMe(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.sessionFrom(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	roles, permissions := a.sessionRoleSummary(r.Context(), sess)
	a.writeJSON(w, http.StatusOK, meResponse{
		Subject:     sess.Subject,
		TenantID:    sess.TenantID,
		Email:       sess.Email,
		Roles:       roles,
		Permissions: permissions,
		Locale:      preferredWebLocale(r.Header.Get("Accept-Language")),
	})
}

func (a *API) sessionRoleSummary(ctx context.Context, sess auth.Session) ([]string, []string) {
	roleNames := a.sessionRoleNames(ctx, sess)
	seen := map[string]bool{}
	permissions := make([]string, 0, len(roleNames))
	for _, name := range roleNames {
		role, ok := a.roles.Role(name)
		if !ok {
			continue
		}
		for _, perm := range role.Permissions {
			value := string(perm)
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			permissions = append(permissions, value)
		}
	}
	sort.Strings(permissions)
	return roleNames, permissions
}

// authLogout clears the session and CSRF cookies.
func (a *API) authLogout(w http.ResponseWriter, _ *http.Request) {
	a.clearCookie(w, sessionCookieName)
	a.clearCookie(w, csrfCookieName)
	w.WriteHeader(http.StatusNoContent)
}

func preferredWebLocale(acceptLanguage string) string {
	bestLocale := ""
	bestQuality := -1.0
	for _, raw := range strings.Split(acceptLanguage, ",") {
		tag, quality := parseAcceptLanguageRange(raw)
		if tag == "" || quality <= 0 {
			continue
		}
		locale := webLocaleForLanguageTag(tag)
		if locale == "" || quality <= bestQuality {
			continue
		}
		bestLocale = locale
		bestQuality = quality
	}
	return bestLocale
}

func parseAcceptLanguageRange(raw string) (string, float64) {
	parts := strings.Split(raw, ";")
	tag := strings.TrimSpace(parts[0])
	quality := 1.0
	for _, part := range parts[1:] {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") {
			continue
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil {
			return tag, 0
		}
		quality = parsed
	}
	return tag, quality
}

func webLocaleForLanguageTag(tag string) string {
	switch strings.ToLower(tag) {
	case "en-us", "en":
		return "en-US"
	case "es-es", "es":
		return "es-ES"
	case "en-xa":
		return "en-XA"
	case "ar-xb":
		return "ar-XB"
	}
	lang := strings.Split(tag, "-")[0]
	switch strings.ToLower(lang) {
	case "en":
		return "en-US"
	case "es":
		return "es-ES"
	case "ar", "fa", "he", "ur":
		return "ar-XB"
	}
	return ""
}

func (a *API) authOIDCBackChannelLogout(w http.ResponseWriter, r *http.Request) {
	if a.auth == nil || a.auth.VerifyOIDCLogoutToken == nil || a.auth.Sessions == nil {
		a.writeError(w, errStatus(http.StatusNotFound, "OIDC back-channel logout is not configured"))
		return
	}
	if !a.allowSpecialRouteRequest(w, r, specialRouteAbuseRequest{}) {
		return
	}
	if err := r.ParseForm(); err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid back-channel logout request"))
		return
	}
	raw := r.Form.Get("logout_token")
	if raw == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "missing logout_token"))
		return
	}
	claims, err := a.auth.VerifyOIDCLogoutToken(raw)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrLogoutTokenReplay), errors.Is(err, auth.ErrLogoutTokenInvalid):
			a.writeError(w, errStatus(http.StatusBadRequest, "invalid logout_token"))
		default:
			a.writeError(w, errStatus(http.StatusUnauthorized, "logout_token verification failed"))
		}
		return
	}
	if claims.SID != "" {
		_ = a.auth.Sessions.Revoke(claims.SID)
	}
	if claims.Subject != "" {
		_ = a.auth.Sessions.RevokeSubject(claims.Subject)
	}
	w.WriteHeader(http.StatusOK)
}

// enforceCSRF implements double-submit CSRF protection for the cookie-session path
// (SEC-007). It applies ONLY to requests authenticated by the session cookie: a
// bearer-token (Authorization header) request is CSRF-immune (a browser does not
// attach the header cross-site) and is exempt, as are safe methods (GET/HEAD/
// OPTIONS, which must not mutate). For a session-authenticated mutating request it
// requires the X-CSRF-Token header to be present and to constant-time-equal the
// trstctl_csrf cookie; a cross-site attacker can ride the session cookie but
// cannot read the CSRF cookie to set the header, so a forged POST is rejected. It
// returns true when the request may proceed and false (after writing 403) otherwise.
func (a *API) enforceCSRF(w http.ResponseWriter, r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	// Bearer-token callers are not cookie-driven and cannot be CSRF'd.
	if r.Header.Get("Authorization") != "" {
		return true
	}
	// Only the cookie-session path needs the check; if there is no session cookie the
	// request is not session-authenticated and other auth (or rejection) applies.
	if _, err := r.Cookie(sessionCookieName); err != nil {
		return true
	}
	cookie, err := r.Cookie(csrfCookieName)
	header := r.Header.Get(csrfHeaderName)
	if err != nil || cookie.Value == "" || header == "" ||
		!crypto.ConstantTimeEqual([]byte(cookie.Value), []byte(header)) {
		a.writeProblem(w, problem.New(http.StatusForbidden, "missing or invalid CSRF token"))
		return false
	}
	return true
}

func (a *API) sessionFrom(r *http.Request) (auth.Session, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return auth.Session{}, false
	}
	sess, err := a.auth.Sessions.Verify(c.Value)
	if err != nil {
		return auth.Session{}, false
	}
	return sess, true
}

func (a *API) setTransientCookie(w http.ResponseWriter, name, value string) {
	// SameSite=Lax (not Strict): the OIDC state/nonce cookies must survive the
	// top-level cross-site redirect back from the identity provider, which Strict
	// would drop. They are short-lived and unprivileged.
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", HttpOnly: true,
		Secure: a.auth.Secure, SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
}

func (a *API) setSessionCookie(w http.ResponseWriter, value string) {
	// SameSite=Strict on the session cookie: the browser never attaches it to a
	// cross-site request, which (with the double-submit CSRF token) is the SEC-007
	// hardening. The post-login redirect is same-site (this server's /), so Strict
	// does not break the flow.
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: value, Path: "/", HttpOnly: true,
		Secure: a.auth.Secure, SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(12 * time.Hour),
	})
}

// setCSRFCookie sets the double-submit CSRF token cookie. It is intentionally NOT
// HttpOnly so the SPA can read it and echo it in the X-CSRF-Token header; that is
// safe because the token is not a credential on its own (a session cookie is still
// required) and a cross-site attacker cannot read it (SameSite=Strict + same-origin
// script access only). SEC-007.
func (a *API) setCSRFCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookieName, Value: value, Path: "/", HttpOnly: false,
		Secure: a.auth.Secure, SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(12 * time.Hour),
	})
}

func (a *API) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", HttpOnly: true,
		Secure: a.auth.Secure, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}
