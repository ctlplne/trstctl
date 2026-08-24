// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/samlsp"
)

const (
	providerSessionCookie       = "__Host-trstctl_provider_session"
	providerDevSessionCookie    = "trstctl_provider_session"
	providerCSRFCookie          = "trstctl_provider_csrf"
	providerCSRFHeader          = "X-Provider-CSRF-Token"
	providerSAMLStateCookie     = "trstctl_provider_saml_state"
	providerSAMLRequestIDCookie = "trstctl_provider_saml_request_id"
	maxProviderSAMLResponse     = 2 << 20
)

// SAMLProvider is the crypto-boundary surface the Provider plane consumes.
// internal/crypto/samlsp.ServiceProvider is the production implementation;
// tests can inject normalized already-verified assertion fixtures.
type SAMLProvider interface {
	LoginRedirect(string) (samlsp.Redirect, error)
	MetadataXML() ([]byte, error)
	VerifyResponse(*http.Request, []string) (samlsp.Assertion, error)
}

type SAMLAuthenticatorConfig struct {
	Provider SAMLProvider

	SubjectAttribute string
	EmailAttribute   string
	RoleAttribute    string
	AdminValues      []string
	OperatorValues   []string
	MFAAttribute     string
	MFAValues        []string

	Directory        OperatorDirectory
	RequireDirectory bool

	SessionSecret []byte
	SessionTTL    time.Duration
	LoginRedirect string
	Secure        bool
}

// SAMLAuthenticator owns the Provider SP endpoints and its separate HttpOnly
// session. It never reuses a customer-tenant browser session: Provider staff
// and tenant users are distinct privilege domains.
type SAMLAuthenticator struct {
	cfg      SAMLAuthenticatorConfig
	sessions *auth.SessionIssuer
	admin    map[string]bool
	operator map[string]bool
	mfa      map[string]bool
}

func NewSAMLAuthenticator(cfg SAMLAuthenticatorConfig) *SAMLAuthenticator {
	if cfg.Provider == nil || len(cfg.SessionSecret) < 32 || strings.TrimSpace(cfg.RoleAttribute) == "" ||
		strings.TrimSpace(cfg.MFAAttribute) == "" || (len(cfg.AdminValues) == 0 && len(cfg.OperatorValues) == 0) {
		return nil
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if strings.TrimSpace(cfg.LoginRedirect) == "" {
		cfg.LoginRedirect = "/provider"
	}
	toSet := func(values []string) map[string]bool {
		out := map[string]bool{}
		for _, value := range values {
			if value = strings.TrimSpace(value); value != "" {
				out[value] = true
			}
		}
		return out
	}
	return &SAMLAuthenticator{
		cfg: cfg, sessions: auth.NewSessionIssuer(cfg.SessionSecret, cfg.SessionTTL),
		admin: toSet(cfg.AdminValues), operator: toSet(cfg.OperatorValues), mfa: toSet(cfg.MFAValues),
	}
}

func (a *SAMLAuthenticator) AuthenticateOperator(r *http.Request) (Operator, bool) {
	if a == nil || r == nil || a.sessions == nil {
		return Operator{}, false
	}
	cookie, err := r.Cookie(a.sessionCookieName())
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return Operator{}, false
	}
	session, err := a.sessions.Verify(cookie.Value)
	if err != nil || session.TenantID != providerAuthorityTenant {
		return Operator{}, false
	}
	var sessionRole OperatorRole
	mfa := false
	for _, value := range session.Roles {
		switch value {
		case string(OperatorAdmin):
			sessionRole = OperatorAdmin
		case string(OperatorOperator):
			if sessionRole == "" {
				sessionRole = OperatorOperator
			}
		case "mfa":
			mfa = true
		}
	}
	if !validOperatorRole(sessionRole) || !mfa {
		return Operator{}, false
	}
	operator := Operator{ID: session.Subject, Email: session.Email, Role: sessionRole, MFA: true, Session: session.ID}
	if a.cfg.Directory != nil {
		identity, resolveErr := a.cfg.Directory.ResolveOperator(r.Context(), session.Subject)
		if resolveErr != nil || !identity.Active {
			return Operator{}, false
		}
		role := lesserRole(sessionRole, identity.Role)
		if role == "" {
			return Operator{}, false
		}
		operator.ID, operator.Role = identity.ID, role
		if strings.TrimSpace(identity.Email) != "" {
			operator.Email = identity.Email
		}
	} else if a.cfg.RequireDirectory {
		return Operator{}, false
	}
	return operator, true
}

// AuthenticateLogout recognizes the same signed, unexpired Provider cookie
// after its server-side record has been revoked. The handler uses this only to
// replay the original idempotent logout result; it grants no Provider action.
func (a *SAMLAuthenticator) AuthenticateLogout(r *http.Request) (Operator, bool) {
	if a == nil || r == nil || a.sessions == nil {
		return Operator{}, false
	}
	cookie, err := r.Cookie(a.sessionCookieName())
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return Operator{}, false
	}
	session, err := a.sessions.VerifyForLogoutContext(r.Context(), cookie.Value)
	if err != nil || session.TenantID != providerAuthorityTenant || session.ID == "" || session.Subject == "" {
		return Operator{}, false
	}
	return Operator{ID: session.Subject, Email: session.Email, Session: session.ID}, true
}

func (a *SAMLAuthenticator) ServeLogin(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.cfg.Provider == nil {
		http.NotFound(w, r)
		return
	}
	state, err := auth.RandomState()
	if err != nil {
		writeProviderError(w, err)
		return
	}
	redirect, err := a.cfg.Provider.LoginRedirect(state)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	a.setTransientCookie(w, providerSAMLStateCookie, state)
	a.setTransientCookie(w, providerSAMLRequestIDCookie, redirect.RequestID)
	http.Redirect(w, r, redirect.URL, http.StatusFound)
}

func (a *SAMLAuthenticator) ServeACS(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.cfg.Provider == nil {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxProviderSAMLResponse)
	if err := r.ParseForm(); err != nil {
		writeProviderError(w, errors.New("provider: invalid SAML response"))
		return
	}
	relayState := strings.TrimSpace(r.Form.Get("RelayState"))
	stateCookie, stateErr := r.Cookie(providerSAMLStateCookie)
	requestCookie, requestErr := r.Cookie(providerSAMLRequestIDCookie)
	if relayState == "" || stateErr != nil || requestErr != nil || stateCookie.Value == "" || requestCookie.Value == "" ||
		!crypto.ConstantTimeEqual([]byte(stateCookie.Value), []byte(relayState)) {
		writeProviderError(w, errors.New("provider: invalid SAML state"))
		return
	}
	possibleRequestIDs := []string{requestCookie.Value}
	assertion, err := a.cfg.Provider.VerifyResponse(r, possibleRequestIDs)
	if err != nil {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	operator, ok := a.operatorFromAssertion(r, assertion)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	token, err := a.sessions.Issue(operator.ID, providerAuthorityTenant, operator.Email,
		[]string{string(operator.Role), "mfa"})
	if err != nil {
		writeProviderError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- credential cookie is HttpOnly, host-only, strict, and Secure follows the served TLS mode.
		Name: a.sessionCookieName(), Value: token, Path: "/", HttpOnly: true,
		Secure: a.cfg.Secure, SameSite: http.SameSiteStrictMode, MaxAge: int(a.cfg.SessionTTL.Seconds()),
	})
	csrf, err := auth.RandomState()
	if err != nil {
		writeProviderError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- non-HttpOnly by design for double-submit CSRF; it is not a credential without the HttpOnly session.
		Name: providerCSRFCookie, Value: csrf, Path: "/provider", Secure: a.cfg.Secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(a.cfg.SessionTTL.Seconds()),
	})
	a.clearCookie(w, providerSAMLStateCookie)
	a.clearCookie(w, providerSAMLRequestIDCookie)
	http.Redirect(w, r, a.cfg.LoginRedirect, http.StatusFound)
}

// RevokeSession ends the server-side Provider session and expires both browser
// cookies. Clearing React state alone is not logout: the HttpOnly cookie would
// otherwise authenticate the next request and immediately sign the user back
// in.
func (a *SAMLAuthenticator) RevokeSession(ctx context.Context, w http.ResponseWriter, sessionID string) error {
	if a == nil || a.sessions == nil {
		return errors.New("provider: SAML session issuer is not configured")
	}
	if strings.TrimSpace(sessionID) != "" {
		if err := a.sessions.RevokeContext(ctx, providerAuthorityTenant, sessionID); err != nil && !errors.Is(err, auth.ErrSessionNotFound) {
			return err
		}
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- deletion preserves the HttpOnly, strict, host-only session policy; Secure is false only in explicit loopback development mode (CWE-614).
		Name: a.sessionCookieName(), Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: a.cfg.Secure, SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- this non-credential double-submit cookie must remain JavaScript-readable; strict and served-mode Secure still apply (CWE-614).
		Name: providerCSRFCookie, Path: "/provider", MaxAge: -1,
		Secure: a.cfg.Secure, SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func (a *SAMLAuthenticator) sessionCookieName() string {
	if a != nil && !a.cfg.Secure {
		// Browsers reject an insecure __Host- cookie even on a loopback-only
		// development SP. Production and TLS-terminating-proxy deployments use
		// the stronger prefixed name.
		return providerDevSessionCookie
	}
	return providerSessionCookie
}

func (a *SAMLAuthenticator) ServeMetadata(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.cfg.Provider == nil {
		http.NotFound(w, r)
		return
	}
	metadata, err := a.cfg.Provider.MetadataXML()
	if err != nil {
		writeProviderError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(metadata)
}

func (a *SAMLAuthenticator) operatorFromAssertion(r *http.Request, assertion samlsp.Assertion) (Operator, bool) {
	subject := strings.TrimSpace(assertion.Subject)
	if values := assertion.Attributes[a.cfg.SubjectAttribute]; a.cfg.SubjectAttribute != "" && len(values) > 0 {
		subject = strings.TrimSpace(values[0])
	}
	if subject == "" {
		return Operator{}, false
	}
	role := OperatorRole("")
	for _, value := range assertion.Attributes[a.cfg.RoleAttribute] {
		if a.admin[value] {
			role = OperatorAdmin
			break
		}
		if a.operator[value] {
			role = OperatorOperator
		}
	}
	if role == "" {
		return Operator{}, false
	}
	mfa := false
	for _, value := range assertion.Attributes[a.cfg.MFAAttribute] {
		if a.mfa[value] {
			mfa = true
			break
		}
	}
	if !mfa {
		return Operator{}, false
	}
	email := ""
	if values := assertion.Attributes[a.cfg.EmailAttribute]; len(values) > 0 {
		email = strings.TrimSpace(values[0])
	}
	operator := Operator{ID: subject, Email: email, Role: role, MFA: true}
	if a.cfg.Directory != nil {
		identity, err := a.cfg.Directory.ResolveOperator(r.Context(), subject)
		if err != nil || !identity.Active {
			return Operator{}, false
		}
		role = lesserRole(role, identity.Role)
		if role == "" {
			return Operator{}, false
		}
		operator.ID, operator.Role = identity.ID, role
		if identity.Email != "" {
			operator.Email = identity.Email
		}
	} else if a.cfg.RequireDirectory {
		return Operator{}, false
	}
	return operator, true
}

func (a *SAMLAuthenticator) setTransientCookie(w http.ResponseWriter, name, value string) {
	// SAML HTTP-POST returns from the IdP cross-site. In production the
	// correlation cookie therefore needs SameSite=None + Secure or the browser
	// drops it before ACS and every real SP-initiated login fails. Plaintext is
	// loopback-only and uses Lax because browsers reject insecure None cookies.
	sameSite := http.SameSiteLaxMode
	if a.cfg.Secure {
		sameSite = http.SameSiteNoneMode
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- short-lived HttpOnly state/request correlation; None is paired with Secure for the required cross-site SAML POST.
		Name: name, Value: value, Path: "/provider/v1/auth/saml", HttpOnly: true,
		Secure: a.cfg.Secure, SameSite: sameSite, MaxAge: 600,
	})
}

func (a *SAMLAuthenticator) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: "/provider/v1/auth/saml", MaxAge: -1, HttpOnly: true, Secure: a.cfg.Secure, SameSite: http.SameSiteLaxMode}) // #nosec G124 -- expiry retains HttpOnly/Lax and uses insecure transport only in explicit loopback development mode (CWE-614).
}

// AnyAuthenticator accepts the first positively verified configured identity
// method. There is no fallback identity: every child must itself verify.
type AnyAuthenticator []OperatorAuthenticator

func (a AnyAuthenticator) AuthenticateOperator(r *http.Request) (Operator, bool) {
	for _, authenticator := range a {
		if authenticator == nil {
			continue
		}
		if operator, ok := authenticator.AuthenticateOperator(r); ok {
			return operator, true
		}
	}
	return Operator{}, false
}
