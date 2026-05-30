package api

import (
	"context"
	"net/http"
	"time"

	"certctl.io/certctl/internal/auth"
)

// Cookie names for the browser OIDC login + session flow.
const (
	sessionCookieName = "certctl_session"
	stateCookieName   = "certctl_oidc_state"
	nonceCookieName   = "certctl_oidc_nonce"
)

// AuthConfig configures the browser OIDC login and session bridge the web UI
// uses (F12). The OIDC machinery itself is S3.6's: the code exchange and
// id_token verification are seams so production wires the real provider while
// tests inject fakes.
type AuthConfig struct {
	AuthEndpoint  string // provider authorization endpoint
	ClientID      string
	RedirectURI   string // this server's /auth/callback URL, registered with the provider
	DefaultTenant string // tenant assigned to a logged-in user (until per-user mapping lands)
	// Exchange swaps an authorization code for an id_token at the provider.
	Exchange func(ctx context.Context, code string) (idToken string, err error)
	// VerifyIDToken validates an id_token against the expected nonce and returns
	// its claims (production: auth.OIDCVerifier.Verify).
	VerifyIDToken func(idToken, nonce string) (auth.Claims, error)
	Sessions      *auth.SessionIssuer
	LoginRedirect string // where to send the browser after login (default "/")
	Secure        bool   // set the Secure flag on cookies (true behind TLS)
}

type meResponse struct {
	Subject  string `json:"subject"`
	TenantID string `json:"tenant_id"`
	Email    string `json:"email,omitempty"`
}

// authLogin starts the OIDC flow: it sets short-lived state and nonce cookies
// and redirects the browser to the provider.
func (a *API) authLogin(w http.ResponseWriter, r *http.Request) {
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
	a.setTransientCookie(w, stateCookieName, state)
	a.setTransientCookie(w, nonceCookieName, nonce)
	url := auth.AuthCodeURL(a.auth.AuthEndpoint, a.auth.ClientID, a.auth.RedirectURI, state, nonce)
	http.Redirect(w, r, url, http.StatusFound)
}

// authCallback completes the flow: verify state, exchange the code, verify the
// id_token against the nonce, mint a session, and redirect to the UI.
func (a *API) authCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil || stateCookie.Value == "" || stateCookie.Value != q.Get("state") {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid OIDC state"))
		return
	}
	code := q.Get("code")
	if code == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "missing authorization code"))
		return
	}
	idToken, err := a.auth.Exchange(r.Context(), code)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadGateway, "token exchange failed"))
		return
	}
	nonce := ""
	if c, err := r.Cookie(nonceCookieName); err == nil {
		nonce = c.Value
	}
	claims, err := a.auth.VerifyIDToken(idToken, nonce)
	if err != nil {
		a.writeError(w, errStatus(http.StatusUnauthorized, "id_token verification failed"))
		return
	}
	token, err := a.auth.Sessions.Issue(claims.Subject, a.auth.DefaultTenant, claims.Email)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.setSessionCookie(w, token)
	a.clearCookie(w, stateCookieName)
	a.clearCookie(w, nonceCookieName)
	redirect := a.auth.LoginRedirect
	if redirect == "" {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// authMe returns the current session's principal, or 401 if unauthenticated.
func (a *API) authMe(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.sessionFrom(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	a.writeJSON(w, http.StatusOK, meResponse{Subject: sess.Subject, TenantID: sess.TenantID, Email: sess.Email})
}

// authLogout clears the session cookie.
func (a *API) authLogout(w http.ResponseWriter, _ *http.Request) {
	a.clearCookie(w, sessionCookieName)
	w.WriteHeader(http.StatusNoContent)
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
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", HttpOnly: true,
		Secure: a.auth.Secure, SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
}

func (a *API) setSessionCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: value, Path: "/", HttpOnly: true,
		Secure: a.auth.Secure, SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(12 * time.Hour),
	})
}

func (a *API) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", HttpOnly: true,
		Secure: a.auth.Secure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}
