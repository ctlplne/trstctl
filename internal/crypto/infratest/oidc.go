// SPDX-License-Identifier: BUSL-1.1

package infratest

import (
	"crypto/subtle"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
)

// OIDCProvider is a stand-in OpenID Connect identity provider (A273-O1), the
// authorization code flow as OpenID Connect Core 1.0 describes it:
//   - GET /authorize?response_type=code&client_id&redirect_uri&state&nonce
//     answers its sign-in page (a form with a CSRF token bound to a
//     pre-session cookie), or, for a browser it has signed in, redirects to
//     redirect_uri with a one-time code and the state.
//   - POST /login signs the user in, sets its own session cookie and
//     redirects to the client with the code; a wrong password shows the page
//     again.
//   - POST /token (client_secret_basic, grant_type=authorization_code)
//     exchanges the code once for an RS256 ID token (iss, aud, sub, nonce).
//   - GET /jwks publishes the signing key; /.well-known/openid-configuration
//     names the endpoints.
type OIDCProvider struct {
	mu        sync.Mutex
	srv       *httptest.Server
	key       *jose.SigningKey
	passwords map[string][]byte
	clients   map[string]oidcClient
	pending   map[string]oidcAuthorization // sign-in page request -> authorization
	codes     map[string]oidcCode
	sessions  map[string]string // session cookie -> user
	pre       map[string]string // pre-session cookie -> CSRF token
	failed    map[string]int
	signIns   int
	served    []string
}

type oidcClient struct{ secret, redirectURI string }

type oidcAuthorization struct{ client, redirectURI, state, nonce string }

type oidcCode struct {
	oidcAuthorization
	user    string
	expires time.Time
}

// Stand-in identity provider cookie names.
const (
	OIDCSessionCookie = "idp_session"
	OIDCPreCookie     = "idp_pre"
)

// StartOIDCProvider brings up the provider with one user.
func StartOIDCProvider(user, password string) (*OIDCProvider, error) {
	key, err := jose.GenerateRSASigningKey("idp-1")
	if err != nil {
		return nil, err
	}
	p := &OIDCProvider{key: key, passwords: map[string][]byte{user: []byte(password)}, clients: map[string]oidcClient{},
		pending: map[string]oidcAuthorization{}, codes: map[string]oidcCode{}, sessions: map[string]string{}, pre: map[string]string{},
		failed: map[string]int{}}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	return p, nil
}

// URL is the provider's origin, which is also its issuer.
func (p *OIDCProvider) URL() string { return p.srv.URL }

// CAPEM is the provider's self-signed certificate.
func (p *OIDCProvider) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.srv.Certificate().Raw})
}

// Close stops the provider.
func (p *OIDCProvider) Close() { p.srv.Close() }

// AddClient registers a relying party.
func (p *OIDCProvider) AddClient(id, secret, redirectURI string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients[id] = oidcClient{secret: secret, redirectURI: redirectURI}
}

// SignIns is how many password sign-ins succeeded.
func (p *OIDCProvider) SignIns() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.signIns
}

// Failed is how many sign-ins of user the provider refused.
func (p *OIDCProvider) Failed(user string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.failed[user]
}

// SessionCookies are every session cookie value the provider issued.
func (p *OIDCProvider) SessionCookies() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.sessions))
	for id := range p.sessions {
		out = append(out, id)
	}
	return out
}

// Served is every request the provider answered, as "METHOD /path".
func (p *OIDCProvider) Served() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.served...)
}

func (p *OIDCProvider) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.served = append(p.served, r.Method+" "+r.URL.Path)
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeIdPJSON(w, http.StatusOK, map[string]string{"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/authorize",
			"token_endpoint": p.srv.URL + "/token", "jwks_uri": p.srv.URL + "/jwks"})
	case "/jwks":
		doc, err := p.key.PublicJWKS()
		if err != nil {
			http.Error(w, "no signing key", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	case "/authorize":
		q := r.URL.Query()
		client, ok := p.clients[q.Get("client_id")]
		if r.Method != http.MethodGet || !ok || q.Get("response_type") != "code" || q.Get("redirect_uri") != client.redirectURI || q.Get("state") == "" || q.Get("nonce") == "" {
			http.Error(w, "invalid authorization request", http.StatusBadRequest)
			return
		}
		a := oidcAuthorization{client: q.Get("client_id"), redirectURI: client.redirectURI, state: q.Get("state"), nonce: q.Get("nonce")}
		if cookie, err := r.Cookie(OIDCSessionCookie); err == nil && p.sessions[cookie.Value] != "" {
			p.redirectWithCode(w, r, a, p.sessions[cookie.Value])
			return
		}
		request := newWebToken()
		p.pending[request] = a
		p.signInPage(w, r, request, "")
	case "/login":
		if r.Method != http.MethodPost || r.ParseForm() != nil {
			http.Error(w, "post the sign-in form", http.StatusMethodNotAllowed)
			return
		}
		cookie, err := r.Cookie(OIDCPreCookie)
		a, pending := p.pending[r.PostForm.Get("request")]
		if err != nil || p.pre[cookie.Value] == "" || subtle.ConstantTimeCompare([]byte(p.pre[cookie.Value]), []byte(r.PostForm.Get("csrf"))) != 1 || !pending {
			http.Error(w, "the sign-in form expired", http.StatusForbidden)
			return
		}
		user := r.PostForm.Get("username")
		want, known := p.passwords[user]
		if !known || subtle.ConstantTimeCompare(want, []byte(r.PostForm.Get("password"))) != 1 {
			p.failed[user]++
			p.signInPage(w, r, r.PostForm.Get("request"), "Sign-in failed")
			return
		}
		delete(p.pending, r.PostForm.Get("request"))
		delete(p.pre, cookie.Value)
		p.failed[user] = 0
		p.signIns++
		session := newWebToken()
		p.sessions[session] = user
		http.SetCookie(w, &http.Cookie{Name: OIDCPreCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		http.SetCookie(w, &http.Cookie{Name: OIDCSessionCookie, Value: session, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		p.redirectWithCode(w, r, a, user)
	case "/token":
		p.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *OIDCProvider) signInPage(w http.ResponseWriter, r *http.Request, request, message string) {
	pre := ""
	if cookie, err := r.Cookie(OIDCPreCookie); err == nil && p.pre[cookie.Value] != "" {
		pre = cookie.Value
	} else {
		pre = newWebToken()
		p.pre[pre] = newWebToken()
		http.SetCookie(w, &http.Cookie{Name: OIDCPreCookie, Value: pre, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><title>Lab identity provider</title></head><body>
<p class="message">%s</p>
<form method="post" action="/login" id="idp-sign-in">
<input type="hidden" name="csrf" value="%s">
<input type="hidden" name="request" value="%s">
<label>User <input type="text" name="username"></label>
<label>Password <input type="password" name="password"></label>
<button type="submit">Sign in</button>
</form></body></html>`, html.EscapeString(message), p.pre[pre], html.EscapeString(request))
}

func (p *OIDCProvider) redirectWithCode(w http.ResponseWriter, r *http.Request, a oidcAuthorization, user string) {
	code := newWebToken()
	p.codes[code] = oidcCode{oidcAuthorization: a, user: user, expires: time.Now().Add(time.Minute)}
	target, err := url.Parse(a.redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect", http.StatusBadRequest)
		return
	}
	q := target.Query()
	q.Set("code", code)
	q.Set("state", a.state)
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (p *OIDCProvider) token(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	client, known := p.clients[id]
	if r.Method != http.MethodPost || !ok || !known || subtle.ConstantTimeCompare([]byte(client.secret), []byte(secret)) != 1 || r.ParseForm() != nil {
		writeIdPJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	code, found := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	if r.PostForm.Get("grant_type") != "authorization_code" || !found || code.client != id || code.redirectURI != r.PostForm.Get("redirect_uri") || time.Now().After(code.expires) {
		writeIdPJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	claims, err := json.Marshal(map[string]any{"iss": p.srv.URL, "aud": id, "sub": code.user, "nonce": code.nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()})
	if err != nil {
		writeIdPJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	idToken, err := p.key.Sign(claims)
	if err != nil {
		writeIdPJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeIdPJSON(w, http.StatusOK, map[string]any{"access_token": newWebToken(), "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
}

// SSOWebConsole is a stand-in internal console that signs its users in only
// through an OpenID Connect provider (A273-O1): a request without its session
// redirects to the provider's authorization endpoint; its callback exchanges
// the code with the provider directly, checks the ID token's signature,
// issuer, audience and nonce, and sets its own HttpOnly session cookie. A
// settings form carries its own CSRF token.
type SSOWebConsole struct {
	mu       sync.Mutex
	srv      *httptest.Server
	idp      *OIDCProvider
	client   *http.Client
	id, key  string
	states   map[string]string // state -> nonce
	sessions map[string]*webConsoleSession
	signIns  int
	banner   string
	served   []string
}

// Stand-in SSO console cookie name.
const SSOConsoleSessionCookie = "sso_console_session"

// StartSSOWebConsole brings up a console that signs in through idp as the
// relying party clientID.
func StartSSOWebConsole(idp *OIDCProvider, clientID, clientSecret string) *SSOWebConsole {
	c := &SSOWebConsole{idp: idp, client: idp.srv.Client(), id: clientID, key: clientSecret, states: map[string]string{},
		sessions: map[string]*webConsoleSession{}, banner: "welcome"}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(c.serve))
	idp.AddClient(clientID, clientSecret, c.srv.URL+"/oidc/callback")
	return c
}

// URL is the console's origin.
func (c *SSOWebConsole) URL() string { return c.srv.URL }

// CAPEM is the console's self-signed certificate.
func (c *SSOWebConsole) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.srv.Certificate().Raw})
}

// Close stops the console.
func (c *SSOWebConsole) Close() { c.srv.Close() }

// Banner is the setting the operator's task changes.
func (c *SSOWebConsole) Banner() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.banner
}

// SignIns is how many identity provider sign-ins the console accepted.
func (c *SSOWebConsole) SignIns() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.signIns
}

// SessionCookies are every session cookie value the console issued.
func (c *SSOWebConsole) SessionCookies() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.sessions))
	for id := range c.sessions {
		out = append(out, id)
	}
	return out
}

// SignOutAll ends every console session, as a console that expires them does.
func (c *SSOWebConsole) SignOutAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions = map[string]*webConsoleSession{}
}

func (c *SSOWebConsole) serve(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.served = append(c.served, r.Method+" "+r.URL.Path)
	if r.Method == http.MethodPost {
		if origin := r.Header.Get("Origin"); origin != "" && origin != c.srv.URL {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
	}
	if r.URL.Path == "/oidc/callback" {
		c.callback(w, r)
		return
	}
	var session *webConsoleSession
	if cookie, err := r.Cookie(SSOConsoleSessionCookie); err == nil {
		session = c.sessions[cookie.Value]
	}
	if session == nil || r.URL.Path == "/login" {
		// Every request without a session signs in through the provider.
		state, nonce := newWebToken(), newWebToken()
		c.states[state] = nonce
		q := url.Values{"response_type": {"code"}, "client_id": {c.id}, "redirect_uri": {c.srv.URL + "/oidc/callback"},
			"scope": {"openid"}, "state": {state}, "nonce": {nonce}}
		http.Redirect(w, r, c.idp.URL()+"/authorize?"+q.Encode(), http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch r.URL.Path {
	case "/":
		_, _ = fmt.Fprintf(w, `<!doctype html><html><body><h1>SSO lab console</h1><p>Signed in as %s</p><p class="banner">%s</p>
<a href="/settings">Settings</a></body></html>`, html.EscapeString(session.user), html.EscapeString(c.banner))
	case "/settings":
		if r.Method == http.MethodPost {
			if r.ParseForm() != nil || subtle.ConstantTimeCompare([]byte(session.csrf), []byte(r.PostForm.Get("csrf"))) != 1 {
				http.Error(w, "the settings form expired", http.StatusForbidden)
				return
			}
			c.banner = r.PostForm.Get("banner")
			http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
			return
		}
		_, _ = fmt.Fprintf(w, `<!doctype html><html><body><h1>Settings</h1>
<form method="post" action="/settings"><input type="hidden" name="csrf" value="%s">
<label>Banner <input type="text" name="banner" value="%s"></label>
<button type="submit">Save</button></form></body></html>`, session.csrf, html.EscapeString(c.banner))
	default:
		http.NotFound(w, r)
	}
}

// callback exchanges the code with the provider, directly, and checks the ID
// token before it signs the user in.
func (c *SSOWebConsole) callback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	nonce, ok := c.states[state]
	delete(c.states, state)
	if !ok || r.URL.Query().Get("code") == "" {
		http.Error(w, "unknown sign-in", http.StatusBadRequest)
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {r.URL.Query().Get("code")}, "redirect_uri": {c.srv.URL + "/oidc/callback"}}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, c.idp.URL()+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, "sign-in failed", http.StatusBadGateway)
		return
	}
	req.SetBasicAuth(c.id, c.key)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client.Do(req)
	if err != nil {
		http.Error(w, "the identity provider is unreachable", http.StatusBadGateway)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	var answer struct {
		IDToken string `json:"id_token"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &answer) != nil || answer.IDToken == "" {
		http.Error(w, "the identity provider refused the sign-in", http.StatusBadGateway)
		return
	}
	keys, err := c.publishedKeys(r)
	if err != nil {
		http.Error(w, "the identity provider's keys are unavailable", http.StatusBadGateway)
		return
	}
	payload, err := keys.Verify(answer.IDToken)
	var claims struct {
		Iss   string `json:"iss"`
		Aud   string `json:"aud"`
		Sub   string `json:"sub"`
		Nonce string `json:"nonce"`
		Exp   int64  `json:"exp"`
	}
	if err != nil || json.Unmarshal(payload, &claims) != nil || claims.Iss != c.idp.URL() || claims.Aud != c.id || claims.Nonce != nonce ||
		claims.Sub == "" || time.Now().Unix() > claims.Exp {
		http.Error(w, "the ID token does not verify", http.StatusForbidden)
		return
	}
	c.signIns++
	id := newWebToken()
	c.sessions[id] = &webConsoleSession{user: claims.Sub, csrf: newWebToken()}
	http.SetCookie(w, &http.Cookie{Name: SSOConsoleSessionCookie, Value: id, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// publishedKeys reads the JWK Set the identity provider publishes at its
// jwks_uri, as a relying party does, rather than the provider's key in memory.
func (c *SSOWebConsole) publishedKeys(r *http.Request) (*jose.JWKSet, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, c.idp.URL()+"/jwks", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	doc, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: %s", resp.Status)
	}
	return jose.ParseJWKSet(doc)
}
