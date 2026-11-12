// SPDX-License-Identifier: BUSL-1.1

package infratest

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// WebConsole is a stand-in internal web admin console (A273), built the way
// such consoles commonly are: a sign-in page whose form carries a CSRF token
// bound to a pre-session cookie and posts to another path, an HttpOnly
// session cookie, an absolute redirect to the sign-in page when signed out,
// same-origin checks on every POST, a settings form with its own CSRF token,
// a JavaScript-readable XSRF-TOKEN cookie, and a careless account page that
// echoes the account's password. Its API also takes HTTP basic
// authentication or an API key header. A links page and a JSON answer name
// the console's own origin, as many consoles' pages do (A273-O2).
type WebConsole struct {
	mu        sync.Mutex
	srv       *httptest.Server
	passwords map[string][]byte
	tokens    map[string]string // API key -> user
	sessions  map[string]*webConsoleSession
	pre       map[string]string // pre-session cookie -> sign-in CSRF token
	failed    map[string]int
	signIns   int
	banner    string
	newPass   int
	served    []string
}

type webConsoleSession struct {
	user, csrf string
}

// Stand-in cookie names.
const (
	WebConsoleSessionCookie = "console_session"
	WebConsolePreCookie     = "console_pre"
	WebConsoleXSRFCookie    = "XSRF-TOKEN"
)

// StartWebConsole brings up the console with one administrator.
func StartWebConsole(admin, password string) *WebConsole {
	c := &WebConsole{passwords: map[string][]byte{admin: []byte(password)}, tokens: map[string]string{},
		sessions: map[string]*webConsoleSession{}, pre: map[string]string{}, failed: map[string]int{}, banner: "welcome"}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(c.serve))
	return c
}

// URL is the console's origin.
func (c *WebConsole) URL() string { return c.srv.URL }

// CAPEM is the console's self-signed certificate.
func (c *WebConsole) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.srv.Certificate().Raw})
}

// Close stops the console.
func (c *WebConsole) Close() { c.srv.Close() }

// SetPassword sets (or adds) an account's password.
func (c *WebConsole) SetPassword(user, password string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.passwords[user] = []byte(password)
}

// AddToken adds an API key for user.
func (c *WebConsole) AddToken(token, user string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens[token] = user
}

// Banner is the setting the operator's task changes.
func (c *WebConsole) Banner() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.banner
}

// Failed is how many sign-ins of user the console refused.
func (c *WebConsole) Failed(user string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failed[user]
}

// SignIns is how many form sign-ins succeeded.
func (c *WebConsole) SignIns() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.signIns
}

// NewPasswordsSubmitted is how many settings posts carried a new password.
func (c *WebConsole) NewPasswordsSubmitted() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.newPass
}

// SessionCookies are every session cookie value the console issued.
func (c *WebConsole) SessionCookies() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.sessions))
	for id := range c.sessions {
		out = append(out, id)
	}
	return out
}

// Served is every request the console answered, as "METHOD /path".
func (c *WebConsole) Served() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.served...)
}

func newWebToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (c *WebConsole) serve(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.served = append(c.served, r.Method+" "+r.URL.Path)
	if r.Method == http.MethodPost {
		if origin := r.Header.Get("Origin"); origin != "" && origin != c.srv.URL {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
	}
	session := c.sessionFor(r)
	switch r.URL.Path {
	case "/login":
		c.loginPage(w, r, "")
	case "/session":
		c.signIn(w, r)
	case "/logout":
		if cookie, err := r.Cookie(WebConsoleSessionCookie); err == nil {
			delete(c.sessions, cookie.Value)
		}
		http.SetCookie(w, &http.Cookie{Name: WebConsoleSessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, c.srv.URL+"/login", http.StatusFound)
	case "/api/whoami":
		user := ""
		if session != nil {
			user = session.user
		} else if name, password, ok := r.BasicAuth(); ok {
			if c.passwordMatches(name, password) {
				user = name
			} else {
				c.failed[name]++
			}
		} else if key := r.Header.Get("X-Api-Key"); key != "" {
			user = c.tokens[key]
		}
		if user == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="lab console"`)
			http.Error(w, "sign in", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"user": user})
	default:
		if session == nil {
			http.Redirect(w, r, c.srv.URL+"/login", http.StatusFound)
			return
		}
		c.signedIn(w, r, session)
	}
}

func (c *WebConsole) sessionFor(r *http.Request) *webConsoleSession {
	cookie, err := r.Cookie(WebConsoleSessionCookie)
	if err != nil {
		return nil
	}
	return c.sessions[cookie.Value]
}

func (c *WebConsole) passwordMatches(user, password string) bool {
	want, ok := c.passwords[user]
	return ok && subtle.ConstantTimeCompare(want, []byte(password)) == 1
}

func (c *WebConsole) loginPage(w http.ResponseWriter, r *http.Request, message string) {
	pre := ""
	if cookie, err := r.Cookie(WebConsolePreCookie); err == nil && c.pre[cookie.Value] != "" {
		pre = cookie.Value
	} else {
		pre = newWebToken()
		c.pre[pre] = newWebToken()
		http.SetCookie(w, &http.Cookie{Name: WebConsolePreCookie, Value: pre, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><title>Lab console sign-in</title></head><body>
<p class="message">%s</p>
<form method="post" action="/session" id="sign-in">
<input type="hidden" name="csrf" value="%s">
<label>User <input type="text" name="username"></label>
<label>Password <input type="password" name="password"></label>
<input type="checkbox" name="remember" value="1">
<button type="submit" name="action" value="sign-in">Sign in</button>
</form></body></html>`, html.EscapeString(message), c.pre[pre])
}

func (c *WebConsole) signIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.ParseForm() != nil {
		http.Error(w, "post the sign-in form", http.StatusMethodNotAllowed)
		return
	}
	cookie, err := r.Cookie(WebConsolePreCookie)
	if err != nil || c.pre[cookie.Value] == "" || subtle.ConstantTimeCompare([]byte(c.pre[cookie.Value]), []byte(r.PostForm.Get("csrf"))) != 1 || r.PostForm.Get("action") != "sign-in" {
		http.Error(w, "the sign-in form expired", http.StatusForbidden)
		return
	}
	user := r.PostForm.Get("username")
	if !c.passwordMatches(user, r.PostForm.Get("password")) {
		c.failed[user]++
		c.loginPage(w, r, "Sign-in failed")
		return
	}
	delete(c.pre, cookie.Value)
	c.failed[user] = 0
	c.signIns++
	id := newWebToken()
	c.sessions[id] = &webConsoleSession{user: user, csrf: newWebToken()}
	http.SetCookie(w, &http.Cookie{Name: WebConsolePreCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: WebConsoleSessionCookie, Value: id, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (c *WebConsole) signedIn(w http.ResponseWriter, r *http.Request, s *webConsoleSession) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch r.URL.Path {
	case "/":
		http.SetCookie(w, &http.Cookie{Name: WebConsoleXSRFCookie, Value: s.csrf, Path: "/", Secure: true, SameSite: http.SameSiteLaxMode}) // #nosec G124 -- a double-submit CSRF token the page's scripts must read (CWE-1004)
		_, _ = fmt.Fprintf(w, `<!doctype html><html><body><h1>Lab console</h1><p>Signed in as %s</p><p class="banner">%s</p>
<a href="/settings">Settings</a> <a href="/account">Account</a> <a href="/logout">Sign out</a></body></html>`, html.EscapeString(s.user), html.EscapeString(c.banner))
	case "/settings":
		if r.Method == http.MethodPost {
			if r.ParseForm() != nil || subtle.ConstantTimeCompare([]byte(s.csrf), []byte(r.PostForm.Get("csrf"))) != 1 {
				http.Error(w, "the settings form expired", http.StatusForbidden)
				return
			}
			c.banner = r.PostForm.Get("banner")
			if r.PostForm.Get("new_password") != "" {
				c.newPass++
			}
			http.Redirect(w, r, c.srv.URL+"/settings?saved=1", http.StatusSeeOther)
			return
		}
		_, _ = fmt.Fprintf(w, `<!doctype html><html><body><h1>Settings</h1>
<form method="post" action="/settings"><input type="hidden" name="csrf" value="%s">
<label>Banner <input type="text" name="banner" value="%s"></label>
<label>New service password <input type="password" name="new_password"></label>
<button type="submit">Save</button></form></body></html>`, s.csrf, html.EscapeString(c.banner))
	case "/links":
		// Absolute links to its own origin: a <base>, a scheme-relative
		// script, an anchor, a WebSocket URL, a Refresh and a Link header,
		// a Content-Security-Policy naming it, and a look-alike origin
		// that is not the console's.
		authority := strings.TrimPrefix(c.srv.URL, "https://")
		w.Header().Set("Refresh", "600; url="+c.srv.URL+"/settings")
		w.Header().Set("Link", "<"+c.srv.URL+"/app.css>; rel=preload; as=style")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' wss://"+authority+"; img-src "+authority+" data:; upgrade-insecure-requests")
		_, _ = fmt.Fprintf(w, `<!doctype html><html><head><base href="%[1]s/"><script src="//%[2]s/app.js"></script></head><body>
<a href="%[1]s/settings" id="absolute">Settings</a> <a href="%[1]s.example/elsewhere" id="look-alike">Elsewhere</a>
<script>var events = "wss://%[2]s/events";</script></body></html>`, c.srv.URL, authority)
	case "/api/links":
		// A JSON answer whose encoder escapes slashes.
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"self":"%s"}`, strings.ReplaceAll(c.srv.URL+"/api/whoami", "/", `\/`))
	case "/account":
		// A careless page: it shows the account's own password.
		_, _ = fmt.Fprintf(w, `<!doctype html><html><body><h1>Account</h1><input type="password" name="current" value="%s"></body></html>`,
			html.EscapeString(string(c.passwords[s.user])))
	default:
		http.NotFound(w, r)
	}
}
