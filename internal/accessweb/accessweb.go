// SPDX-License-Identifier: BUSL-1.1

// Package accessweb validates an internal web admin console's reviewed route
// and the sign-in an access template sets for it (A273). It holds no
// credentials and performs no network calls.
package accessweb

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// TargetWeb is the access target type of an internal web admin console.
const TargetWeb = "webconsole"

// The ways the gateway signs in to a console for the operator.
const (
	// SignInForm: the gateway fetches the console's sign-in page, fills its
	// form (hidden fields such as a CSRF token kept) and submits it itself;
	// it holds the session cookies the console sets.
	SignInForm = "form"
	// SignInHeader: the gateway adds the vaulted token to every request in
	// the named header.
	SignInHeader = "header"
	// SignInBasic: the gateway adds HTTP basic authentication to every
	// request.
	SignInBasic = "basic"
	// SignInSSO (A273-O1): the console signs its users in through an
	// identity provider. The gateway starts the console's sign-in at its
	// page, follows it to the provider named on the console's route, fills
	// the provider's form itself and follows it back; the browser never
	// reaches the provider, and both sides' cookies stay at the gateway.
	SignInSSO = "sso"
)

// MaxBrowserCookies bounds the cookies a template lets the browser hold.
const MaxBrowserCookies = 8

// SignIn is how the gateway signs in to a console, set per access template
// and bound into the reviewed request. The browser never receives the
// credential or the console's cookies; BrowserCookies names the few a
// console's own scripts must read (a double-submit CSRF token), which pass
// to the browser — never a session cookie.
type SignIn struct {
	Mode           string   `json:"mode"`
	LoginPath      string   `json:"login_path,omitempty"`
	UsernameField  string   `json:"username_field,omitempty"`
	PasswordField  string   `json:"password_field,omitempty"`
	Header         string   `json:"header,omitempty"`
	HeaderPrefix   string   `json:"header_prefix,omitempty"`
	BrowserCookies []string `json:"browser_cookies,omitempty"`
}

var (
	// formField is an HTML form field name a sign-in may fill.
	formField = regexp.MustCompile(`^[A-Za-z0-9_.:\[\]-]{1,128}$`)
	// headerName is an HTTP header field name (RFC 9110 token).
	headerName = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
	// cookieName is a cookie name (RFC 6265 token).
	cookieName = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
)

// reservedHeaders are headers a sign-in may not set: the connection's own
// framing, the cookies the gateway keeps, and the forwarding headers.
var reservedHeaders = map[string]bool{"host": true, "cookie": true, "set-cookie": true, "content-length": true,
	"transfer-encoding": true, "connection": true, "upgrade": true, "te": true, "trailer": true, "keep-alive": true,
	"proxy-authorization": true, "proxy-authenticate": true, "proxy-connection": true, "origin": true, "referer": true,
	"forwarded": true, "x-forwarded-for": true, "x-forwarded-host": true, "x-forwarded-proto": true}

// Validate checks a sign-in recipe; it names fields and paths, never a
// credential.
func (s SignIn) Validate() error {
	switch s.Mode {
	case SignInForm, SignInSSO:
		if s.Header != "" || s.HeaderPrefix != "" {
			return errors.New("a form or single sign-on sign-in sets no header")
		}
		if err := validPath(s.LoginPath); err != nil {
			return errors.New("a form or single sign-on sign-in names the console's sign-in page as a path (/login), without query or fragment")
		}
		if !formField.MatchString(s.UsernameField) || !formField.MatchString(s.PasswordField) || s.UsernameField == s.PasswordField {
			return errors.New("a form or single sign-on sign-in names its distinct username and password fields")
		}
	case SignInHeader:
		if s.LoginPath != "" || s.UsernameField != "" || s.PasswordField != "" {
			return errors.New("a header sign-in fills no form")
		}
		if !headerName.MatchString(s.Header) || reservedHeaders[strings.ToLower(s.Header)] {
			return errors.New("a header sign-in names the header its token goes in (not a framing, cookie or forwarding header)")
		}
		if len(s.HeaderPrefix) > 64 || !printableASCII(s.HeaderPrefix) {
			return errors.New("a header prefix is up to 64 printable characters")
		}
	case SignInBasic:
		if s.LoginPath != "" || s.UsernameField != "" || s.PasswordField != "" || s.Header != "" || s.HeaderPrefix != "" {
			return errors.New("a basic sign-in names no form or header")
		}
	default:
		return errors.New("a web sign-in mode is form, sso, header or basic")
	}
	if len(s.BrowserCookies) > MaxBrowserCookies {
		return errors.New("a template lets the browser hold at most 8 cookies")
	}
	seen := map[string]bool{}
	for _, name := range s.BrowserCookies {
		if !cookieName.MatchString(name) || seen[name] {
			return errors.New("browser cookies are distinct cookie names")
		}
		seen[name] = true
	}
	return nil
}

// AllowsBrowserCookie reports whether the browser may hold the named cookie.
func (s SignIn) AllowsBrowserCookie(name string) bool {
	for _, allowed := range s.BrowserCookies {
		if allowed == name {
			return true
		}
	}
	return false
}

// Route is where a console answers: an origin, or the path under one that the
// console lives under (A273-O3), with no query, fragment or user
// information, over https — plain http only on a loopback address a lab
// opted into — with the CA and server name its certificate is checked
// against (no CA: the system roots).
type Route struct {
	URL        string `json:"url"`
	CAPEM      string `json:"ca_pem,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	// SignInURL (A273-O1) is the origin of the identity provider the console
	// signs its users in through, with the CA and name its certificate is
	// checked against. A single sign-on template needs it; the gateway
	// follows the console's sign-in to this origin and no other.
	SignInURL        string `json:"sign_in_url,omitempty"`
	SignInCAPEM      string `json:"sign_in_ca_pem,omitempty"`
	SignInServerName string `json:"sign_in_server_name,omitempty"`
}

// hostName is a DNS name a server certificate may be checked against.
var hostName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// Validate checks a route; allowLoopback admits a loopback address (a lab).
func (r Route) Validate(allowLoopback bool) error {
	if len(r.URL) > 2048 || strings.ContainsAny(r.URL, "\r\n\x00 ") {
		return errors.New("a console URL is a single origin under 2048 characters")
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return errors.New("a console URL is an origin (https://host[:port]) or a path under one, without user information, query or fragment")
	}
	if trimmed := strings.TrimSuffix(u.Path, "/"); trimmed != "" && (u.RawPath != "" || strings.HasSuffix(trimmed, "/") || validPath(trimmed) != nil) {
		return errors.New("a console's path is plain segments under its origin, such as /console/")
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	switch {
	case loopback && !allowLoopback:
		return errors.New("a loopback console needs the lab opt-in")
	case u.Scheme == "http" && !loopback:
		return errors.New("a console is reached over https (its credential would cross the network in the clear)")
	case u.Scheme != "https" && u.Scheme != "http":
		return errors.New("a console is reached over https")
	}
	if len(r.CAPEM) > 64<<10 || (r.CAPEM != "" && !strings.Contains(r.CAPEM, "-----BEGIN CERTIFICATE-----")) {
		return errors.New("a console's CA is PEM certificates under 64 KiB")
	}
	if r.ServerName != "" && !hostName.MatchString(r.ServerName) {
		return errors.New("a console's server name is a DNS name")
	}
	if r.SignInURL == "" {
		if r.SignInCAPEM != "" || r.SignInServerName != "" {
			return errors.New("an identity provider's CA or server name needs its sign_in_url")
		}
		return nil
	}
	idp := Route{URL: r.SignInURL, CAPEM: r.SignInCAPEM, ServerName: r.SignInServerName}
	if err := idp.Validate(allowLoopback); err != nil || idp.Prefix() != "/" {
		return errors.New("a console's identity provider is an origin over https (https://idp.example), with its own CA and server name")
	}
	if sameOrigin(idp.Origin(), r.Origin()) {
		return errors.New("a console's identity provider is another origin than the console's")
	}
	return nil
}

// sameOrigin compares two origins' scheme, host and port, a default port
// written out matching one left implicit.
func sameOrigin(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return a == b
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Hostname(), ub.Hostname()) && port(ua) == port(ub)
}

// Origin is the route's origin: its scheme and host, without a path.
func (r Route) Origin() string {
	u, err := url.Parse(r.URL)
	if err != nil || u.Host == "" {
		return strings.TrimSuffix(r.URL, "/")
	}
	return u.Scheme + "://" + u.Host
}

// Prefix is the path the console lives under, ending in a slash: "/" for a
// console at its origin.
func (r Route) Prefix() string {
	u, err := url.Parse(r.URL)
	if err != nil || strings.TrimSuffix(u.Path, "/") == "" {
		return "/"
	}
	return strings.TrimSuffix(u.Path, "/") + "/"
}

// Within reports whether a request path stays under the console's path. A
// console at its origin takes every path. Under a path, it takes that path
// and what lies below it, never with a dot segment or a backslash that a
// server could resolve to climb out of it (A273-O3).
func (r Route) Within(p string) bool {
	prefix := r.Prefix()
	if prefix == "/" {
		return true
	}
	if strings.ContainsRune(p, '\\') {
		return false
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return strings.HasPrefix(p, prefix)
}

// SignsInWithin reports whether a sign-in stays under the console's path: a
// form sign-in's page must lie under it, since the gateway posts the
// account's password there, and a single sign-on starts there.
func (r Route) SignsInWithin(s SignIn) bool {
	return s.Mode != SignInForm && s.Mode != SignInSSO || r.Within(s.LoginPath)
}

// SignsInThrough reports whether a route can carry a sign-in: a single
// sign-on needs the route's identity provider, and only it uses one.
func (r Route) SignsInThrough(s SignIn) bool {
	return (s.Mode == SignInSSO) == (r.SignInURL != "")
}

func validPath(p string) error {
	if p == "" || len(p) > 512 || p[0] != '/' || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "?#\\\r\n\x00 ") {
		return errors.New("invalid path")
	}
	u, err := url.Parse(p)
	if err != nil || u.Path != p || u.Host != "" || u.Scheme != "" {
		return errors.New("invalid path")
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "." || segment == ".." {
			return errors.New("invalid path")
		}
	}
	return nil
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
