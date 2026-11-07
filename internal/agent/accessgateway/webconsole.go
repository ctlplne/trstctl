// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	xhtml "golang.org/x/net/html"

	"trstctl.com/trstctl/internal/accessweb"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A273: internal web admin consoles. The browser reaches a console only
// through the session's tunnel and never holds its credential. The gateway
// signs in for the operator as the reviewed template says — filling the
// console's own sign-in form, or adding the vaulted token or basic
// authentication to every request — and keeps every cookie the console
// sets, passing the browser only the few the template names for the
// console's own scripts. The browser's credentials and cookies never reach
// the console, the credential is masked out of every page, and each request
// and response is recorded, masked. Ending the session (its deadline, a
// recall, a terminate) closes its connections and wipes its cookies.

const (
	// webRedirects bounds the redirects one sign-in request follows.
	webRedirects = 5
	// webPageBytes bounds a sign-in page the gateway reads.
	webPageBytes = 1 << 20
	// webMaxSignIns bounds a session's sign-ins: a console that keeps
	// signing the session out stops being signed in to.
	webMaxSignIns = 10
	// webMaxCookies and webCookieBytes bound the cookies a session keeps.
	webMaxCookies  = 64
	webCookieBytes = 4 << 10
	// webSignInTimeout bounds one form sign-in.
	webSignInTimeout = 30 * time.Second
	// webMaskMin is the shortest credential masked out of what the browser
	// receives: a shorter one would mask ordinary words of the page.
	webMaskMin = 8
)

// webAccount is the vaulted account a console session signs in as: a
// username and password (form, basic) or a token (header).
type webAccount struct {
	username, secret []byte
}

func (a webAccount) wipe() {
	secret.Wipe(a.username)
	secret.Wipe(a.secret)
}

// parseWebAccount reads the vaulted credential: {"username","password"}, or
// for a header sign-in {"token"} (a password is taken as the token).
func parseWebAccount(raw []byte, mode string) (webAccount, error) {
	var parsed struct {
		Username secret.JSONBytes `json:"username"`
		Password secret.JSONBytes `json:"password"`
		Token    secret.JSONBytes `json:"token"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return webAccount{}, errors.New("accessgateway: the console account is not a vaulted JSON credential")
	}
	a := webAccount{username: parsed.Username, secret: parsed.Password}
	if mode == accessweb.SignInHeader && len(parsed.Token) > 0 {
		secret.Wipe(a.secret)
		a.secret = parsed.Token
	} else {
		secret.Wipe(parsed.Token)
	}
	switch {
	case len(a.secret) == 0 || len(a.secret) > 4096 || bytes.ContainsAny(a.secret, "\r\n\x00"):
	case mode == accessweb.SignInHeader && !printableBytes(a.secret):
	case mode != accessweb.SignInHeader && (len(a.username) == 0 || len(a.username) > 512 || bytes.ContainsAny(a.username, "\r\n\x00")):
	case mode == accessweb.SignInBasic && bytes.IndexByte(a.username, ':') >= 0:
	default:
		return a, nil
	}
	a.wipe()
	return webAccount{}, errors.New("accessgateway: the console account needs a username and password (a token for a header sign-in)")
}

func printableBytes(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// basicValue is the account's HTTP basic authentication value.
func basicValue(a webAccount) []byte {
	pair := make([]byte, 0, len(a.username)+1+len(a.secret))
	pair = append(append(append(pair, a.username...), ':'), a.secret...)
	defer secret.Wipe(pair)
	out := make([]byte, base64.StdEncoding.EncodedLen(len(pair)))
	base64.StdEncoding.Encode(out, pair)
	return out
}

// webSecretForms are the shapes the account's secret takes in what the
// console or the gateway writes: as is, HTML-escaped, form-encoded, and the
// basic authentication value. Each is a fresh copy the caller wipes.
func webSecretForms(a webAccount, mode string) [][]byte {
	forms := [][]byte{append([]byte(nil), a.secret...)}
	if escaped := appendHTMLEscaped(make([]byte, 0, 6*len(a.secret)), a.secret); !bytes.Equal(escaped, a.secret) {
		forms = append(forms, escaped)
	} else {
		secret.Wipe(escaped)
	}
	if encoded := appendFormEscaped(make([]byte, 0, 3*len(a.secret)), a.secret); !bytes.Equal(encoded, a.secret) {
		forms = append(forms, encoded)
	} else {
		secret.Wipe(encoded)
	}
	if mode == accessweb.SignInBasic {
		forms = append(forms, basicValue(a))
	}
	return forms
}

// appendFormEscaped form-encodes src onto dst byte by byte (no string copy).
func appendFormEscaped(dst, src []byte) []byte {
	const hex = "0123456789ABCDEF"
	for _, c := range src {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '_', c == '.', c == '~':
			dst = append(dst, c)
		case c == ' ':
			dst = append(dst, '+')
		default:
			dst = append(dst, '%', hex[c>>4], hex[c&15])
		}
	}
	return dst
}

// appendHTMLEscaped HTML-escapes src onto dst as html.EscapeString does.
func appendHTMLEscaped(dst, src []byte) []byte {
	for _, c := range src {
		switch c {
		case '&':
			dst = append(dst, "&amp;"...)
		case '<':
			dst = append(dst, "&lt;"...)
		case '>':
			dst = append(dst, "&gt;"...)
		case '"':
			dst = append(dst, "&#34;"...)
		case '\'':
			dst = append(dst, "&#39;"...)
		default:
			dst = append(dst, c)
		}
	}
	return dst
}

func wipeAll(bufs [][]byte) {
	for _, b := range bufs {
		secret.Wipe(b)
	}
}

// webSignInRefused is a sign-in the console judged (or one whose outcome is
// unknown after the password was sent): the session never sends it again.
type webSignInRefused struct{ reason string }

func (e *webSignInRefused) Error() string { return "accessgateway: " + e.reason }

func refusedSignIn(format string, args ...any) error {
	return &webSignInRefused{reason: fmt.Sprintf(format, args...)}
}

// webConsoleState belongs to one console session across its connections:
// the cookies the console set, held here and never sent to the browser, and
// the sign-in's outcome.
type webConsoleState struct {
	mu       sync.Mutex
	cookies  map[string]*secret.Buffer
	order    []string
	signedIn bool
	signIns  int
	refused  error
	closed   bool
	// bounced and bouncedAt are the last request the console answered by
	// signing the session out, so a page that signs out (the console's own
	// sign-out link) is not visited again in a loop.
	bounced   string
	bouncedAt time.Time
	// action is the path the console's sign-in form posts to; the browser
	// may not post there.
	action string
}

func newWebConsoleState() *webConsoleState {
	return &webConsoleState{cookies: map[string]*secret.Buffer{}}
}

// destroy wipes the session's cookies; nothing signs in afterwards.
func (s *webConsoleState) destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, b := range s.cookies {
		b.Destroy()
		delete(s.cookies, name)
	}
	s.order = nil
	s.signedIn, s.closed = false, true
	s.refused = errors.New("accessgateway: the console session ended")
}

// keep stores a cookie the console set; it reports whether the console
// dropped one the session held.
func (s *webConsoleState) keep(c *http.Cookie) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keepLocked(c)
}

// keepLocked stores (or, expired or emptied, drops) a cookie the console set
// and reports whether it dropped one the session held.
func (s *webConsoleState) keepLocked(c *http.Cookie) bool {
	held := false
	if old := s.cookies[c.Name]; old != nil {
		held = true
		old.Destroy()
		delete(s.cookies, c.Name)
		s.order = slices.DeleteFunc(s.order, func(name string) bool { return name == c.Name })
	}
	if s.closed {
		return held
	}
	if c.MaxAge < 0 || c.Value == "" || (!c.Expires.IsZero() && !c.Expires.After(time.Now())) || len(c.Value) > webCookieBytes || len(s.cookies) >= webMaxCookies {
		return held
	}
	b, err := secret.NewFrom([]byte(c.Value))
	if err != nil {
		return held
	}
	s.cookies[c.Name] = b
	s.order = append(s.order, c.Name)
	return false
}

// cookieHeader is the Cookie header the console gets: its own cookies, then
// the template-named ones the browser holds.
func (s *webConsoleState) cookieHeader(browser []*http.Cookie) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cookieHeaderLocked(browser)
}

func (s *webConsoleState) cookieHeaderLocked(browser []*http.Cookie) string {
	// A cookie the template lets the browser hold is the browser's: its
	// value wins over any the gateway kept from the sign-in.
	fromBrowser := map[string]bool{}
	for _, c := range browser {
		fromBrowser[c.Name] = true
	}
	var b strings.Builder
	add := func(name string, value []byte) {
		if b.Len() > 0 {
			b.WriteString("; ")
		}
		b.WriteString(name)
		b.WriteByte('=')
		b.Write(value)
	}
	for _, name := range s.order {
		if !fromBrowser[name] {
			add(name, s.cookies[name].Bytes())
		}
	}
	for _, c := range browser {
		add(c.Name, []byte(c.Value))
	}
	return b.String()
}

// maskCookies masks the session's cookie values out of recorded text.
func (s *webConsoleState) maskCookies(text string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.cookies {
		if v := b.Bytes(); len(v) >= webMaskMin {
			text = strings.ReplaceAll(text, string(v), "[masked:cookie]")
		}
	}
	return text
}

// signedOut records that the console signed the session out answering
// uri, and is where the browser goes next: back to uri, unless the request
// itself signed out (the console dropped the session's cookie, or uri was
// bounced moments ago), when it goes to the console's home page.
func (s *webConsoleState) signedOut(uri string, dropped bool) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signedIn = false
	back := uri
	if dropped || (uri == s.bounced && time.Since(s.bouncedAt) < 30*time.Second) {
		back = "/"
	}
	s.bounced, s.bouncedAt = uri, time.Now()
	return back
}

func (s *webConsoleState) formAction() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.action
}

// webConsoleClient is one connection's way to the console.
type webConsoleClient struct {
	// transport is the session's way to the console; sign-in requests are
	// sent on it one at a time (redirects and cookies are the gateway's).
	transport http.RoundTripper
	target    *url.URL
	in        accessweb.SignIn
	account   webAccount
	rec       *connRecorder
}

func (c *webConsoleClient) event(name, kind, text string) {
	if c.rec != nil {
		c.rec.event(name, kind, text, 0)
	}
}

// ensureSignedIn signs the session in through the console's form once, and
// again after the console signs it out (at most webMaxSignIns times). A
// sign-in the console refused is never sent again in the session: enough of
// them would lock the account out. The sign-in outlives the browser request
// that started it (a navigation must not cut it off after the password was
// sent), bounded by webSignInTimeout.
func (s *webConsoleState) ensureSignedIn(ctx context.Context, c *webConsoleClient) error {
	ctx, cancel := context.WithTimeout(ctx, webSignInTimeout)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.refused != nil:
		return s.refused
	case s.signedIn:
		return nil
	case s.signIns >= webMaxSignIns:
		return errors.New("accessgateway: the console keeps signing the session out")
	}
	s.signIns++
	err := s.formSignInLocked(ctx, c)
	var judged *webSignInRefused
	switch {
	case err == nil:
		s.signedIn = true
	case errors.As(err, &judged):
		s.refused = err
	}
	return err
}

// formSignInLocked fetches the sign-in page, fills its form — keeping its
// hidden fields, such as a CSRF token, and its submit button — and posts it.
// Only a failure before the password was sent may be tried again.
func (s *webConsoleState) formSignInLocked(ctx context.Context, c *webConsoleClient) error {
	login := c.target.ResolveReference(&url.URL{Path: c.in.LoginPath})
	page, pageURL, status, err := s.fetchLocked(ctx, c, http.MethodGet, login, nil, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return refusedSignIn("the console's sign-in page answered %d", status)
	}
	form, ok := findSignInForm(page, c.in.PasswordField)
	if !ok {
		return refusedSignIn("the console's sign-in page has no form with the %s field", c.in.PasswordField)
	}
	if strings.EqualFold(form.method, http.MethodGet) {
		return refusedSignIn("the console's sign-in form would put the password in a URL")
	}
	action, err := pageURL.Parse(form.action)
	if err != nil || !sameOrigin(action, c.target) {
		return refusedSignIn("the console's sign-in form posts off its origin")
	}
	action.Fragment = ""
	s.action = action.Path
	body := form.encode(c.in.UsernameField, c.account.username, c.in.PasswordField, c.account.secret)
	defer secret.Wipe(body)
	final, _, status, err := s.fetchLocked(ctx, c, http.MethodPost, action, body, pageURL)
	switch {
	case err != nil:
		err = refusedSignIn("the console's answer to the sign-in was lost: %v", err)
	case status >= 400:
		err = refusedSignIn("the console refused the sign-in (HTTP %d)", status)
	case hasSignInForm(final, c.in.PasswordField):
		err = refusedSignIn("the console refused the sign-in")
	}
	outcome := "signed in"
	if err != nil {
		outcome = "refused"
	}
	c.event("web", "sign-in", "form POST "+action.Path+": "+outcome)
	return err
}

// fetchLocked makes one sign-in request, following the console's
// same-origin redirects and keeping every cookie it sets; it returns the
// final page (bounded), its URL and its status.
func (s *webConsoleState) fetchLocked(ctx context.Context, c *webConsoleClient, method string, u *url.URL, body []byte, referer *url.URL) ([]byte, *url.URL, int, error) {
	for hop := 0; ; hop++ {
		var reader io.Reader = http.NoBody
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
		if err != nil {
			return nil, nil, 0, err
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req.Header.Set("Accept-Encoding", "identity")
		if body != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", webOrigin(c.target))
		}
		if referer != nil {
			req.Header.Set("Referer", referer.String())
		}
		if cookie := s.cookieHeaderLocked(nil); cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		resp, err := c.transport.RoundTrip(req)
		if err != nil {
			return nil, nil, 0, errors.New("accessgateway: the console is unreachable")
		}
		for _, cookie := range resp.Cookies() {
			s.keepLocked(cookie)
		}
		page, readErr := io.ReadAll(io.LimitReader(resp.Body, webPageBytes))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, nil, 0, errors.New("accessgateway: the console's answer was cut short")
		}
		location := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode > 399 || location == "" {
			return page, u, resp.StatusCode, nil
		}
		if hop >= webRedirects {
			return nil, nil, 0, refusedSignIn("the console's sign-in redirects too often")
		}
		next, err := u.Parse(location)
		if err != nil || !sameOrigin(next, c.target) {
			return nil, nil, 0, refusedSignIn("the console's sign-in redirects off its origin")
		}
		if resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusPermanentRedirect {
			method, body = http.MethodGet, nil
		}
		referer, u = u, next
	}
}

// signInForm is the console's sign-in form as the gateway fills it.
type signInForm struct {
	action, method string
	hidden         []formPair
	submit         *formPair
}

type formPair struct{ name, value string }

// encode is the form's body with the account filled in; the caller wipes it.
func (f signInForm) encode(userField string, user []byte, passField string, password []byte) []byte {
	size := 3*(len(userField)+len(user)+len(passField)+len(password)) + 4
	for _, p := range f.hidden {
		size += 3*(len(p.name)+len(p.value)) + 2
	}
	if f.submit != nil {
		size += 3*(len(f.submit.name)+len(f.submit.value)) + 2
	}
	out := make([]byte, 0, size) // never regrown: no stray copy of the password
	add := func(name string, value []byte) {
		if len(out) > 0 {
			out = append(out, '&')
		}
		out = appendFormEscaped(out, []byte(name))
		out = append(out, '=')
		out = appendFormEscaped(out, value)
	}
	for _, p := range f.hidden {
		if p.name != userField && p.name != passField {
			add(p.name, []byte(p.value))
		}
	}
	add(userField, user)
	add(passField, password)
	if f.submit != nil {
		add(f.submit.name, []byte(f.submit.value))
	}
	return out
}

func hasSignInForm(page []byte, passwordField string) bool {
	_, ok := findSignInForm(page, passwordField)
	return ok
}

// findSignInForm is the first form on the page with the password field: its
// action and method, its hidden fields and its first named submit button.
func findSignInForm(page []byte, passwordField string) (signInForm, bool) {
	z := xhtml.NewTokenizer(bytes.NewReader(page))
	var form *signInForm
	hasPassword := false
	for {
		switch z.Next() {
		case xhtml.ErrorToken:
			if form != nil && hasPassword {
				return *form, true
			}
			return signInForm{}, false
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			name, more := z.TagName()
			attrs := map[string]string{}
			for more {
				var key, value []byte
				key, value, more = z.TagAttr()
				if _, seen := attrs[string(key)]; !seen {
					attrs[string(key)] = string(value)
				}
			}
			switch string(name) {
			case "form":
				form, hasPassword = &signInForm{action: attrs["action"], method: attrs["method"]}, false
			case "input":
				if form == nil {
					continue
				}
				kind := strings.ToLower(attrs["type"])
				switch {
				case attrs["name"] == passwordField:
					hasPassword = true
				case kind == "hidden" && attrs["name"] != "":
					form.hidden = append(form.hidden, formPair{attrs["name"], attrs["value"]})
				case (kind == "submit" || kind == "image") && attrs["name"] != "" && form.submit == nil:
					form.submit = &formPair{attrs["name"], attrs["value"]}
				}
			case "button":
				if kind := strings.ToLower(attrs["type"]); form != nil && (kind == "" || kind == "submit") && attrs["name"] != "" && form.submit == nil {
					form.submit = &formPair{attrs["name"], attrs["value"]}
				}
			}
		case xhtml.EndTagToken:
			if name, _ := z.TagName(); string(name) == "form" && form != nil {
				if hasPassword {
					return *form, true
				}
				form = nil
			}
		}
	}
}

// webOrigin is a URL's origin.
func webOrigin(u *url.URL) string { return u.Scheme + "://" + u.Host }

// sameOrigin compares scheme, host and port (a default port written out
// matches one left implicit).
func sameOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

// webBinaryMedia are the content types whose bodies the browser gets as they
// are: no credential is masked out of an image.
var webBinaryMedia = regexp.MustCompile(`^(image|audio|video|font)/|^application/(octet-stream|zip|gzip|pdf|wasm)$`)

// webSensitiveField is a form or JSON field whose value a recording masks.
var webSensitiveField = regexp.MustCompile(`(?i)pass|pwd|secret|token|credential|api[-_]?key|private`)

var webJSONSensitive = regexp.MustCompile(`("[^"\\]*(?i:pass|pwd|secret|token|credential|api[-_]?key|private)[^"\\]*"\s*:\s*)"(?:[^"\\]|\\.)*"`)

// maskWebFields masks the values of sensitive-looking fields in a recorded
// form or JSON body.
func maskWebFields(body []byte, contentType string) []byte {
	media, _, _ := mime.ParseMediaType(contentType)
	switch {
	case media == "application/x-www-form-urlencoded":
		parts := bytes.Split(body, []byte("&"))
		for i, part := range parts {
			key, _, found := bytes.Cut(part, []byte("="))
			name, err := url.QueryUnescape(string(key))
			if found && err == nil && webSensitiveField.MatchString(name) {
				parts[i] = append(append([]byte(nil), key...), "=[masked:field]"...)
			}
		}
		return bytes.Join(parts, []byte("&"))
	case media == "application/json" || strings.HasSuffix(media, "+json"):
		return webJSONSensitive.ReplaceAll(body, []byte(`$1"[masked:field]"`))
	}
	return body
}

// webMaskBody replaces every credential shape in a console's response with
// as many asterisks before the browser sees it; the length stays, so the
// response's framing stands.
type webMaskBody struct {
	src      io.ReadCloser
	literals [][]byte
	held     []byte
	out      []byte
	eof      bool
}

func (b *webMaskBody) Read(p []byte) (int, error) {
	longest := 0
	for _, l := range b.literals {
		longest = max(longest, len(l))
	}
	for len(b.out) == 0 && !b.eof {
		chunk := make([]byte, 32<<10)
		n, err := b.src.Read(chunk)
		b.held = append(b.held, chunk[:n]...)
		switch {
		case errors.Is(err, io.EOF):
			b.eof = true
		case err != nil:
			return 0, err
		}
		for _, l := range b.literals {
			for i := bytes.Index(b.held, l); i >= 0; {
				for j := range l {
					b.held[i+j] = '*'
				}
				next := bytes.Index(b.held[i+len(l):], l)
				if next < 0 {
					break
				}
				i += len(l) + next
			}
		}
		keep := 0
		if !b.eof {
			keep = min(len(b.held), longest-1)
		}
		b.out = append(b.out, b.held[:len(b.held)-keep]...)
		b.held = append(b.held[:0], b.held[len(b.held)-keep:]...)
	}
	if len(b.out) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.out)
	b.out = b.out[n:]
	return n, nil
}

func (b *webMaskBody) Close() error { return b.src.Close() }

// webDial reaches a console by address: a name that resolves to the
// gateway's own host, a link-local address (a cloud metadata endpoint) or
// another special address is refused, unless the reviewed route itself is a
// loopback lab console (which only a deployment's lab opt-in admits), so a
// registered name re-pointed in DNS never reaches the gateway's neighbours.
func webDial(dial func(context.Context, string, string) (net.Conn, error), route *url.URL) func(context.Context, string, string) (net.Conn, error) {
	if dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		dial = d.DialContext
	}
	host := strings.ToLower(route.Hostname())
	lab := host == "localhost"
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		lab = true
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		name, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		var ips []net.IP
		if ip := net.ParseIP(name); ip != nil {
			ips = []net.IP{ip}
		} else {
			found, err := net.DefaultResolver.LookupIPAddr(ctx, name)
			if err != nil {
				return nil, err
			}
			for _, a := range found {
				ips = append(ips, a.IP)
			}
		}
		lastErr := errors.New("accessgateway: the console's name has no address")
		for _, ip := range ips {
			special := ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
			if special && (!lab || !ip.IsLoopback()) {
				lastErr = fmt.Errorf("accessgateway: the console's address %s is the gateway's own host or a special address", ip)
				continue
			}
			conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

// webGatewayPage is the gateway's own answer to the browser.
func webGatewayPage(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!doctype html><title>trstctl access gateway</title><p>%s</p>\n", message)
}

// serveWebConsole relays one browser connection to the console (A273).
func serveWebConsole(ctx context.Context, client net.Conn, raw []byte, intent SessionIntent, state *webConsoleState, dial func(context.Context, string, string) (net.Conn, error), rec *connRecorder) error {
	in := intent.WebSignIn
	if in == nil || in.Validate() != nil || state == nil {
		return errors.New("accessgateway: the console session has no reviewed sign-in")
	}
	account, err := parseWebAccount(raw, in.Mode)
	if err != nil {
		return err
	}
	defer account.wipe()
	route, err := url.Parse(intent.UpstreamURL)
	if err != nil {
		return errors.New("accessgateway: the console session's route is not a URL")
	}
	target, transport, err := httpUpstream{URL: intent.UpstreamURL, CAPEM: intent.UpstreamCAPEM, ServerName: intent.UpstreamServerName}.transport(webDial(dial, route))
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	target.Path, target.RawPath = "", ""
	c := &webConsoleClient{transport: transport, target: target, in: *in, account: account, rec: rec}
	var authorization string
	switch in.Mode {
	case accessweb.SignInBasic:
		value := basicValue(account)
		authorization = "Basic " + string(value)
		secret.Wipe(value)
	case accessweb.SignInHeader:
		authorization = in.HeaderPrefix + string(account.secret)
	}
	var masks [][]byte
	for _, form := range webSecretForms(account, in.Mode) {
		if len(form) >= webMaskMin {
			masks = append(masks, form)
		} else {
			secret.Wipe(form)
		}
	}
	defer wipeAll(masks)
	proxy := &httputil.ReverseProxy{
		Rewrite:        func(r *httputil.ProxyRequest) { c.rewrite(r, state, authorization) },
		Transport:      transport,
		ModifyResponse: func(resp *http.Response) error { return c.response(resp, state, masks) },
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			webGatewayPage(w, http.StatusBadGateway, "The access gateway could not reach the console.")
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if in.Mode == accessweb.SignInForm {
			if r.URL.Path == in.LoginPath || (r.URL.Path == state.formAction() && r.Method != http.MethodGet && r.Method != http.MethodHead) {
				// The console's sign-in is the gateway's: the browser never
				// posts a password to it.
				if r.Method != http.MethodGet && r.Method != http.MethodHead {
					c.event("web", "refused", r.Method+" "+r.URL.Path+": the gateway signs in for the operator")
					webGatewayPage(w, http.StatusForbidden, "The access gateway signs in to this console for you.")
					return
				}
				if err := state.ensureSignedIn(ctx, c); err != nil {
					webGatewayPage(w, http.StatusBadGateway, "The access gateway could not sign in to the console.")
					return
				}
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			if err := state.ensureSignedIn(ctx, c); err != nil {
				webGatewayPage(w, http.StatusBadGateway, "The access gateway could not sign in to the console.")
				return
			}
		}
		c.recordRequest(r, state)
		proxy.ServeHTTP(w, r)
	})
	listener := newOneConnListener(client)
	server := &http.Server{
		Handler: handler, MaxHeaderBytes: clickhouseMaxHeader, ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:    log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	go func() { <-listener.closed; _ = server.Close() }()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, errOneConnDone) {
		return err
	}
	return nil
}

// rewrite sends the browser's request to the console: the console's own
// cookies and the session's sign-in replace whatever credentials and cookies
// the browser sent, and same-origin checks see the console's origin.
func (c *webConsoleClient) rewrite(r *httputil.ProxyRequest, state *webConsoleState, authorization string) {
	r.SetURL(c.target)
	r.Out.Host = c.target.Host
	var browser []*http.Cookie
	for _, cookie := range r.In.Cookies() {
		if c.in.AllowsBrowserCookie(cookie.Name) {
			browser = append(browser, cookie)
		}
	}
	for _, h := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip"} {
		r.Out.Header.Del(h)
	}
	if cookie := state.cookieHeader(browser); cookie != "" {
		r.Out.Header.Set("Cookie", cookie)
	}
	r.Out.Header.Set("Accept-Encoding", "identity")
	if r.In.Header.Get("Origin") != "" {
		r.Out.Header.Set("Origin", webOrigin(c.target))
	}
	if referer, err := url.Parse(r.In.Header.Get("Referer")); err == nil && referer.Path != "" {
		r.Out.Header.Set("Referer", webOrigin(c.target)+referer.RequestURI())
	} else {
		r.Out.Header.Del("Referer")
	}
	switch c.in.Mode {
	case accessweb.SignInBasic:
		r.Out.Header.Set("Authorization", authorization)
	case accessweb.SignInHeader:
		r.Out.Header.Set(c.in.Header, authorization)
	}
}

// response keeps the console's cookies, keeps the browser on the tunnel,
// masks the credential out of the body and records the answer.
func (c *webConsoleClient) response(resp *http.Response, state *webConsoleState, masks [][]byte) error {
	var browser []*http.Cookie
	dropped := false
	for _, cookie := range resp.Cookies() {
		if c.in.AllowsBrowserCookie(cookie.Name) {
			browser = append(browser, cookie)
			continue
		}
		if state.keep(cookie) && (cookie.MaxAge < 0 || cookie.Value == "") {
			dropped = true
		}
	}
	resp.Header.Del("Set-Cookie")
	for _, cookie := range browser {
		pass := &http.Cookie{Name: cookie.Name, Value: cookie.Value, Path: "/", MaxAge: cookie.MaxAge, Expires: cookie.Expires, HttpOnly: cookie.HttpOnly, SameSite: http.SameSiteStrictMode} // #nosec G124 -- the browser is on the CLI's plain-http loopback tunnel, so a Secure cookie would never come back; only template-named script cookies pass (CWE-614)
		if v := pass.String(); v != "" {
			resp.Header.Add("Set-Cookie", v)
		}
	}
	// No basic-authentication prompt invites the operator to type a password.
	for _, h := range []string{"WWW-Authenticate", "Proxy-Authenticate", "Alt-Svc", "Strict-Transport-Security"} {
		resp.Header.Del(h)
	}
	status := strconv.Itoa(resp.StatusCode)
	if location := resp.Header.Get("Location"); location != "" {
		if next, err := resp.Request.URL.Parse(location); err == nil && sameOrigin(next, c.target) {
			if c.in.Mode == accessweb.SignInForm && next.Path == c.in.LoginPath && resp.Request.URL.Path != c.in.LoginPath {
				// The console signed the session out: sign in again at the
				// next request and send the browser back where it was (home,
				// when the request itself signed out or was not a read).
				uri := "/"
				if resp.Request.Method == http.MethodGet || resp.Request.Method == http.MethodHead {
					uri = resp.Request.URL.RequestURI()
				}
				back := state.signedOut(uri, dropped)
				_ = resp.Body.Close()
				resp.StatusCode, resp.Status = http.StatusSeeOther, "303 See Other"
				resp.Header = http.Header{"Location": {back}, "Cache-Control": {"no-store"}}
				resp.Body, resp.ContentLength = http.NoBody, 0
				c.event("result", "response", status+": signed out by the console; the gateway signs in again")
				return nil
			}
			resp.Header.Set("Location", next.RequestURI())
		}
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		c.event("result", "response", status+" stream "+strings.ToLower(resp.Header.Get("Upgrade")))
		return nil
	}
	media, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if len(masks) > 0 && !webBinaryMedia.MatchString(media) {
		resp.Body = &webMaskBody{src: resp.Body, literals: masks}
	}
	resp.Body = &recordedBody{ReadCloser: resp.Body, done: func(head []byte, size int) {
		c.event("result", "response", state.maskCookies(status+" "+media+": "+boundedHTTPText(head, size)))
	}}
	return nil
}

// recordRequest records the browser's request: its method and target, and a
// form or JSON body with sensitive-looking fields masked.
func (c *webConsoleClient) recordRequest(r *http.Request, state *webConsoleState) {
	if c.rec == nil {
		return
	}
	text := r.Method + " " + r.URL.RequestURI()
	if r.Body != nil && r.ContentLength != 0 && r.Header.Get("Upgrade") == "" {
		body := bufio.NewReaderSize(r.Body, clickhouseRecordBytes+1)
		head, _ := body.Peek(clickhouseRecordBytes)
		if len(head) > 0 {
			masked := maskWebFields(append([]byte(nil), head...), r.Header.Get("Content-Type"))
			size := len(masked)
			if r.ContentLength > int64(len(head)) {
				size = int(r.ContentLength)
			}
			text += " body=" + boundedHTTPText(masked, size)
		}
		r.Body = struct {
			io.Reader
			io.Closer
		}{body, r.Body}
	}
	c.event("web", "request", state.maskCookies(text))
}
