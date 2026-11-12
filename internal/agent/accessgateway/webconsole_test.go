// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/accessweb"
	"trstctl.com/trstctl/internal/crypto/infratest"
)

const webTestPassword = "Console-Pass-1!x"

// webBrowser is a browser on the session's tunnel: each connection it opens
// is served by serveWebConsole with the session's shared state, and every
// byte it sends or receives is kept.
type webBrowser struct {
	client  *http.Client
	jar     *cookiejar.Jar
	mu      sync.Mutex
	traffic bytes.Buffer
}

type tappedConn struct {
	net.Conn
	b *webBrowser
}

func (c tappedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.b.mu.Lock()
	c.b.traffic.Write(p[:n])
	c.b.mu.Unlock()
	return n, err
}

func (c tappedConn) Write(p []byte) (int, error) {
	c.b.mu.Lock()
	c.b.traffic.Write(p)
	c.b.mu.Unlock()
	return c.Conn.Write(p)
}

func (b *webBrowser) seen() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.traffic.Bytes()...)
}

func newWebBrowser(t *testing.T, ctx context.Context, intent SessionIntent, credential string, state *webConsoleState, rec *connRecorder) *webBrowser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	b := &webBrowser{jar: jar}
	transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		browserEnd, gatewayEnd := net.Pipe()
		go func() {
			defer func() { _ = gatewayEnd.Close() }()
			if err := serveWebConsole(ctx, gatewayEnd, []byte(credential), intent, state, nil, rec); err != nil {
				t.Errorf("serveWebConsole: %v", err)
			}
		}()
		return tappedConn{Conn: browserEnd, b: b}, nil
	}}
	t.Cleanup(transport.CloseIdleConnections)
	b.client = &http.Client{Jar: jar, Transport: transport}
	return b
}

const webTunnel = "http://127.0.0.1:18443"

func (b *webBrowser) get(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, err := b.client.Get(webTunnel + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func (b *webBrowser) post(t *testing.T, path string, form url.Values, follow bool) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, webTunnel+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", webTunnel) // what a browser on the tunnel sends
	client := *b.client
	if !follow {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

var webCSRF = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

// TestWebConsoleFormSignInKeepsTheCredentialFromTheBrowserA273: the gateway
// signs in through the console's own form (CSRF token and pre-session cookie
// kept), the operator completes a task, and nothing the browser holds,
// sends or receives carries the password or the console's session cookie;
// the recording has the task, masked; a sign-in the browser posts itself is
// refused; a sign-out signs in again; ending the session stops it.
func TestWebConsoleFormSignInKeepsTheCredentialFromTheBrowserA273(t *testing.T) {
	ctx := context.Background()
	console := infratest.StartWebConsole("admin", webTestPassword)
	t.Cleanup(console.Close)
	intent := SessionIntent{SessionID: "web-1", TargetType: TargetWeb, UpstreamURL: console.URL(), UpstreamCAPEM: string(console.CAPEM()),
		WebSignIn: &accessweb.SignIn{Mode: accessweb.SignInForm, LoginPath: "/login", UsernameField: "username", PasswordField: "password",
			BrowserCookies: []string{infratest.WebConsoleXSRFCookie}}}
	credential := `{"username":"admin","password":"` + webTestPassword + `"}`
	state := newWebConsoleState()
	rec, frames := testConnRecorder(t, []byte(webTestPassword))
	browser := newWebBrowser(t, ctx, intent, credential, state, rec)

	if status, page := browser.get(t, "/"); status != http.StatusOK || !strings.Contains(page, "Signed in as admin") {
		t.Fatalf("the dashboard: %d %s", status, page)
	}
	status, page := browser.get(t, "/settings")
	m := webCSRF.FindStringSubmatch(page)
	if status != http.StatusOK || m == nil {
		t.Fatalf("the settings page: %d %s", status, page)
	}
	resp := browser.post(t, "/settings", url.Values{"csrf": {m[1]}, "banner": {"maintenance tonight"}, "new_password": {"Fresh-Service-Pass-9"}}, false)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings?saved=1" {
		t.Fatalf("saving the settings: %d, Location %q (the console's absolute redirect stays on the tunnel)", resp.StatusCode, resp.Header.Get("Location"))
	}
	if console.Banner() != "maintenance tonight" || console.NewPasswordsSubmitted() != 1 {
		t.Fatalf("the task did not run: banner %q", console.Banner())
	}
	if _, page := browser.get(t, "/account"); strings.Contains(page, webTestPassword) || !strings.Contains(page, strings.Repeat("*", len(webTestPassword))) {
		t.Fatalf("the account page reached the browser with the password: %s", page)
	}
	// The browser cannot post a password to the console's sign-in.
	for _, path := range []string{"/login", "/session"} {
		resp := browser.post(t, path, url.Values{"username": {"admin"}, "password": {"guessed-password"}}, false)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a browser post to %s reached the console: %d", path, resp.StatusCode)
		}
	}
	if console.Failed("admin") != 0 || console.SignIns() != 1 {
		t.Fatalf("sign-ins: failed %d, succeeded %d", console.Failed("admin"), console.SignIns())
	}
	// The console's own sign-out: the gateway signs in again, and the
	// browser lands on the home page instead of signing out in a loop.
	if status, page := browser.get(t, "/logout"); status != http.StatusOK || !strings.Contains(page, "Signed in as admin") || console.SignIns() != 2 {
		t.Fatalf("after signing out: %d (sign-ins %d) %s", status, console.SignIns(), page)
	}

	local, _ := url.Parse(webTunnel)
	for _, c := range browser.jar.Cookies(local) {
		if c.Name != infratest.WebConsoleXSRFCookie {
			t.Fatalf("the browser holds the console's cookie %s", c.Name)
		}
	}
	if len(browser.jar.Cookies(local)) != 1 {
		t.Fatal("the template-named XSRF cookie did not reach the browser")
	}
	seen := browser.seen()
	for _, leak := range append([]string{webTestPassword, base64.StdEncoding.EncodeToString([]byte("admin:" + webTestPassword)), infratest.WebConsoleSessionCookie, infratest.WebConsolePreCookie}, console.SessionCookies()...) {
		if bytes.Contains(seen, []byte(leak)) {
			t.Fatalf("the browser's traffic carries %q", leak)
		}
	}

	state.destroy()
	if status, _ := browser.get(t, "/settings"); status != http.StatusBadGateway {
		t.Fatalf("an ended session still served: %d", status)
	}
	text := frames()
	for _, want := range []string{"request: GET /settings", "request: POST /settings body=banner=maintenance+tonight&", "new_password=[masked:field]",
		"sign-in: form POST /session: signed in", "refused: POST /login: the gateway signs in", "refused: POST /session: the gateway signs in",
		"response: 303 text/html", `value="****************"`, "response: 302: signed out by the console; the gateway signs in again"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the recording lacks %q:\n%s", want, text)
		}
	}
	for _, leak := range append([]string{webTestPassword, "Fresh-Service-Pass-9"}, console.SessionCookies()...) {
		if strings.Contains(text, leak) {
			t.Fatalf("the recording keeps %q:\n%s", leak, text)
		}
	}
}

// TestWebConsoleRefusedSignInIsNeverRepeatedA273: a vaulted password the
// console refuses is sent once in the session, however often the browser
// asks.
func TestWebConsoleRefusedSignInIsNeverRepeatedA273(t *testing.T) {
	ctx := context.Background()
	console := infratest.StartWebConsole("admin", webTestPassword)
	t.Cleanup(console.Close)
	intent := SessionIntent{SessionID: "web-2", TargetType: TargetWeb, UpstreamURL: console.URL(), UpstreamCAPEM: string(console.CAPEM()),
		WebSignIn: &accessweb.SignIn{Mode: accessweb.SignInForm, LoginPath: "/login", UsernameField: "username", PasswordField: "password"}}
	browser := newWebBrowser(t, ctx, intent, `{"username":"admin","password":"changed-elsewhere-1"}`, newWebConsoleState(), nil)
	for i := 0; i < 5; i++ {
		if status, _ := browser.get(t, "/"); status != http.StatusBadGateway {
			t.Fatalf("a refused sign-in served the console: %d", status)
		}
	}
	if console.Failed("admin") != 1 {
		t.Fatalf("the refused password was sent %d times", console.Failed("admin"))
	}
}

// TestWebConsoleBasicAndHeaderSignInA273: basic authentication and an API
// key header are added to every request at the gateway; the browser sends
// none and is never prompted for one.
func TestWebConsoleBasicAndHeaderSignInA273(t *testing.T) {
	ctx := context.Background()
	console := infratest.StartWebConsole("admin", webTestPassword)
	t.Cleanup(console.Close)
	console.AddToken("lab-api-key-0123456789", "automation")
	for _, tc := range []struct {
		name, credential, user string
		signIn                 accessweb.SignIn
		status                 int
	}{
		{"basic", `{"username":"admin","password":"` + webTestPassword + `"}`, "admin", accessweb.SignIn{Mode: accessweb.SignInBasic}, http.StatusOK},
		{"header", `{"token":"lab-api-key-0123456789"}`, "automation", accessweb.SignIn{Mode: accessweb.SignInHeader, Header: "X-Api-Key"}, http.StatusOK},
		{"basic refused", `{"username":"admin","password":"wrong-password-123"}`, "", accessweb.SignIn{Mode: accessweb.SignInBasic}, http.StatusUnauthorized},
	} {
		intent := SessionIntent{SessionID: "web-" + tc.name, TargetType: TargetWeb, UpstreamURL: console.URL(), UpstreamCAPEM: string(console.CAPEM()), WebSignIn: &tc.signIn}
		browser := newWebBrowser(t, ctx, intent, tc.credential, newWebConsoleState(), nil)
		resp, err := browser.client.Get(webTunnel + "/api/whoami")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != tc.status || (tc.user != "" && !strings.Contains(string(body), `"user":"`+tc.user+`"`)) {
			t.Fatalf("%s: %d %s", tc.name, resp.StatusCode, body)
		}
		if resp.Header.Get("WWW-Authenticate") != "" {
			t.Fatalf("%s: the browser was prompted for a password", tc.name)
		}
		for _, leak := range []string{webTestPassword, "wrong-password-123", "lab-api-key-0123456789", base64.StdEncoding.EncodeToString([]byte("admin:" + webTestPassword))} {
			if bytes.Contains(browser.seen(), []byte(leak)) {
				t.Fatalf("%s: the browser's traffic carries %q", tc.name, leak)
			}
		}
	}
}

func TestWebConsoleSessionIntentA273(t *testing.T) {
	good := SessionIntent{SessionID: "s", TargetType: TargetWeb, TargetID: "console", ExpiresAt: time.Now().Add(time.Hour), TicketDigest: strings.Repeat("a", 64), CredentialRef: CredentialRef("s"),
		RequiredAgentID: "agent", UpstreamURL: "https://console.internal.example",
		WebSignIn: &accessweb.SignIn{Mode: accessweb.SignInBasic}}
	if err := ValidateSessionIntent(good); err != nil {
		t.Fatal(err)
	}
	if KindForIntent(good) != KindSessionWeb || !MatchesSessionJob(KindSessionWeb, good) || MatchesSessionJob(KindSession, good) {
		t.Fatal("a web console session rides only its own kind")
	}
	underPath := good
	underPath.UpstreamURL = "https://apps.internal.example/console/"
	if err := ValidateSessionIntent(underPath); err != nil {
		t.Fatalf("a console under a path (A273-O3): %v", err)
	}
	for name, mutate := range map[string]func(*SessionIntent){
		"no sign-in":         func(in *SessionIntent) { in.WebSignIn = nil },
		"bad sign-in":        func(in *SessionIntent) { in.WebSignIn = &accessweb.SignIn{Mode: "saml"} },
		"plain http":         func(in *SessionIntent) { in.UpstreamURL = "http://console.internal.example" },
		"dot segment":        func(in *SessionIntent) { in.UpstreamURL = "https://console.internal.example/admin/../other" },
		"other credential":   func(in *SessionIntent) { in.CredentialRef = CredentialRef("other") },
		"ssh routing":        func(in *SessionIntent) { in.SSHAddress = "127.0.0.1:22" },
		"sign-in elsewhere":  func(in *SessionIntent) { in.TargetType = TargetPostgres; in.UpstreamURL = "" },
		"no upstream at all": func(in *SessionIntent) { in.UpstreamURL = "" },
	} {
		in := good
		signIn := *good.WebSignIn
		in.WebSignIn = &signIn
		mutate(&in)
		if ValidateSessionIntent(in) == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestWebMaskBodyAcrossReadsA273(t *testing.T) {
	secretValue := []byte("Console-Pass-1!x")
	page := bytes.Repeat([]byte("x"), 32<<10-5)
	page = append(append(page, secretValue...), []byte(" and again Console-Pass-1!x.")...)
	body := &webMaskBody{src: io.NopCloser(bytes.NewReader(page)), literals: [][]byte{secretValue}}
	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(page) || bytes.Contains(out, secretValue) || bytes.Count(out, []byte(strings.Repeat("*", len(secretValue)))) != 2 {
		t.Fatalf("masked %d of %d bytes", len(out), len(page))
	}
}

// TestWebDialRefusesTheGatewaysNeighboursA273: a console name that resolves
// to the gateway's own host or a link-local (metadata) address is refused;
// only a reviewed loopback lab route reaches loopback.
func TestWebDialRefusesTheGatewaysNeighboursA273(t *testing.T) {
	var dialed []string
	base := func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}
	console, _ := url.Parse("https://console.internal.example")
	guarded := webDial(base, console)
	for _, addr := range []string{"127.0.0.1:443", "[::1]:443", "169.254.169.254:80", "0.0.0.0:443", "224.0.0.1:443"} {
		if conn, err := guarded(context.Background(), "tcp", addr); err == nil {
			_ = conn.Close()
			t.Fatalf("%s was reached", addr)
		}
	}
	if conn, err := guarded(context.Background(), "tcp", "10.20.30.40:8443"); err != nil {
		t.Fatalf("a private console address was refused: %v", err)
	} else {
		_ = conn.Close()
	}
	lab, _ := url.Parse("https://127.0.0.1:9443")
	if conn, err := webDial(base, lab)(context.Background(), "tcp", "127.0.0.1:9443"); err != nil {
		t.Fatalf("the lab's loopback console was refused: %v", err)
	} else {
		_ = conn.Close()
	}
	if len(dialed) != 2 || dialed[0] != "10.20.30.40:8443" || dialed[1] != "127.0.0.1:9443" {
		t.Fatalf("dialed %v", dialed)
	}
}

// TestWebConsoleUnderAPathStaysUnderItA273O3: a console that lives under a
// path is reached only there. The tunnel's root and the bare path lead to
// it; the operator's task runs under it; another application on the same
// host, and a dot segment or encoded slash that would climb out, are refused
// at the gateway and never reach the host; a template whose sign-in page
// lies outside the path does not open the session.
func TestWebConsoleUnderAPathStaysUnderItA273O3(t *testing.T) {
	ctx := context.Background()
	console := infratest.StartWebConsoleUnder("admin", webTestPassword, "/console")
	t.Cleanup(console.Close)
	intent := SessionIntent{SessionID: "web-path", TargetType: TargetWeb, UpstreamURL: console.Route(), UpstreamCAPEM: string(console.CAPEM()),
		WebSignIn: &accessweb.SignIn{Mode: accessweb.SignInForm, LoginPath: "/console/login", UsernameField: "username", PasswordField: "password"}}
	credential := `{"username":"admin","password":"` + webTestPassword + `"}`
	rec, frames := testConnRecorder(t, []byte(webTestPassword))
	browser := newWebBrowser(t, ctx, intent, credential, newWebConsoleState(), rec)

	for _, start := range []string{"/", "/console"} {
		resp, err := browser.client.Get(webTunnel + start)
		if err != nil {
			t.Fatal(err)
		}
		page, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/console/" || !strings.Contains(string(page), "Signed in as admin") {
			t.Fatalf("%s led to %s: %d %s", start, resp.Request.URL.Path, resp.StatusCode, page)
		}
	}
	status, page := browser.get(t, "/console/settings")
	m := webCSRF.FindStringSubmatch(page)
	if status != http.StatusOK || m == nil {
		t.Fatalf("the settings page under the path: %d %s", status, page)
	}
	resp := browser.post(t, "/console/settings", url.Values{"csrf": {m[1]}, "banner": {"under a path"}}, false)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/console/settings?saved=1" || console.Banner() != "under a path" {
		t.Fatalf("the task under the path: %d, Location %q, banner %q", resp.StatusCode, resp.Header.Get("Location"), console.Banner())
	}
	for _, outside := range []string{"/other-app", "/console/../other-app", "/console/..%2fother-app", "/consoles/x"} {
		if status, page := browser.get(t, outside); status != http.StatusForbidden || strings.Contains(page, "another application") {
			t.Fatalf("%s outside the console's path: %d %s", outside, status, page)
		}
	}
	if served := strings.Join(console.Served(), "\n"); strings.Contains(served, "other-app") || strings.Contains(served, "/consoles/") {
		t.Fatalf("a path outside the console reached its host:\n%s", served)
	}
	if text := frames(); !strings.Contains(text, "refused: GET /other-app: outside the console's path /console/") {
		t.Fatalf("the recording lacks the refusal:\n%s", text)
	}

	outside := intent
	signIn := *intent.WebSignIn
	signIn.LoginPath = "/login"
	outside.WebSignIn = &signIn
	browserEnd, gatewayEnd := net.Pipe()
	defer func() { _ = browserEnd.Close() }()
	if err := serveWebConsole(ctx, gatewayEnd, []byte(credential), outside, newWebConsoleState(), nil, nil); err == nil || !strings.Contains(err.Error(), "outside its reviewed path") {
		t.Fatalf("a sign-in page outside the console's path opened the session: %v", err)
	}
}
