// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/accessweb"
	"trstctl.com/trstctl/internal/crypto/infratest"
)

func ssoIntent(console *infratest.SSOWebConsole, idp *infratest.OIDCProvider) SessionIntent {
	return SessionIntent{SessionID: "web-sso", TargetType: TargetWeb, UpstreamURL: console.URL(), UpstreamCAPEM: string(console.CAPEM()),
		WebSignInURL: idp.URL(), WebSignInCAPEM: string(idp.CAPEM()),
		WebSignIn: &accessweb.SignIn{Mode: accessweb.SignInSSO, LoginPath: "/login", UsernameField: "username", PasswordField: "password"}}
}

// TestWebConsoleSingleSignOnThroughItsIdentityProviderA273O1: a console that
// signs its users in only through an OpenID Connect provider. The gateway
// follows the console's sign-in to the provider its route names, fills the
// provider's form once and follows the code back; the operator completes a
// task. The browser never reaches the provider: its traffic carries neither
// the password, nor the provider's origin, nor either side's cookies. When
// the console ends its own session, the gateway signs in again on the
// provider's session, without the password; a refused password is never sent
// again.
func TestWebConsoleSingleSignOnThroughItsIdentityProviderA273O1(t *testing.T) {
	ctx := context.Background()
	idp, err := infratest.StartOIDCProvider("admin", webTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)
	console := infratest.StartSSOWebConsole(idp, "lab-console", "lab-console-client-secret")
	t.Cleanup(console.Close)
	credential := `{"username":"admin","password":"` + webTestPassword + `"}`
	rec, frames := testConnRecorder(t, []byte(webTestPassword))
	browser := newWebBrowser(t, ctx, ssoIntent(console, idp), credential, newWebConsoleState(), rec)

	if status, page := browser.get(t, "/"); status != http.StatusOK || !strings.Contains(page, "Signed in as admin") {
		t.Fatalf("the console through its identity provider: %d %s", status, page)
	}
	status, page := browser.get(t, "/settings")
	m := webCSRF.FindStringSubmatch(page)
	if status != http.StatusOK || m == nil {
		t.Fatalf("the settings page: %d %s", status, page)
	}
	resp := browser.post(t, "/settings", url.Values{"csrf": {m[1]}, "banner": {"signed in once"}}, false)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || console.Banner() != "signed in once" {
		t.Fatalf("the operator's task: %d, banner %q", resp.StatusCode, console.Banner())
	}
	if idp.SignIns() != 1 || console.SignIns() != 1 || idp.Failed("admin") != 0 {
		t.Fatalf("sign-ins: provider %d (failed %d), console %d", idp.SignIns(), idp.Failed("admin"), console.SignIns())
	}
	if !slices.Contains(idp.Served(), "GET /jwks") {
		t.Fatalf("the console did not verify the ID token against the provider's published keys: %v", idp.Served())
	}
	// The console ends its sessions; the provider still holds the gateway's.
	console.SignOutAll()
	if status, page := browser.get(t, "/settings"); status != http.StatusOK || !strings.Contains(page, "Settings") {
		t.Fatalf("after the console signed the session out: %d %s", status, page)
	}
	if idp.SignIns() != 1 || console.SignIns() != 2 {
		t.Fatalf("signing in again sent the password: provider %d, console %d", idp.SignIns(), console.SignIns())
	}
	seen := browser.seen()
	leaks := append([]string{webTestPassword, idp.URL(), strings.TrimPrefix(idp.URL(), "https://"), infratest.OIDCSessionCookie, infratest.OIDCPreCookie,
		infratest.SSOConsoleSessionCookie}, append(idp.SessionCookies(), console.SessionCookies()...)...)
	for _, leak := range leaks {
		if bytes.Contains(seen, []byte(leak)) {
			t.Fatalf("the browser's traffic carries %q", leak)
		}
	}
	text := frames()
	for _, want := range []string{"sign-in: sso POST " + idp.URL() + "/login: signed in", "signed in with the provider's session", "request: POST /settings body=banner=signed+in+once"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the recording lacks %q:\n%s", want, text)
		}
	}
	for _, leak := range append([]string{webTestPassword}, idp.SessionCookies()...) {
		if strings.Contains(text, leak) {
			t.Fatalf("the recording keeps %q", leak)
		}
	}

	// A password the provider refuses is sent once in the session.
	wrong := newWebBrowser(t, ctx, ssoIntent(console, idp), `{"username":"admin","password":"not-the-password-1"}`, newWebConsoleState(), nil)
	for range 3 {
		if status, _ := wrong.get(t, "/"); status != http.StatusBadGateway {
			t.Fatalf("a refused single sign-on served the console: %d", status)
		}
	}
	if idp.Failed("admin") != 1 {
		t.Fatalf("the refused password was sent %d times", idp.Failed("admin"))
	}
}

// TestWebConsoleSingleSignOnFollowsOnlyItsReviewedProviderA273O1: the
// gateway follows a console's sign-in only to the identity provider its
// reviewed route names. A console that redirects to another provider is not
// signed in, and that provider is never reached.
func TestWebConsoleSingleSignOnFollowsOnlyItsReviewedProviderA273O1(t *testing.T) {
	ctx := context.Background()
	actual, err := infratest.StartOIDCProvider("admin", webTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(actual.Close)
	reviewed, err := infratest.StartOIDCProvider("admin", webTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reviewed.Close)
	console := infratest.StartSSOWebConsole(actual, "lab-console", "lab-console-client-secret")
	t.Cleanup(console.Close)
	intent := ssoIntent(console, reviewed)
	browser := newWebBrowser(t, ctx, intent, `{"username":"admin","password":"`+webTestPassword+`"}`, newWebConsoleState(), nil)
	if status, _ := browser.get(t, "/"); status != http.StatusBadGateway {
		t.Fatalf("a console redirecting to another provider was signed in: %d", status)
	}
	if served := actual.Served(); len(served) != 0 {
		t.Fatalf("the unreviewed provider was reached: %v", served)
	}
	// A session whose route names no provider does not open.
	noProvider := intent
	noProvider.WebSignInURL, noProvider.WebSignInCAPEM = "", ""
	browserEnd, gatewayEnd := net.Pipe()
	defer func() { _ = browserEnd.Close() }()
	if err := serveWebConsole(ctx, gatewayEnd, []byte(`{"username":"admin","password":"x-password-123"}`), noProvider, newWebConsoleState(), nil, nil); err == nil {
		t.Fatal("a single sign-on without its identity provider opened the session")
	}
}
