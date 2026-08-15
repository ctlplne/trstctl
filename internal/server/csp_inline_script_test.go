// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

var inlineScriptRe = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

// TestServedInlineScriptMatchesCSPHash is the regression guard for a security
// header that silently broke a feature.
//
// The served console ships one inline script — the pre-paint theme applier — and
// script-src was 'self' with no allowance for it. The browser refused to run it,
// so the theme-flash prevention did nothing in production and every page load
// logged a CSP violation. Nothing failed loudly, because a blocked inline script
// looks exactly like a script that decided to do nothing.
//
// The fix allows those exact bytes by hash. This test pins the two together: edit
// the script without updating the hash and it breaks here, at build time, instead
// of silently in a browser.
func TestServedInlineScriptMatchesCSPHash(t *testing.T) {
	body, err := os.ReadFile("../webui/dist/index.html")
	if err != nil {
		t.Skipf("no built web UI to check: %v", err)
	}
	matches := inlineScriptRe.FindAllStringSubmatch(string(body), -1)
	if len(matches) == 0 {
		t.Skip("the shipped index.html has no inline script; nothing to allow")
	}
	if len(matches) > 1 {
		t.Fatalf("the shipped index.html has %d inline scripts but the CSP allows one hash; "+
			"each additional inline script is silently blocked", len(matches))
	}

	want := "'sha256-" + base64.StdEncoding.EncodeToString(crypto.SHA256Sum([]byte(matches[0][1]))) + "'"
	if want != webUIThemeScriptCSPHash {
		t.Fatalf("the shipped inline script hashes to %s but the CSP allows %s;\n"+
			"the browser will refuse to run it and the theme-flash prevention will silently "+
			"do nothing. Update webUIThemeScriptCSPHash.", want, webUIThemeScriptCSPHash)
	}
}

// TestCSPAllowsTheInlineScriptWithoutUnsafeInline pins the shape of the fix: a
// hash, never 'unsafe-inline', which would permit every injected script and
// defeat the header entirely.
func TestCSPAllowsTheInlineScriptWithoutUnsafeInline(t *testing.T) {
	rec := httptest.NewRecorder()
	handler := securityHeadersMiddleware(SecurityHeaders{}, http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("no Content-Security-Policy was set")
	}
	scriptSrc := ""
	for _, directive := range strings.Split(csp, ";") {
		if strings.HasPrefix(strings.TrimSpace(directive), "script-src") {
			scriptSrc = strings.TrimSpace(directive)
		}
	}
	if scriptSrc == "" {
		t.Fatal("the CSP has no script-src directive")
	}
	if strings.Contains(scriptSrc, "'unsafe-inline'") {
		t.Error("script-src allows 'unsafe-inline', which permits every injected script — " +
			"the inline theme applier must be allowed by hash, not by opening the door")
	}
	if !strings.Contains(scriptSrc, webUIThemeScriptCSPHash) {
		t.Errorf("script-src does not carry the inline script's hash: %s", scriptSrc)
	}
	if !strings.Contains(scriptSrc, "'self'") {
		t.Errorf("script-src no longer allows the app's own bundles: %s", scriptSrc)
	}
}
