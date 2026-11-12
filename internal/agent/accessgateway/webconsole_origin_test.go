// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/accessweb"
	"trstctl.com/trstctl/internal/crypto/infratest"
)

// chunkedReader returns at most n bytes per Read, so a form can straddle
// any two reads.
type chunkedReader struct {
	src io.Reader
	n   int
}

func (r chunkedReader) Read(p []byte) (int, error) { return r.src.Read(p[:min(len(p), r.n)]) }

func rewriteOrigins(t *testing.T, target, tunnel, body string, chunk int) string {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(newWebOriginBody(io.NopCloser(chunkedReader{src: strings.NewReader(body), n: chunk}), webOriginForms(u, tunnel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestWebOriginBodyRewritesEveryFormAcrossReadsA273O2: each way a body
// writes the console's origin (any case of its host, JSON-escaped,
// scheme-relative, its WebSocket scheme, a default port written or not)
// names the tunnel instead, however the body is split across reads; a
// longer port or host name, user information and another scheme are left
// alone; without a known tunnel the links become root-relative.
func TestWebOriginBodyRewritesEveryFormAcrossReadsA273O2(t *testing.T) {
	for _, tc := range []struct{ name, target, tunnel, in, want string }{
		{"explicit port", "https://Console.Example:8443", "http://127.0.0.1:5555",
			`<a href="https://console.example:8443/a">` + "\n" +
				`{"self":"https:\/\/Console.Example:8443\/api"}` + "\n" +
				`<script src="//console.example:8443/app.js"></script>` + "\n" +
				`new WebSocket("wss://console.example:8443/ws")` + "\n" +
				`https://console.example:84430/ https://console.example:8443.evil.test/ https://console.example:8443@evil.test/` + "\n" +
				`ftp://console.example:8443/ https://console.example.evil:8443/` + "\n" +
				`url(//console.example:8443/bg.png) end https://console.example:8443`,
			`<a href="http://127.0.0.1:5555/a">` + "\n" +
				`{"self":"http:\/\/127.0.0.1:5555\/api"}` + "\n" +
				`<script src="//127.0.0.1:5555/app.js"></script>` + "\n" +
				`new WebSocket("ws://127.0.0.1:5555/ws")` + "\n" +
				`https://console.example:84430/ https://console.example:8443.evil.test/ https://console.example:8443@evil.test/` + "\n" +
				`ftp://console.example:8443/ https://console.example.evil:8443/` + "\n" +
				`url(//127.0.0.1:5555/bg.png) end http://127.0.0.1:5555`},
		{"default port", "https://console.example", "http://localhost:7000",
			`"https://console.example/x" "https://console.example:443/y" "https://console.example:8443/z" "https://console.examples/w" https://console.example`,
			`"http://localhost:7000/x" "http://localhost:7000/y" "https://console.example:8443/z" "https://console.examples/w" http://localhost:7000`},
		{"no tunnel", "https://console.example:8443", "",
			`<a href="https://console.example:8443/settings"><img src="//console.example:8443/i.png">`,
			`<a href="/settings"><img src="/i.png">`},
	} {
		for _, chunk := range []int{1, 2, 3, 7, 64, 1 << 20} {
			if got := rewriteOrigins(t, tc.target, tc.tunnel, tc.in, chunk); got != tc.want {
				t.Fatalf("%s, %d-byte reads:\n got %s\nwant %s", tc.name, chunk, got, tc.want)
			}
		}
	}
	for host, want := range map[string]string{
		"127.0.0.1:5555": "http://127.0.0.1:5555", "LOCALHOST:80": "http://localhost:80", "[::1]:9": "http://[::1]:9",
		"evil.test:80": "", "127.0.0.1": "", "10.0.0.1:80": "", "127.0.0.1:0": "", "127.0.0.1:70000": "",
	} {
		if got := webTunnelOrigin(host); got != want {
			t.Fatalf("the tunnel origin of Host %q = %q, want %q", host, got, want)
		}
	}
}

// TestWebConsoleKeepsTheConsolesOwnLinksOnTheTunnelA273O2: a console page,
// API answer and headers that name the console's own origin reach the
// browser naming the tunnel's; a link followed from them stays on the
// tunnel and reaches the console; the console's origin reaches the browser
// only inside a look-alike origin.
func TestWebConsoleKeepsTheConsolesOwnLinksOnTheTunnelA273O2(t *testing.T) {
	ctx := context.Background()
	console := infratest.StartWebConsole("admin", webTestPassword)
	t.Cleanup(console.Close)
	intent := SessionIntent{SessionID: "web-links", TargetType: TargetWeb, UpstreamURL: console.URL(), UpstreamCAPEM: string(console.CAPEM()),
		WebSignIn: &accessweb.SignIn{Mode: accessweb.SignInForm, LoginPath: "/login", UsernameField: "username", PasswordField: "password"}}
	browser := newWebBrowser(t, ctx, intent, `{"username":"admin","password":"`+webTestPassword+`"}`, newWebConsoleState(), nil)

	resp, err := browser.client.Get(webTunnel + "/links")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	for _, want := range []string{`<base href="` + webTunnel + `/">`, `<script src="//127.0.0.1:18443/app.js">`, `<a href="` + webTunnel + `/settings" id="absolute">`,
		`"ws://127.0.0.1:18443/events"`, `<a href="` + console.URL() + `.example/elsewhere" id="look-alike">`} {
		if !strings.Contains(string(page), want) {
			t.Fatalf("the links page lacks %q:\n%s", want, page)
		}
	}
	if resp.Header.Get("Refresh") != "600; url=/settings" || resp.Header.Get("Link") != "</app.css>; rel=preload; as=style" {
		t.Fatalf("header URLs left the tunnel: Refresh %q, Link %q", resp.Header.Get("Refresh"), resp.Header.Get("Link"))
	}
	if policy := resp.Header.Get("Content-Security-Policy"); policy != "default-src 'self'; connect-src 'self' ws://127.0.0.1:18443; img-src http://127.0.0.1:18443 data:" {
		t.Fatalf("the console's policy does not fit the tunnel: %q", policy)
	}
	// The browser follows the absolute link as written, and stays on the
	// tunnel.
	followed, err := browser.client.Get(webTunnel + "/settings")
	if err != nil {
		t.Fatal(err)
	}
	settings, _ := io.ReadAll(followed.Body)
	_ = followed.Body.Close()
	if followed.StatusCode != http.StatusOK || !webCSRF.Match(settings) {
		t.Fatalf("the followed link: %d %s", followed.StatusCode, settings)
	}
	if status, body := browser.get(t, "/api/links"); status != http.StatusOK || body != `{"self":"http:\/\/127.0.0.1:18443\/api\/whoami"}` {
		t.Fatalf("the JSON answer: %d %s", status, body)
	}
	seen := browser.seen()
	escaped := []byte(strings.ReplaceAll(console.URL(), "/", `\/`))
	if bytes.Contains(seen, escaped) || bytes.Count(seen, []byte(console.URL())) != bytes.Count(seen, []byte(console.URL()+".example")) {
		t.Fatalf("the console's origin reached the browser:\n%s", seen)
	}
}

// TestWebTunnelPolicyNamesTheTunnelA273O2: a Content-Security-Policy source
// on the console's origin, written with its scheme, its WebSocket scheme, no
// scheme or a path, names the tunnel's origin; keywords, nonces, wildcards
// and other origins stand; the directives that would upgrade the plain-http
// tunnel go, with or without a known tunnel.
func TestWebTunnelPolicyNamesTheTunnelA273O2(t *testing.T) {
	target, _ := url.Parse("https://console.example:8443")
	policy := "default-src 'self' https://console.example:8443/static/ 'nonce-abc'; connect-src wss://CONSOLE.example:8443 https://other.example *.example; " +
		"img-src console.example:8443 data:; upgrade-insecure-requests; block-all-mixed-content"
	want := "default-src 'self' http://127.0.0.1:5555/static/ 'nonce-abc'; connect-src ws://127.0.0.1:5555 https://other.example *.example; img-src http://127.0.0.1:5555 data:"
	if got := webTunnelPolicy(policy, target, "http://127.0.0.1:5555"); got != want {
		t.Fatalf("the policy on the tunnel:\n got %s\nwant %s", got, want)
	}
	if got := webTunnelPolicy(policy, target, ""); strings.Contains(got, "upgrade-insecure-requests") || strings.Contains(got, "block-all-mixed-content") || !strings.Contains(got, "wss://CONSOLE.example:8443") {
		t.Fatalf("the policy without a known tunnel: %s", got)
	}
}
