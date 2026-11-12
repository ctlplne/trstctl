// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/crypto/jose"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto/infratest"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/objectstore/s3test"
)

const a273ConsolePassword = "Lab-Console-Pass-7!"

// a273Capture is the browser's side of the network: every connection the
// browser opens to the CLI's tunnel passes through it, and it keeps every
// byte both ways.
type a273Capture struct {
	ln    net.Listener
	mu    sync.Mutex
	bytes bytes.Buffer
}

func startA273Capture(t *testing.T, tunnel string) *a273Capture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &a273Capture{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			browser, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = browser.Close() }()
				upstream, err := net.Dial("tcp", tunnel)
				if err != nil {
					return
				}
				defer func() { _ = upstream.Close() }()
				done := make(chan struct{}, 2)
				pipe := func(dst, src net.Conn) {
					buf := make([]byte, 32<<10)
					for {
						n, err := src.Read(buf)
						if n > 0 {
							c.mu.Lock()
							c.bytes.Write(buf[:n])
							c.mu.Unlock()
							if _, werr := dst.Write(buf[:n]); werr != nil {
								break
							}
						}
						if err != nil {
							break
						}
					}
					if tcp, ok := dst.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
					done <- struct{}{}
				}
				go pipe(upstream, browser)
				go pipe(browser, upstream)
				<-done
				<-done
			}()
		}
	}()
	return c
}

func (c *a273Capture) seen() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.bytes.Bytes()...)
}

var (
	a273OpenLine = regexp.MustCompile(`Open http://(127\.0\.0\.1:\d+)/ in your browser`)
	a273CSRF     = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)
	a273Absolute = regexp.MustCompile(`<a href="([^"]+)" id="absolute">`)
)

// TestServedWebConsoleSessionA273: an internal web admin console is reached
// only through its gateway. A webconsole target vaults the account and names
// the console's route; an access template sets how the gateway signs in (the
// console's own form); a reviewed session through the template is opened
// with the CLI tunnel, and a browser on it completes a settings task. The
// console's password and its session cookies appear nowhere in the browser's
// cookie jar, its network traffic, the CLI's output or the gateway's log;
// the sealed recording has the task with the credential and a password field
// masked; links the console writes with its own origin keep the browser on
// the tunnel (A273-O2); terminating the session stops the browser's access.
// A session without a template that signs in, a misdeclared target or
// template, and a check-out of the account are refused. A console under a
// path is reached only under it (A273-O3).
func TestServedWebConsoleSessionA273(t *testing.T) {
	if testing.Short() {
		t.Skip("gateway session proof")
	}
	console := infratest.StartWebConsole("admin", a273ConsolePassword)
	t.Cleanup(console.Close)
	// TRSTCTL_A273_BROWSER_DIR (opt-in) holds the session open for a real
	// browser: the test writes the tunnel's address to <dir>/url, waits for
	// <dir>/done, checks the browser's traffic too, and after terminating
	// writes <dir>/terminated and waits for <dir>/exit.
	browserDir := os.Getenv("TRSTCTL_A273_BROWSER_DIR")
	ttl, maxTTL := 120, 3*time.Minute
	if browserDir != "" {
		ttl, maxTTL = 1500, 30*time.Minute
	}

	f := &gatewayFixture{t: t, objects: s3test.NewServer(t), gatewayLog: &lockedBuffer{}, dir: t.TempDir()}
	var err error
	if f.auditKey, err = jose.GenerateRSASigningKey("audit-export"); err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.gatewayAddr = raw.Addr().String()
	gatewayID := agentRowID(servedTestTenant, "role-agent")
	f.h = newRoleHarnessWithEventOptions(t, []string{mtls.AgentRoleGateway}, []string{relay.KindAccessGatewayWebSession}, nil, withSecretsEnabled(t, nil), func(d *Deps) {
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: maxTTL, ExpiryInterval: 50 * time.Millisecond,
			WebConsoleAllowLoopback: true, Attestors: []attest.Attestor{servedPAMAttestor{}}}
		d.ArchiveObjectStore = f.objects.Open(t)
		d.AuditSigningKey = f.auditKey
	})
	h := f.h
	if _, err := h.client.Heartbeat(context.Background(), &transport.HeartbeatRequest{AgentID: h.agent, Version: "a273", Status: "active",
		Executors: &transport.ExecutorReport{Version: "a273", Kinds: []transport.ExecutorKind{{Kind: relay.KindAccessGatewayWebSession}}}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f.ctx = ctx
	startServedExternalCADispatcher(t, h.servedHarness)
	go h.srv.RunPAMSessionExpiry(ctx)
	f.requester = seedScopedTokenSubject(t, h.store, h.tenant, "a273-requester", "access:read", "access:write")
	f.reviewerOne = seedScopedTokenSubject(t, h.store, h.tenant, "a273-reviewer-one", "access:approve")
	f.reviewerTwo = seedScopedTokenSubject(t, h.store, h.tenant, "a273-reviewer-two", "access:approve")
	f.operator = seedScopedTokenSubject(t, h.store, h.tenant, "a273-operator", "access:read", "access:write", "access:targets.write", "access:terminate")
	custodian := seedScopedTokenSubject(t, h.store, h.tenant, "a273-custodian", "secrets:read", "secrets:write")

	const account = "consoles/a273-lab-admin"
	value, _ := json.Marshal(map[string]string{"username": "admin", "password": a273ConsolePassword})
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", custodian, "a273-seed",
		map[string]any{"name": account, "value": string(value)}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("vault the console account: %d %s", status, body)
	}
	route := map[string]any{"url": console.URL(), "ca_pem": string(console.CAPEM())}
	register := func(key string, target map[string]any) (int, []byte) {
		t.Helper()
		body := map[string]any{"target_type": "webconsole", "account_secret": account, "allowed_roles": []string{account},
			"gateway_agent_id": gatewayID, "gateway_address": f.gatewayAddr, "web": route}
		for k, v := range target {
			body[k] = v
		}
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", f.operator, key, body)
	}
	for name, target := range map[string]map[string]any{
		"plain http":     {"id": "a273-plain", "web": map[string]any{"url": "http://console.internal.example"}},
		"route climbs":   {"id": "a273-path", "web": map[string]any{"url": "https://console.internal.example/admin/../other"}},
		"no route":       {"id": "a273-noroute", "web": nil},
		"with provider":  {"id": "a273-provider", "provider_id": "some-provider"},
		"no gateway":     {"id": "a273-nogw", "gateway_agent_id": "", "gateway_address": ""},
		"other password": {"id": "a273-roles", "allowed_roles": []string{"someone-else"}},
	} {
		if status, body := register("a273-bad-"+name, target); status == http.StatusCreated {
			t.Fatalf("%s: a misdeclared web console target was registered: %s", name, body)
		}
	}
	if status, body := register("a273-register", map[string]any{"id": "a273-lab-console"}); status != http.StatusCreated ||
		!strings.Contains(string(body), `"target_type":"webconsole"`) || !strings.Contains(string(body), console.URL()) {
		t.Fatalf("register the console = %d %s", status, body)
	}

	template := func(key string, signIn map[string]any) (int, api.PAMAccessTemplate) {
		t.Helper()
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, key, map[string]any{
			"name": "a273-" + key, "reason": "Reviewed console maintenance", "required_approvals": 2, "max_ttl_seconds": ttl, "web_sign_in": signIn})
		var saved api.PAMAccessTemplate
		_ = json.Unmarshal(body, &saved)
		return status, saved
	}
	if status, _ := template("bad-mode", map[string]any{"mode": "saml"}); status != http.StatusUnprocessableEntity {
		t.Fatalf("a template with an unknown sign-in mode = %d", status)
	}
	if status, _ := template("bad-header", map[string]any{"mode": "header", "header": "Cookie"}); status != http.StatusUnprocessableEntity {
		t.Fatalf("a template putting the token in the Cookie header = %d", status)
	}
	status, signsIn := template("form", map[string]any{"mode": "form", "login_path": "/login", "username_field": "username",
		"password_field": "password", "browser_cookies": []string{infratest.WebConsoleXSRFCookie}})
	if status != http.StatusCreated || signsIn.WebSignIn == nil || signsIn.WebSignIn.Mode != "form" {
		t.Fatalf("save the console's template = %d %+v", status, signsIn)
	}
	request := func(templateID string) map[string]any {
		r := map[string]any{"target_type": "webconsole", "target_id": "a273-lab-console", "role": account, "ttl_seconds": ttl,
			"reason": "rotate the banner", "method": "stub_pam", "payload_base64": "Z2VudWluZQ=="}
		if templateID != "" {
			r["template_id"] = templateID
		}
		return r
	}
	untemplated := request("")
	untemplated["request_id"] = uuid.NewString()
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", f.requester, "a273-untemplated", untemplated); status != http.StatusUnprocessableEntity ||
		!strings.Contains(string(body), "web_sign_in") {
		t.Fatalf("a session without a template that signs in = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts", f.requester, "a273-checkout",
		map[string]any{"request_id": uuid.NewString(), "target_type": "webconsole", "target_id": "a273-lab-console", "reason": "show me the password", "ttl_seconds": 120}); status < 400 ||
		strings.Contains(string(body), a273ConsolePassword) {
		t.Fatalf("a check-out of the console account = %d %s", status, body)
	}

	// The gateway's server certificate names the address its targets bind.
	cert, err := mtls.NewRenewingServerCertificate(h.srv.AgentCACertPEM(), []string{"127.0.0.1"}, func(csr []byte) ([]byte, error) {
		resp, err := h.client.SignGatewayServerCertificate(context.Background(), &transport.SignGatewayServerCertificateRequest{CSRDER: csr, Hosts: []string{"127.0.0.1"}})
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(resp.CertificatePEM)
		if block == nil {
			return nil, fmt.Errorf("not PEM")
		}
		return block.Bytes, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cert.Close)
	ln, err := mtls.GatewayWrapListener(raw, cert)
	if err != nil {
		t.Fatal(err)
	}
	f.gw, err = accessgateway.New(accessgateway.Config{Channel: &sshCollectionServedChannel{t: t, h: h}, Listener: ln,
		ClaimInterval: 100 * time.Millisecond, ExtendInterval: 200 * time.Millisecond,
		Logf: func(format string, args ...any) {
			_, _ = f.gatewayLog.Write([]byte(strings.TrimSpace(fmt.Sprintf(format, args...)) + "\n"))
		}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = f.gw.Run(ctx) }()
	f.api = httptest.NewServer(h.srv.Handler())
	t.Cleanup(f.api.Close)

	session := servedPAMReviewedOpen(t, h.servedHarness, f.requester, f.reviewerOne, f.reviewerTwo, "a273-open", request(signsIn.ID))
	if session.Delivery != "gateway" || session.Gateway == nil {
		t.Fatalf("the console session was not delivered through its gateway: %+v", session)
	}
	// The reviewers saw how the gateway signs in.
	if status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/approval-requests?status=consumed", f.reviewerOne, nil); status != http.StatusOK ||
		!strings.Contains(string(body), "pam-web-sign-in:form") {
		t.Fatalf("the reviewed request's evidence lacks the sign-in: %d %s", status, body)
	}
	out, stop := f.connect(session.ID, session.Gateway.Ticket, a273OpenLine.MatchString)
	defer stop()
	capture := startA273Capture(t, a273OpenLine.FindStringSubmatch(out)[1])
	base := "http://" + capture.ln.Addr().String()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	get := func(path string) (int, string, error) {
		resp, err := browser.Get(base + path)
		if err != nil {
			return 0, "", err
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body), nil
	}
	var page string
	a201Await(t, "the console through the gateway", func() bool {
		status, body, err := get("/")
		page = body
		return err == nil && status == http.StatusOK && strings.Contains(body, "Signed in as admin")
	})
	status, page, err = get("/settings")
	m := a273CSRF.FindStringSubmatch(page)
	if err != nil || status != http.StatusOK || m == nil {
		t.Fatalf("the settings page: %d %v %s (gateway: %s)", status, err, page, f.gatewayLog.String())
	}
	form := url.Values{"csrf": {m[1]}, "banner": {"maintenance tonight"}, "new_password": {"Fresh-Service-Pass-9"}}
	req, _ := http.NewRequest(http.MethodPost, base+"/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", base)
	resp, err := browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || console.Banner() != "maintenance tonight" || console.NewPasswordsSubmitted() != 1 {
		t.Fatalf("the operator's task: %d, banner %q", resp.StatusCode, console.Banner())
	}
	if _, page, err := get("/account"); err != nil || strings.Contains(page, a273ConsolePassword) || !strings.Contains(page, strings.Repeat("*", len(a273ConsolePassword))) {
		t.Fatalf("the account page reached the browser with the password (%v): %s", err, page)
	}
	// A273-O2: pages, headers and API answers that name the console's own
	// origin name the browser's tunnel instead, and a link followed as
	// written stays on the tunnel.
	if resp, err = browser.Get(base + "/links"); err != nil {
		t.Fatal(err)
	}
	links, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	absolute := a273Absolute.FindSubmatch(links)
	if absolute == nil || string(absolute[1]) != base+"/settings" || resp.Header.Get("Refresh") != "600; url=/settings" {
		t.Fatalf("the links page left the tunnel: Refresh %q\n%s", resp.Header.Get("Refresh"), links)
	}
	if policy := resp.Header.Get("Content-Security-Policy"); !strings.Contains(policy, "connect-src 'self' ws://"+capture.ln.Addr().String()) || strings.Contains(policy, "upgrade-insecure-requests") {
		t.Fatalf("the console's policy does not fit the tunnel: %q", policy)
	}
	if followed, err := browser.Get(string(absolute[1])); err != nil {
		t.Fatal(err)
	} else {
		settings, _ := io.ReadAll(followed.Body)
		_ = followed.Body.Close()
		if followed.StatusCode != http.StatusOK || !a273CSRF.Match(settings) {
			t.Fatalf("the absolute link followed: %d %s", followed.StatusCode, settings)
		}
	}
	if status, body, err := get("/api/links"); err != nil || status != http.StatusOK || body != `{"self":"`+strings.ReplaceAll(base+"/api/whoami", "/", `\/`)+`"}` {
		t.Fatalf("the JSON answer naming the console: %d %v %s", status, err, body)
	}

	local, _ := url.Parse(base)
	for _, c := range jar.Cookies(local) {
		if c.Name != infratest.WebConsoleXSRFCookie {
			t.Fatalf("the browser holds the console's cookie %s", c.Name)
		}
	}
	leaks := append([]string{a273ConsolePassword, infratest.WebConsoleSessionCookie, infratest.WebConsolePreCookie}, console.SessionCookies()...)
	for _, leak := range leaks {
		for where, text := range map[string]string{"network traffic": string(capture.seen()), "CLI output": out, "gateway log": f.gatewayLog.String()} {
			if strings.Contains(text, leak) {
				t.Fatalf("the browser's %s carries %q", where, leak)
			}
		}
	}
	if console.Failed("admin") != 0 || console.SignIns() != 1 {
		t.Fatalf("the console saw %d failed and %d good sign-ins", console.Failed("admin"), console.SignIns())
	}
	// The console's origin reaches the browser only inside a look-alike.
	if seen := capture.seen(); bytes.Contains(seen, []byte(strings.ReplaceAll(console.URL(), "/", `\/`))) ||
		bytes.Count(seen, []byte(console.URL())) != bytes.Count(seen, []byte(console.URL()+".example")) {
		t.Fatal("the console's own origin reached the browser's network traffic")
	}
	if browserDir != "" {
		a273AwaitBrowser(t, browserDir, "url", base+"/", "done")
		for _, leak := range append(leaks, console.SessionCookies()...) {
			if bytes.Contains(capture.seen(), []byte(leak)) {
				t.Fatalf("the real browser's traffic carries %q", leak)
			}
		}
	}

	// Terminating the session stops the browser's access.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/terminate", f.operator, "a273-terminate",
		map[string]any{"reason": "A273 proof complete"}); status != http.StatusAccepted {
		t.Fatalf("terminate = %d %s", status, body)
	}
	browser.CloseIdleConnections()
	a201Await(t, "the terminated session stops serving the browser", func() bool {
		browser.CloseIdleConnections()
		status, body, err := get("/settings")
		return err != nil || (status != http.StatusOK && !strings.Contains(body, "Settings"))
	})
	a201Await(t, "the console session's recording seals", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
	})
	text := recordingText(t, h, session.ID)
	for _, want := range []string{"sign-in: form POST /session: signed in", "request: GET /settings", "request: POST /settings body=banner=maintenance+tonight&",
		"new_password=[masked:field]", "response: 200 text/html", `value="` + strings.Repeat("*", len(a273ConsolePassword)) + `"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("the recording lacks %q:\n%s", want, text)
		}
	}
	for _, leak := range append([]string{a273ConsolePassword, "Fresh-Service-Pass-9"}, console.SessionCookies()...) {
		if strings.Contains(text, leak) {
			t.Fatalf("the recording keeps %q", leak)
		}
	}
	if served := strings.Join(console.Served(), "\n"); !strings.Contains(served, "POST /settings") || strings.Contains(served, "POST /login") {
		t.Fatalf("the console served:\n%s", served)
	}
	if browserDir != "" {
		a273AwaitBrowser(t, browserDir, "terminated", "terminated\n", "exit")
	}

	// A273-O3: a console that lives under a path. Its target names the path,
	// a template whose sign-in page lies outside it is refused when the
	// session is requested, and through the session's tunnel the browser
	// lands on the path and reaches only it, never another application on the
	// same host.
	underPath := infratest.StartWebConsoleUnder("admin", a273ConsolePassword, "/console")
	t.Cleanup(underPath.Close)
	if status, body := register("a273-register-path", map[string]any{"id": "a273-path-console", "web": map[string]any{"url": underPath.Route(), "ca_pem": string(underPath.CAPEM())}}); status != http.StatusCreated ||
		!strings.Contains(string(body), underPath.Route()) {
		t.Fatalf("register the console under a path = %d %s", status, body)
	}
	pathRequest := func(templateID string) map[string]any {
		r := request(templateID)
		r["target_id"] = "a273-path-console"
		return r
	}
	outside := pathRequest(signsIn.ID)
	outside["request_id"] = uuid.NewString()
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", f.requester, "a273-path-outside", outside); status != http.StatusUnprocessableEntity ||
		!strings.Contains(string(body), "outside the console's path /console/") {
		t.Fatalf("a template signing in outside the console's path = %d %s", status, body)
	}
	status, pathSignsIn := template("form-path", map[string]any{"mode": "form", "login_path": "/console/login", "username_field": "username", "password_field": "password"})
	if status != http.StatusCreated {
		t.Fatalf("save the path console's template = %d", status)
	}
	pathSession := servedPAMReviewedOpen(t, h.servedHarness, f.requester, f.reviewerOne, f.reviewerTwo, "a273-open-path", pathRequest(pathSignsIn.ID))
	pathOut, stopPath := f.connect(pathSession.ID, pathSession.Gateway.Ticket, a273OpenLine.MatchString)
	defer stopPath()
	pathCapture := startA273Capture(t, a273OpenLine.FindStringSubmatch(pathOut)[1])
	pathBase := "http://" + pathCapture.ln.Addr().String()
	pathJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	pathBrowser := &http.Client{Jar: pathJar, Timeout: 30 * time.Second}
	a201Await(t, "the console under a path through the gateway", func() bool {
		resp, err := pathBrowser.Get(pathBase + "/")
		if err != nil {
			return false
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK && resp.Request.URL.Path == "/console/" && strings.Contains(string(body), "Signed in as admin")
	})
	for _, elsewhere := range []string{"/other-app", "/console/../other-app"} {
		resp, err := pathBrowser.Get(pathBase + elsewhere)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || strings.Contains(string(body), "another application") {
			t.Fatalf("%s outside the console's path: %d %s", elsewhere, resp.StatusCode, body)
		}
	}
	if served := strings.Join(underPath.Served(), "\n"); strings.Contains(served, "other-app") || !strings.Contains(served, "POST /console/session") {
		t.Fatalf("the host under a path served:\n%s", served)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+pathSession.ID+"/terminate", f.operator, "a273-terminate-path",
		map[string]any{"reason": "A273-O3 proof complete"}); status != http.StatusAccepted {
		t.Fatalf("terminate the path session = %d %s", status, body)
	}
}

// a273AwaitBrowser writes note to <dir>/<write> and waits (up to half an
// hour) for <dir>/<await>.
func a273AwaitBrowser(t *testing.T, dir, write, note, await string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, write), []byte(note), 0o600); err != nil { // #nosec G703 -- the operator-named handshake directory of an opt-in test run, with constant file names (CWE-22)
		t.Fatal(err)
	}
	for deadline := time.Now().Add(30 * time.Minute); ; time.Sleep(time.Second) {
		if _, err := os.Stat(filepath.Join(dir, await)); err == nil { // #nosec G703 -- the operator-named handshake directory of an opt-in test run, with constant file names (CWE-22)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no browser wrote %s", await)
		}
	}
}
