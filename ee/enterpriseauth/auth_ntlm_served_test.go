// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"context"
	"net"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/store"
)

// A80: the served binary runs the NTLM handshake over one client connection
// against the configured helper, maps the account the helper reports to its
// tenant, and mints the normal browser session; a refused handshake and an
// unmapped account get no session.
func TestServedNTLMLoginCompletesTheHandshakeOverOneConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	const tenantA = "11111111-1111-1111-1111-111111111111"
	ctx := context.Background()
	dsn := serverTestPostgresDSN(t)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	resetServerTestStore(t, st)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "ntlm tenant"}); err != nil {
		t.Fatal(err)
	}
	address, _ := fakeNTLMHelper(t, `ADLAB\alice`)
	dir := t.TempDir()
	cfg := config.NTLM{
		Enabled: true, HelperAddress: address, Domain: "ADLAB",
		SessionSecretFile: filepath.Join(dir, "session.secret"), SessionTTL: "1h", LoginRedirect: "/",
		TenantMappings: []config.TenantMapping{{Subject: "alice@ADLAB", TenantID: tenantA, Roles: []string{"admin"}}},
	}
	phaseStore, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		phaseStore.Close()
		t.Fatal(err)
	}
	srv, err := server.Build(ctx, server.Deps{TenantAuthFactory: Build, Store: phaseStore, Log: log, NTLM: cfg})
	if err != nil {
		_ = log.Close()
		phaseStore.Close()
		t.Fatalf("build control plane: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + ln.Addr().String()
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Close() }()

	resp, err := http.Get(baseURL + "/auth/methods")
	if err != nil {
		t.Fatal(err)
	}
	if methods := readBodyString(t, resp); !strings.Contains(methods, `"ntlm":true`) {
		t.Fatalf("/auth/methods = %s, want ntlm advertised", methods)
	}

	// One keep-alive connection per client, as a browser does for NTLM.
	oneConn := func(jar http.CookieJar) *http.Client {
		return &http.Client{Jar: jar, Transport: &http.Transport{MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	step := func(client *http.Client, authorization string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/auth/ntlm/login?return_to=%2Fcertificates", nil)
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = readBodyString(t, resp)
		return resp
	}
	jar, _ := cookiejar.New(nil)
	client := oneConn(jar)
	if resp := step(client, ""); resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != "NTLM" {
		t.Fatalf("no token = %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if resp := step(client, "NTLM "+ntlmMessage(1, "negotiate")); resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "NTLM "+ntlmMessage(2, "challenge")) {
		t.Fatalf("negotiate = %d %q, want the helper's challenge", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if resp := step(client, "NTLM "+ntlmMessage(3, "good")); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/certificates" {
		t.Fatalf("authenticate = %d → %q, want 302 to the return path", resp.StatusCode, resp.Header.Get("Location"))
	}
	assertAuthMeTenant(t, baseURL, jar, tenantA)

	refused, _ := cookiejar.New(nil)
	client = oneConn(refused)
	step(client, "NTLM "+ntlmMessage(1, "negotiate"))
	if resp := step(client, "NTLM "+ntlmMessage(3, "bad")); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("helper NA = %d, want 401", resp.StatusCode)
	}
	assertAuthMeUnauthorized(t, baseURL, refused)

}
