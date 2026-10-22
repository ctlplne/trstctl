// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"context"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/kerberostest"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/store"
)

// A79: the served binary answers /auth/kerberos/login with a Negotiate
// challenge, verifies the browser's SPNEGO ticket against the service keytab,
// maps the principal to its tenant, and mints the same browser session the
// other login paths mint; tickets under another key and principals the
// mapping cannot place are refused.
func TestServedKerberosLoginNegotiatesAgainstTheServiceKeytab(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	const (
		realm    = "LAB.TEST"
		spn      = "HTTP/trstctl.lab.test"
		password = "service-keytab-password" // #nosec G101 -- fabricated fixture credential; the keytab is minted in-process (CWE-798)
		tenantA  = "11111111-1111-1111-1111-111111111111"
	)
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
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "kerberos tenant"}); err != nil {
		t.Fatal(err)
	}
	keytabBytes, err := kerberostest.ServiceKeytab(spn, realm, password)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keytabPath := filepath.Join(dir, "http.keytab")
	if err := os.WriteFile(keytabPath, keytabBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Kerberos{
		Enabled: true, KeytabFile: keytabPath, ServicePrincipal: spn, Realm: realm,
		SessionSecretFile: filepath.Join(dir, "session.secret"), SessionTTL: "1h", LoginRedirect: "/",
		TenantMappings: []config.TenantMapping{{Subject: "alice@" + realm, TenantID: tenantA, Roles: []string{"admin"}}},
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
	srv, err := server.Build(ctx, server.Deps{TenantAuthFactory: Build, Store: phaseStore, Log: log, Kerberos: cfg})
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
	methods := readBodyString(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(methods, `"kerberos":true`) {
		t.Fatalf("/auth/methods = %d %s, want kerberos advertised", resp.StatusCode, methods)
	}

	jar, _ := cookiejar.New(nil)
	client := noFollowClient(jar)
	resp, err = client.Get(baseURL + "/auth/kerberos/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Negotiate") {
		t.Fatalf("login without a ticket = %d %q, want a Negotiate challenge", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	negotiate := func(user, pw string, start time.Time) *http.Response {
		t.Helper()
		header, err := kerberostest.NegotiateHeader(spn, realm, pw, user, start)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/auth/kerberos/login?return_to=%2Fcertificates%3Fexpiry%3D30d", nil)
		req.Header.Set("Authorization", header)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	if resp := negotiate("alice", password, time.Now()); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/certificates?expiry=30d" {
		t.Fatalf("login with a valid ticket = %d → %q, want 302 to the return path", resp.StatusCode, resp.Header.Get("Location"))
	}
	assertAuthMeTenant(t, baseURL, jar, tenantA)

	other, _ := cookiejar.New(nil)
	client = noFollowClient(other)
	if resp := negotiate("alice", "another-service-password", time.Now()); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ticket under another service key = %d, want 401", resp.StatusCode)
	}
	if resp := negotiate("alice", password, time.Now().Add(-3*time.Hour)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired ticket = %d, want 401", resp.StatusCode)
	}
	if resp := negotiate("mallory", password, time.Now()); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("principal with no tenant mapping = %d, want 403", resp.StatusCode)
	}
	assertAuthMeUnauthorized(t, baseURL, other)
}

func readBodyString(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return b.String()
}
