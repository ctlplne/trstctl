// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

func TestInChainGroupFilterEscapesTheUserDN(t *testing.T) {
	got := inChainGroupFilter("uid=al(ice),ou=people,dc=example,dc=org")
	if got != "(member:1.2.840.113556.1.4.1941:=uid=al\\28ice\\29,ou=people,dc=example,dc=org)" {
		t.Fatalf("in-chain filter = %q", got)
	}
}

// A82 on a real OpenLDAP: alice is a direct member of trstctl-admins, which is
// a member of platform-admins, which is a member of everyone (and everyone of
// itself). A mapping on the grandparent group signs her in only when nested
// expansion is on, the walk is bounded, and the cycle does not loop.
func TestServedLDAPNestedGroupsMapTheGrandparentRole(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL and an OpenLDAP container; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "33333333-3333-3333-3333-333333333333"
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
	ldapURL := startOpenLDAPContainer(t)
	bindPasswordFile := filepath.Join(t.TempDir(), "ldap-bind.secret")
	if err := os.WriteFile(bindPasswordFile, []byte("admin-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := config.LDAP{
		Enabled: true, URL: ldapURL, UserDNTemplate: "uid={username},ou=people,dc=example,dc=org",
		BindDN: "cn=admin,dc=example,dc=org", BindPasswordFile: bindPasswordFile,
		GroupSearchBaseDN: "ou=groups,dc=example,dc=org", GroupFilter: "(member={user_dn})", GroupNameAttribute: "cn", EmailAttribute: "mail",
		SessionSecretFile: filepath.Join(t.TempDir(), "ldap-session.secret"), SessionTTL: "1h", LoginRedirect: "/",
		TenantMappings: []config.TenantMapping{{Group: "everyone", TenantID: tenantID, Roles: []string{"viewer"}}},
	}
	login := func(cfg config.LDAP) (int, http.CookieJar, string) {
		t.Helper()
		srv := buildLDAPServer(t, ctx, dsn, tenantID, cfg)
		defer func() { _ = srv.Shutdown(context.Background()) }()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		baseURL := "http://" + ln.Addr().String()
		httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = httpSrv.Serve(ln) }()
		defer func() { _ = httpSrv.Close() }()
		jar, _ := cookiejar.New(nil)
		resp, err := noFollowClient(jar).Post(baseURL+"/auth/ldap/login", "application/json", strings.NewReader(`{"username":"alice","password":"alice-password"}`))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusFound {
			assertAuthMeTenant(t, baseURL, jar, tenantID)
		}
		return resp.StatusCode, jar, string(body)
	}
	if code, _, body := login(base); code != http.StatusForbidden {
		t.Fatalf("direct groups only: login = %d %s, want 403 (everyone is two levels up)", code, body)
	}
	nested := base
	nested.NestedGroups = config.LDAPNestedGroups{Enabled: true, MaxDepth: 5}
	if code, _, body := login(nested); code != http.StatusFound {
		t.Fatalf("nested expansion: login = %d %s, want 302", code, body)
	}
	shallow := base
	shallow.NestedGroups = config.LDAPNestedGroups{Enabled: true, MaxDepth: 1}
	if code, _, body := login(shallow); code != http.StatusForbidden {
		t.Fatalf("depth 1 reaches platform-admins only: login = %d %s, want 403", code, body)
	}
}
