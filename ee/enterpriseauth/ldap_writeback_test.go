// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
)

// A83 on a real OpenLDAP: an operator's role change on a directory member is
// written to the directory's role groups by the outbox worker, and offboarding
// removes the member from them; a member outside the directory base is never
// written back.
func TestServedLDAPWritebackAppliesRoleGroupsToTheDirectory(t *testing.T) {
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
	container := openLDAPContainerName(t)
	bindPasswordFile := filepath.Join(t.TempDir(), "ldap-bind.secret")
	if err := os.WriteFile(bindPasswordFile, []byte("admin-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	const viewers = "cn=trstctl-viewers,ou=groups,dc=example,dc=org"
	ldapCfg := config.LDAP{
		Enabled: true, URL: ldapURL, UserDNTemplate: "uid={username},ou=people,dc=example,dc=org",
		BindDN: "cn=admin,dc=example,dc=org", BindPasswordFile: bindPasswordFile,
		GroupSearchBaseDN: "ou=groups,dc=example,dc=org", GroupFilter: "(member={user_dn})", GroupNameAttribute: "cn", EmailAttribute: "mail",
		Writeback:         config.LDAPWriteback{Enabled: true, BaseDN: "dc=example,dc=org", RoleGroups: map[string]string{"viewer": viewers}},
		SessionSecretFile: filepath.Join(t.TempDir(), "ldap-session.secret"), SessionTTL: "1h", LoginRedirect: "/",
		TenantMappings: []config.TenantMapping{{Group: "trstctl-admins", TenantID: tenantID, Roles: []string{"admin"}}},
	}
	srv := buildLDAPServer(t, ctx, dsn, tenantID, ldapCfg)
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + ln.Addr().String()
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Close() }()
	token := seedServedScopedToken(t, st, tenantID, "access:write", "access:read", "access:role.assign")

	const alice = "uid=alice,ou=people,dc=example,dc=org"
	call := func(method, path, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, baseURL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", method+path+body)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(out)
	}
	members := func() string {
		t.Helper()
		out, err := exec.Command("docker", "exec", container, "ldapsearch", "-x", "-H", "ldap://127.0.0.1", // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
			"-D", "cn=admin,dc=example,dc=org", "-w", "admin-password", "-b", viewers, "-s", "base", "(objectClass=*)", "member").CombinedOutput()
		if err != nil {
			t.Fatalf("ldapsearch: %v\n%s", err, out)
		}
		return string(out)
	}
	if bytes.Contains([]byte(members()), []byte(alice)) {
		t.Fatal("alice is a viewer before any writeback")
	}
	if code, body := call(http.MethodPut, "/api/v1/access/members/"+alice, `{"display_name":"Alice","roles":["viewer"],"source":"ldap"}`); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("upsert member = %d %s", code, body)
	}
	if err := srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if got := members(); !strings.Contains(got, alice) {
		t.Fatalf("after the role upsert alice is not in the viewers group:\n%s", got)
	}
	// Idempotent: a second delivery for the same state changes nothing and does not fail.
	if code, body := call(http.MethodPut, "/api/v1/access/members/"+alice, `{"display_name":"Alice Lab","roles":["viewer"],"source":"ldap"}`); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("second upsert = %d %s", code, body)
	}
	if err := srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if got := members(); strings.Count(got, alice) != 1 {
		t.Fatalf("alice listed %d times after the second upsert:\n%s", strings.Count(got, alice), got)
	}
	if code, body := call(http.MethodPost, "/api/v1/access/members/"+alice+"/offboard", `{"reason":"left the team"}`); code != http.StatusOK {
		t.Fatalf("offboard = %d %s", code, body)
	}
	if err := srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if got := members(); strings.Contains(got, alice) {
		t.Fatalf("after offboarding alice is still a viewer:\n%s", got)
	}
	// A member outside the directory base queues no writeback.
	if code, body := call(http.MethodPut, "/api/v1/access/members/local-operator", `{"display_name":"Local","roles":["viewer"],"source":"local"}`); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("local upsert = %d %s", code, body)
	}
	if err := srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if got := members(); strings.Contains(got, "local-operator") {
		t.Fatalf("a non-directory member was written to the directory:\n%s", got)
	}
}

// seedServedScopedToken mints an API token for the served API the way the
// server package's tests do.
func seedServedScopedToken(t *testing.T, st *store.Store, tenant string, scopes ...string) string {
	t.Helper()
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	if _, err := st.CreateAPIToken(context.Background(), store.APITokenRecord{TenantID: tenant, TokenHash: hash, Subject: "writeback-test-operator", Scopes: scopes}); err != nil {
		t.Fatalf("seed api token: %v", err)
	}
	token := secrettext.String(raw)
	secret.Wipe(raw)
	return token
}
