// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// A81: bind outcomes that mean "change your password" are told apart from
// plain refusals, and the Active Directory password value is the quoted
// UTF-16LE form the directory expects.
func TestLDAPPasswordChangeClassification(t *testing.T) {
	ad773 := ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 773, v4563"))
	ad52e := ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563"))
	if !ldapPasswordChangeRequired(ad773, nil) {
		t.Fatal("AD 'data 773' (must change) was not classified as change required")
	}
	if ldapPasswordChangeRequired(ad52e, nil) {
		t.Fatal("AD 'data 52e' (wrong password) was classified as change required")
	}
	expired := ldap.NewControlBeheraPasswordPolicy()
	expired.Error = 0
	reset := ldap.NewControlBeheraPasswordPolicy()
	reset.Error = 2
	fine := ldap.NewControlBeheraPasswordPolicy()
	if !ldapPasswordChangeRequired(nil, []ldap.Control{expired}) || !ldapPasswordChangeRequired(nil, []ldap.Control{reset}) {
		t.Fatal("ppolicy passwordExpired/changeAfterReset were not classified as change required")
	}
	if ldapPasswordChangeRequired(nil, []ldap.Control{fine}) || ldapPasswordChangeRequired(nil, nil) {
		t.Fatal("a clean bind was classified as change required")
	}
	if got := adPasswordValue([]byte("Pa$$")); !bytes.Equal(got, []byte{'"', 0, 'P', 0, 'a', 0, '$', 0, '$', 0, '"', 0}) {
		t.Fatalf("adPasswordValue = %x", got)
	}
	var refused *LDAPPasswordRefusedError
	if err := classifyPasswordChangeError(ldap.NewError(ldap.LDAPResultConstraintViolation, errors.New("Password fails quality checking policy"))); !errors.As(err, &refused) || !strings.Contains(refused.Reason, "quality") {
		t.Fatalf("constraint violation = %v, want the directory's refusal reason", err)
	}
	if err := classifyPasswordChangeError(errors.New("network down")); errors.As(err, &refused) {
		t.Fatal("a transport error was reported as a directory refusal")
	}
	v := LDAPVerifier{URL: "ldap://127.0.0.1:1"}
	if err := v.ChangePassword(context.Background(), "alice", []byte("same"), []byte("same")); !errors.As(err, &refused) {
		t.Fatalf("unchanged password = %v, want a refusal before any directory call", err)
	}
}

// A81 on a real OpenLDAP: the served route proves the current password, changes
// it through the Password Modify extended operation, and the old credential
// stops working while the new one signs in; a wrong current password changes
// nothing.
func TestServedLDAPPasswordChangeAgainstOpenLDAP(t *testing.T) {
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
	ldapCfg := config.LDAP{
		Enabled: true, URL: ldapURL, UserDNTemplate: "uid={username},ou=people,dc=example,dc=org",
		BindDN: "cn=admin,dc=example,dc=org", BindPasswordFile: bindPasswordFile,
		GroupSearchBaseDN: "ou=groups,dc=example,dc=org", GroupFilter: "(member={user_dn})", GroupNameAttribute: "cn", EmailAttribute: "mail",
		PasswordChange:    config.LDAPPasswordChange{Enabled: true},
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

	resp, err := http.Get(baseURL + "/auth/methods")
	if err != nil {
		t.Fatal(err)
	}
	methods, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(methods), `"ldap_password_change":true`) {
		t.Fatalf("/auth/methods = %s, want the password change advertised", methods)
	}
	post := func(path, body string) (int, string) {
		t.Helper()
		resp, err := noFollowClient(nil).Post(baseURL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(out)
	}
	if code, body := post("/auth/ldap/password", `{"username":"alice","current_password":"not-the-password","new_password":"Alice-new-password-1"}`); code != http.StatusUnauthorized {
		t.Fatalf("change with a wrong current password = %d %s, want 401", code, body)
	}
	if code, body := post("/auth/ldap/password", `{"username":"alice","current_password":"alice-password","new_password":"Alice-new-password-1"}`); code != http.StatusNoContent {
		t.Fatalf("password change = %d %s, want 204", code, body)
	}
	if code, _ := post("/auth/ldap/login", `{"username":"alice","password":"alice-password"}`); code != http.StatusUnauthorized {
		t.Fatalf("login with the old password = %d, want 401", code)
	}
	jar, _ := cookiejar.New(nil)
	resp, err = noFollowClient(jar).Post(baseURL+"/auth/ldap/login", "application/json", strings.NewReader(`{"username":"alice","password":"Alice-new-password-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login with the new password = %d, want 302", resp.StatusCode)
	}
	assertAuthMeTenant(t, baseURL, jar, tenantID)
}
