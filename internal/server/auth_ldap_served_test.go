// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// TestServedLDAPLoginBindsOpenLDAPAndMapsGroupRole is the IAM-03 acceptance
// test: the served binary must bind a user against a real OpenLDAP backend,
// discover the user's directory group, map that group to a tenant + RBAC role,
// and mint the same browser session used by OIDC and SAML.
func TestServedLDAPLoginBindsOpenLDAPAndMapsGroupRole(t *testing.T) {
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
		t.Fatalf("write LDAP bind password file: %v", err)
	}
	ldapCfg := config.LDAP{
		Enabled:            true,
		URL:                ldapURL,
		UserDNTemplate:     "uid={username},ou=people,dc=example,dc=org",
		BindDN:             "cn=admin,dc=example,dc=org",
		BindPasswordFile:   bindPasswordFile,
		GroupSearchBaseDN:  "ou=groups,dc=example,dc=org",
		GroupFilter:        "(member={user_dn})",
		GroupNameAttribute: "cn",
		EmailAttribute:     "mail",
		SessionSecretFile:  filepath.Join(t.TempDir(), "ldap-session.secret"),
		SessionTTL:         "1h",
		LoginRedirect:      "/",
		TenantMappings: []config.TenantMapping{
			{Group: "trstctl-admins", TenantID: tenantID, Roles: []string{"admin"}},
		},
	}

	srv := buildLDAPServer(t, ctx, dsn, ldapCfg)
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Close() }()

	jar, _ := cookiejar.New(nil)
	client := noFollowClient(jar)
	loginBody := []byte(`{"username":"alice","password":"alice-password"}`)
	resp, err := client.Post(baseURL+"/auth/ldap/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("POST /auth/ldap/login: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /auth/ldap/login = %d, want 302 session redirect: %s", resp.StatusCode, body)
	}

	assertAuthMeTenant(t, baseURL, jar, tenantID)
	assertSessionCanReadAccessRoles(t, baseURL, jar)
}

func startOpenLDAPContainer(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required for the OpenLDAP acceptance backend: %v", err)
	}
	if err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").Run(); err != nil {
		t.Skipf("docker daemon is required for the OpenLDAP acceptance backend: %v", err)
	}

	name := "trstctl-ldap-test-" + strings.NewReplacer(".", "-", "/", "-").Replace(t.Name()) + fmt.Sprintf("-%d", time.Now().UnixNano())
	ldifDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(ldifDir, "01-users.ldif"), []byte(openLDAPFixtureLDIF), 0o600); err != nil {
		t.Fatalf("write OpenLDAP fixture LDIF: %v", err)
	}
	args := []string{
		"run", "-d", "--rm",
		"--name", name,
		"-p", "127.0.0.1::389",
		"-e", "LDAP_ORGANISATION=trstctl test",
		"-e", "LDAP_DOMAIN=example.org",
		"-e", "LDAP_ADMIN_PASSWORD=admin-password",
		"-e", "LDAP_TLS=false",
		"-e", "LDAP_CUSTOM_LDIF_DIR=/container/service/slapd/assets/config/bootstrap/ldif/custom",
		"-v", ldifDir + ":/container/service/slapd/assets/config/bootstrap/ldif/custom:ro",
		"osixia/openldap:1.5.0",
		"--copy-service",
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("start OpenLDAP container: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})

	var endpoint string
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "port", name, "389/tcp").CombinedOutput()
		if err == nil {
			endpoint = strings.TrimSpace(string(out))
			if endpoint != "" {
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if endpoint == "" {
		t.Fatalf("OpenLDAP container did not publish 389/tcp")
	}
	if strings.HasPrefix(endpoint, "0.0.0.0:") {
		endpoint = "127.0.0.1:" + strings.TrimPrefix(endpoint, "0.0.0.0:")
	}

	for time.Now().Before(deadline) {
		cmd := exec.Command("docker", "exec", name, "ldapsearch", "-x",
			"-H", "ldap://127.0.0.1",
			"-D", "cn=admin,dc=example,dc=org",
			"-w", "admin-password",
			"-b", "dc=example,dc=org",
			"(uid=alice)")
		if out, err := cmd.CombinedOutput(); err == nil && bytes.Contains(out, []byte("uid: alice")) && openLDAPUserBindReady(name) {
			return "ldap://" + endpoint
		}
		time.Sleep(750 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
	t.Fatalf("OpenLDAP container did not become ready; logs:\n%s", logs)
	return ""
}

func openLDAPUserBindReady(name string) bool {
	cmd := exec.Command("docker", "exec", name, "ldapsearch", "-x",
		"-H", "ldap://127.0.0.1",
		"-D", "uid=alice,ou=people,dc=example,dc=org",
		"-w", "alice-password",
		"-b", "uid=alice,ou=people,dc=example,dc=org",
		"(objectClass=*)",
		"dn")
	out, err := cmd.CombinedOutput()
	return err == nil && bytes.Contains(out, []byte("dn: uid=alice,ou=people,dc=example,dc=org"))
}

func assertSessionCanReadAccessRoles(t *testing.T, baseURL string, jar http.CookieJar) {
	t.Helper()
	resp, err := (&http.Client{Jar: jar}).Get(baseURL + "/api/v1/access/roles")
	if err != nil {
		t.Fatalf("GET /api/v1/access/roles with LDAP session: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LDAP group-mapped admin session cannot read roles: status=%d body=%s", resp.StatusCode, body)
	}
	if got := string(body); !regexp.MustCompile(`"name"\s*:\s*"admin"`).MatchString(got) {
		t.Fatalf("roles response did not include admin role: %s", got)
	}
}

func buildLDAPServer(t *testing.T, ctx context.Context, dsn string, ldapCfg config.LDAP) *Server {
	t.Helper()
	phaseStore, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open served store: %v", err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		phaseStore.Close()
		t.Fatalf("open event log: %v", err)
	}
	srv, err := Build(ctx, Deps{Store: phaseStore, Log: log, LDAP: ldapCfg})
	if err != nil {
		_ = log.Close()
		phaseStore.Close()
		t.Fatalf("build control plane: %v", err)
	}
	return srv
}

const openLDAPFixtureLDIF = `
dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=example,dc=org
objectClass: organizationalUnit
ou: groups

dn: uid=alice,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: Alice Admin
sn: Admin
uid: alice
uidNumber: 10001
gidNumber: 10001
homeDirectory: /home/alice
mail: alice@example.org
userPassword: alice-password

dn: cn=trstctl-admins,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn: trstctl-admins
member: uid=alice,ou=people,dc=example,dc=org
`
