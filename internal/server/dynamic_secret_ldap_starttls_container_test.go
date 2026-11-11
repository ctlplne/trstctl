// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// TestServedDynamicLDAPLeaseOverStartTLSA239L3 is A239-L3 on a real directory
// that refuses every operation not over TLS (LDAP_TLS_ENFORCE): its plain port
// answers a plaintext bind "confidentiality required". An LDAP provider set to
// start_tls, pointed at that plain port (389) with the directory's CA pinned,
// upgrades before it binds: a lease is issued, its credential names the
// ldap:// URL with start_tls, the directory's own ldapwhoami (over StartTLS)
// accepts it, and revocation removes it. The same provider expecting another
// certificate name issues nothing: the upgrade's verification fails and there
// is no plaintext fallback.
func TestServedDynamicLDAPLeaseOverStartTLSA239L3(t *testing.T) {
	lab := startLabOpenLDAPWith(t, labOpenLDAPOptions{startTLS: true})
	admin, adminPassword, base := lab.admin, lab.adminPassword, lab.base
	// The directory refuses a plaintext bind on its plain port.
	if out, err := a201Exec(lab.id, "ldapwhoami", "-x", "-H", "ldap://localhost", "-D", admin, "-w", adminPassword); err == nil ||
		!strings.Contains(out, "Confidentiality required") {
		t.Fatalf("the lab directory accepted a plaintext bind: %v %s", err, out)
	}
	lab.seed(t, `dn: ou=leases,dc=lab,dc=test
objectClass: organizationalUnit
ou: leases

dn: ou=groups,dc=lab,dc=test
objectClass: organizationalUnit
ou: groups

dn: cn=readers,ou=groups,dc=lab,dc=test
objectClass: groupOfNames
cn: readers
member: cn=admin,dc=lab,dc=test
`)
	caRef := writeServedCredentialFile(t, "ldap-ca.pem", string(lab.trustPEM))
	passwordRef := writeServedCredentialFile(t, "ldap-admin-password", adminPassword)
	// The providers as an operator writes them: one verifying the directory's
	// name, one expecting a name the certificate doesn't carry.
	var configs []config.DynamicSecretProviderConfig
	provider := func(id, serverName string) string {
		return fmt.Sprintf(`{"tenant_id": %q, "id": %q, "type": "ldap", "addr": %q, "start_tls": true,
		  "tls_server_name": %q, "tls_ca_ref": %q, "bind_dn": %q, "password_ref": %q, "users_dn": %q,
		  "allowed_roles": ["readonly"], "role_bindings": {"readonly": %q}, "max_ttl": "1h", "username_prefix": "a239l3"}`,
			servedTestTenant, id, lab.plainAddr, serverName, caRef, admin, passwordRef, "ou=leases,"+base, "cn=readers,ou=groups,"+base)
	}
	if err := json.Unmarshal([]byte("["+provider("ldap-starttls", "ldap.lab.test")+","+provider("ldap-wrong-name", "other.lab.test")+"]"), &configs); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the providers as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "A239-L3 LDAP StartTLS tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239l3-lease-1",
		map[string]any{"provider": "ldap-starttls", "role": "readonly", "ttl_seconds": 600})
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || (status != http.StatusCreated && status != http.StatusOK) || lease.Credential == "" {
		t.Fatalf("issue over StartTLS: HTTP %d %s", status, body)
	}
	var credential struct {
		URL      string `json:"url"`
		StartTLS bool   `json:"start_tls"`
		BindDN   string `json:"bind_dn"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.URL != "ldap://"+lab.plainAddr || !credential.StartTLS ||
		!strings.HasSuffix(credential.BindDN, ",ou=leases,"+base) {
		t.Fatalf("the lease's credential: url %q start_tls %v dn %q (%v)", credential.URL, credential.StartTLS, credential.BindDN, err)
	}
	if out, err := lab.tool("ldapwhoami", "-D", credential.BindDN, "-w", credential.Password); err != nil || !strings.Contains(out, credential.BindDN) {
		t.Fatalf("the directory refused the leased account over StartTLS: %v %s", err, out)
	}

	// Another expected name: the upgrade's verification fails, nothing is issued.
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239l3-lease-wrong-name",
		map[string]any{"provider": "ldap-wrong-name", "role": "readonly", "ttl_seconds": 600})
	var refused dynamicLeaseView
	if err := json.Unmarshal(body, &refused); err != nil || refused.Credential != "" {
		t.Fatalf("a provider expecting another certificate name: HTTP %d %s", status, body)
	}
	if refused.ID != "" {
		for deadline := time.Now().Add(60 * time.Second); refused.State != "failed"; {
			if time.Now().After(deadline) {
				t.Fatalf("the lease against the wrong name reads %+v, want failed", refused)
			}
			time.Sleep(200 * time.Millisecond)
			_, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+refused.ID, tok, nil)
			_ = json.Unmarshal(body, &refused)
		}
	}
	entries, _ := lab.tool("ldapsearch", "-D", admin, "-w", adminPassword, "-b", "ou=leases,"+base, "-s", "one", "-LLL", "dn")
	if strings.Count(entries, "dn: ") != 1 {
		t.Fatalf("leased entries after the refused upgrade:\n%s", entries)
	}

	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke: %d %s", status, body)
	}
	a201Await(t, "the lease's directory entry to go", func() bool {
		out, err := lab.tool("ldapwhoami", "-D", credential.BindDN, "-w", credential.Password)
		return err != nil && strings.Contains(out, "Invalid credentials (49)")
	})
	t.Logf("A239L3_STARTTLS_OK lease=%s dn=%s", lease.ID, credential.BindDN)
}
