// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

const a239OpenLDAPImage = "osixia/openldap:1.5.0@sha256:18742e9c449c9c1afe129d3f2f3ee15fb34cc43e5f940a20f3399728f41d7c28"

// A239 on a real directory: the LDAP provider, configured as the binary
// configures it and reached over LDAPS with the directory's CA pinned, issues
// a lease that the directory's own ldapwhoami accepts, in the role's group
// only; a replayed issue converges on that one entry; renewal stays within the
// provider's maximum TTL; revocation deletes the entry, after which
// ldapwhoami is refused with invalid credentials.
func TestServedDynamicLDAPLeaseOnOpenLDAPA239(t *testing.T) {
	lab := startLabOpenLDAP(t)
	ctx := context.Background()
	admin, adminPassword, base := lab.admin, lab.adminPassword, lab.base
	addr, ldap := lab.addr, lab.tool
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

dn: cn=writers,ou=groups,dc=lab,dc=test
objectClass: groupOfNames
cn: writers
member: cn=admin,dc=lab,dc=test
`)
	// Credential references must not be readable by group or others; the
	// provider gets its own 0600 copy of the CA it pins.
	caRef := writeServedCredentialFile(t, "ldap-ca.pem", string(lab.trustPEM))

	registry, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "ldap-leases", Type: "ldap", Addr: addr,
		TLSServerName: "ldap.lab.test", TLSCARef: caRef, BindDN: admin,
		PasswordRef: writeServedCredentialFile(t, "ldap-admin-password", adminPassword), UsersDN: "ou=leases," + base,
		AllowedRoles: []string{"readonly"}, RoleBindings: map[string]string{"readonly": "cn=readers,ou=groups," + base},
		MaxTTL: "1h", UsernamePrefix: "a239",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "A239 LDAP tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	issue := func() dynamicLeaseView {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-ldap-lease-1",
			map[string]any{"provider": "ldap-leases", "role": "readonly", "ttl_seconds": 600})
		if status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("issue: %d %s", status, body)
		}
		var lease dynamicLeaseView
		if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
			t.Fatalf("decode the lease: %v %s", err, body)
		}
		return lease
	}
	lease := issue()
	var credential struct {
		URL      string `json:"url"`
		BindDN   string `json:"bind_dn"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || !strings.HasSuffix(credential.BindDN, ",ou=leases,"+base) {
		t.Fatalf("credential %+v err %v", credential.BindDN, err)
	}
	if out, err := ldap("ldapwhoami", "-D", credential.BindDN, "-w", credential.Password); err != nil || !strings.Contains(out, credential.BindDN) {
		t.Fatalf("the directory refused the leased account: %v %s", err, out)
	}
	members, _ := ldap("ldapsearch", "-D", admin, "-w", adminPassword, "-b", "ou=groups,"+base, "-LLL", "member")
	if !strings.Contains(members, "dn: cn=readers") || strings.Count(members, credential.BindDN) != 1 {
		t.Fatalf("group membership:\n%s", members)
	}
	// A replayed issue returns the same lease; the directory holds one entry.
	if again := issue(); again.ID != lease.ID {
		t.Fatalf("a replayed issue made lease %s beside %s", again.ID, lease.ID)
	}
	entries, _ := ldap("ldapsearch", "-D", admin, "-w", adminPassword, "-b", "ou=leases,"+base, "-s", "one", "-LLL", "dn")
	if strings.Count(entries, "dn: ") != 1 {
		t.Fatalf("leased entries:\n%s", entries)
	}
	// Renewal is capped by the provider's maximum TTL (1h).
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", tok, map[string]any{"extend_seconds": 1800})
	if status != http.StatusOK {
		t.Fatalf("renew: %d %s", status, body)
	}
	var renewed dynamicLeaseView
	_ = json.Unmarshal(body, &renewed)
	if limit := lease.IssuedAt.Add(time.Hour + time.Minute); renewed.ExpiresAt.IsZero() || renewed.ExpiresAt.After(limit) {
		t.Fatalf("renewed to %s, past the 1h maximum from %s", renewed.ExpiresAt, lease.IssuedAt)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", tok, map[string]any{"extend_seconds": 7200})
	_ = json.Unmarshal(body, &renewed)
	if status == http.StatusOK && renewed.ExpiresAt.After(lease.IssuedAt.Add(time.Hour+time.Minute)) {
		t.Fatalf("a renewal past the maximum TTL was granted: %s", renewed.ExpiresAt)
	}

	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke: %d %s", status, body)
	}
	a201Await(t, "the lease's directory entry to go", func() bool {
		out, err := ldap("ldapwhoami", "-D", credential.BindDN, "-w", credential.Password)
		return err != nil && strings.Contains(out, "Invalid credentials (49)")
	})
	members, _ = ldap("ldapsearch", "-D", admin, "-w", adminPassword, "-b", "ou=groups,"+base, "-LLL", "member")
	if strings.Contains(members, credential.BindDN) {
		t.Fatalf("the revoked entry is still a group member:\n%s", members)
	}
	t.Logf("A239_LDAP_OK lease=%s dn=%s", lease.ID, credential.BindDN)
}
