// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// TestServedDynamicLDAPLeaseExpiresInTheDirectoryA239L2 is A239-L2 served, on
// the pinned OpenLDAP image with its stock dds overlay loaded: an ldap
// provider with dynamic_entries, configured as an operator writes it, issues
// a lease whose entry is a dynamic object the directory keeps for the lease's
// time (entryTtl), and the provider catalog says its leases expire in the
// directory. A renewal through the API moves the directory's expiry with the
// lease. Then trstctl does nothing — no lease worker runs and nothing revokes
// — and the directory deletes the entry once the lease's time runs out, not
// before: the password no longer binds. When trstctl's lease worker runs
// again, its revocation of the expired lease completes against the entry the
// directory already removed, and the role group keeps no member for it.
func TestServedDynamicLDAPLeaseExpiresInTheDirectoryA239L2(t *testing.T) {
	lab := startLabOpenLDAPWith(t, labOpenLDAPOptions{dds: true})
	admin, adminPassword, base := lab.admin, lab.adminPassword, lab.base
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
	var configs []config.DynamicSecretProviderConfig
	if err := json.Unmarshal([]byte(fmt.Sprintf(`[{"tenant_id": %q, "id": "ldap-dds", "type": "ldap", "addr": %q,
	  "tls_server_name": "ldap.lab.test", "tls_ca_ref": %q, "bind_dn": %q, "password_ref": %q, "users_dn": %q,
	  "allowed_roles": ["readonly"], "role_bindings": {"readonly": %q}, "max_ttl": "1h", "username_prefix": "a239l2",
	  "dynamic_entries": true}]`, servedTestTenant, lab.addr, caRef, admin, passwordRef, "ou=leases,"+base, "cn=readers,ou=groups,"+base)), &configs); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
		d.DynamicLeaseWorkerInterval = 200 * time.Millisecond
	})
	registerServedTenant(t, h, "A239-L2 LDAP dynamic entries tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	// The catalog says this provider's leases also expire in the directory.
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/providers", tok, nil)
	var catalog struct {
		Configured []struct {
			ID            string `json:"id"`
			BackendExpiry string `json:"backend_expiry"`
		} `json:"configured_providers"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &catalog) != nil || len(catalog.Configured) != 1 ||
		catalog.Configured[0].ID != "ldap-dds" || catalog.Configured[0].BackendExpiry != "directory" {
		t.Fatalf("provider catalog: HTTP %d %s", status, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239l2-lease",
		map[string]any{"provider": "ldap-dds", "role": "readonly", "ttl_seconds": 30})
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || (status != http.StatusCreated && status != http.StatusOK) || lease.Credential == "" {
		t.Fatalf("issue a dynamic-entry lease: HTTP %d %s", status, body)
	}
	var credential struct {
		BindDN   string `json:"bind_dn"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || !strings.HasSuffix(credential.BindDN, ",ou=leases,"+base) {
		t.Fatalf("the lease's credential names %q (%v)", credential.BindDN, err)
	}
	bind := func() (string, error) {
		return lab.tool("ldapwhoami", "-D", credential.BindDN, "-w", credential.Password)
	}
	entryTTL := func() (int, string) {
		out, err := lab.tool("ldapsearch", "-D", admin, "-w", adminPassword, "-b", credential.BindDN, "-s", "base", "-LLL", "entryTtl")
		if err != nil {
			return -1, out
		}
		for _, line := range strings.Split(out, "\n") {
			if value, ok := strings.CutPrefix(strings.TrimSpace(line), "entryTtl: "); ok {
				ttl, convErr := strconv.Atoi(value)
				if convErr == nil {
					return ttl, out
				}
			}
		}
		return -1, out
	}
	if out, err := bind(); err != nil || !strings.Contains(out, credential.BindDN) {
		t.Fatalf("the directory refused the lease's credential: %v %s", err, out)
	}
	if ttl, out := entryTTL(); ttl < 20 || ttl > 30 {
		t.Fatalf("the lease's entry has entryTtl %d, want the lease's 30 s:\n%s", ttl, out)
	}

	// A renewal through the API moves the directory's expiry with the lease.
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", tok, "a239l2-renew",
		map[string]any{"extend_seconds": 20})
	var renewed dynamicLeaseView
	if err := json.Unmarshal(body, &renewed); err != nil || status != http.StatusOK || !renewed.ExpiresAt.Equal(lease.ExpiresAt.Add(20*time.Second)) {
		t.Fatalf("renew the lease: HTTP %d %s", status, body)
	}
	if ttl, out := entryTTL(); float64(ttl) < time.Until(renewed.ExpiresAt).Seconds()-3 || float64(ttl) > time.Until(renewed.ExpiresAt).Seconds()+3 {
		t.Fatalf("the renewed entry has entryTtl %d, want about %.0f s (the lease's new expiry):\n%s", ttl, time.Until(renewed.ExpiresAt).Seconds(), out)
	}
	t.Logf("lease %s renewed to %s; trstctl now does nothing", lease.ID, renewed.ExpiresAt.Format(time.RFC3339))

	// trstctl does nothing: no lease worker runs, nothing revokes. The
	// directory deletes the entry once the lease's time runs out, not before.
	var gone time.Time
	for deadline := renewed.ExpiresAt.Add(60 * time.Second); gone.IsZero(); {
		if _, out := entryTTL(); strings.Contains(out, "No such object (32)") {
			gone = time.Now()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the directory did not delete the lease's entry after its time ran out")
		}
		time.Sleep(time.Second)
	}
	if gone.Before(renewed.ExpiresAt.Add(-time.Second)) {
		t.Fatalf("the directory deleted the entry at %s, before the lease's expiry %s", gone.Format(time.RFC3339), renewed.ExpiresAt.Format(time.RFC3339))
	}
	if out, err := bind(); err == nil || !strings.Contains(out, "Invalid credentials (49)") {
		t.Fatalf("the expired lease's credential still binds: %v %s", err, out)
	}
	if status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+lease.ID, tok, nil); status != http.StatusOK ||
		json.Unmarshal(body, &renewed) != nil || renewed.RevocationStatus != "none" {
		t.Fatalf("trstctl revoked the lease itself: HTTP %d %s", status, body)
	}

	// trstctl comes back: its lease worker revokes the expired lease, and the
	// revocation completes against the entry the directory already removed.
	worker, ok := any(h.srv).(interface{ RunDynamicLeaseWorker(context.Context) })
	if !ok {
		t.Fatal("served dynamic lease worker is not wired")
	}
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		worker.RunDynamicLeaseWorker(workerCtx)
	}()
	t.Cleanup(func() {
		cancelWorker()
		<-workerDone
	})
	a201Await(t, "the expired lease's revocation to complete", func() bool {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+lease.ID, tok, nil)
		var current dynamicLeaseView
		return status == http.StatusOK && json.Unmarshal(body, &current) == nil && current.RevocationStatus == "completed"
	})
	if members, err := lab.tool("ldapsearch", "-D", admin, "-w", adminPassword, "-b", "cn=readers,ou=groups,"+base, "-s", "base", "-LLL", "member"); err != nil ||
		strings.Contains(strings.ToLower(members), strings.ToLower(credential.BindDN)) {
		t.Fatalf("the role group after the expiry: %v\n%s", err, members)
	}
	t.Logf("A239L2_SERVED_OK lease=%s dn=%s deleted by the directory %.1fs after the lease's expiry", lease.ID, credential.BindDN, gone.Sub(renewed.ExpiresAt).Seconds())
}
