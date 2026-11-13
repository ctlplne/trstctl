// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A260-L3 Done-when (lab host): privileged account discovery through a
// non-root administrator reads sudo rights the sudoers files hide from it.
// The administrator may not read /etc/sudoers or /etc/sudoers.d (0440 root)
// but holds sudoers' list right for every user ((ALL) NOPASSWD: list), so the
// discovery asks sudo for each login
// account's rights: a member of sudo reads sudo:ALL, the account a sudoers.d
// rule names for one command sudo:commands, and each says its rights were
// listed by sudo; the administrator's own list right is not a privilege. The
// scan changes nothing on the host.
func TestServedPrivilegedDiscoveryListsSudoRightsA260L3(t *testing.T) {
	adminKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer adminKey.Destroy()
	adminPublic, err := crypto.SSHPublicKeyFromSigner(adminKey)
	if err != nil {
		t.Fatal(err)
	}
	der, err := adminKey.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	lab := startLabSSHAccounts(t, adminPublic)
	if out, err := lab.shell("useradd -m -s /bin/bash discover-admin && mkdir -p /home/discover-admin/.ssh && "+
		"cat > /home/discover-admin/.ssh/authorized_keys && chown -R discover-admin: /home/discover-admin/.ssh && "+
		"chmod 0700 /home/discover-admin/.ssh && chmod 0600 /home/discover-admin/.ssh/authorized_keys", adminPublic); err != nil {
		t.Fatalf("add the discovery administrator: %v %s", err, out)
	}
	if out, err := lab.shell("printf 'root ALL=(ALL:ALL) ALL\\n%%sudo ALL=(ALL:ALL) ALL\\ndiscover-admin ALL = (ALL) NOPASSWD: list\\n@includedir /etc/sudoers.d\\n' > /etc/sudoers && "+
		"chmod 0440 /etc/sudoers && mkdir -p /etc/sudoers.d && "+
		"printf 'orders-single ALL=(root) NOPASSWD: /usr/bin/systemctl restart app\\n' > /etc/sudoers.d/deploy && chmod 0440 /etc/sudoers.d/deploy && "+
		"usermod -aG sudo orders-svc-a && sudo -V | head -n 1", nil); err != nil {
		t.Fatalf("write the sudoers rules: %v %s", err, out)
	} else {
		t.Logf("lab host: %s", strings.TrimSpace(out))
	}
	hostFiles := func() string {
		out, err := lab.shell("cat /etc/passwd /etc/group /etc/shadow /etc/sudoers /etc/sudoers.d/* | sha256sum", nil)
		if err != nil {
			t.Fatalf("hash the host's account files: %v %s", err, out)
		}
		return out
	}
	adminPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	providers := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "a260l3-host", Type: "unix", Addr: lab.addr, AdminUser: "discover-admin",
		HostKeyFingerprint: lab.fingerprint, PrivateKeyRef: writeServedCredentialFile(t, "a260l3-host-admin-key.pem", string(adminPEM)),
		AllowedRoles: []string{"host/single"}, RoleBindings: map[string]string{"host/single": "orders-single"}, MaxTTL: "1h",
		AllowStaticRotation: true,
	}}
	secret.Wipe(adminPEM)
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), providers, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, nil, nil, func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: registry.ForTenant(servedTestTenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: time.Second,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a260l3-operator", "access:read", "access:targets.write")
	if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/discovery/sources/a260l3-host", operator,
		"a260l3-save", map[string]any{"interval_seconds": 0}); status != http.StatusOK {
		t.Fatalf("save the source: HTTP %d %s", status, raw)
	}
	before := hostFiles()
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/discovery/sources/a260l3-host/runs", operator, "a260l3-scan", nil)
	var run a260Run
	if status != http.StatusAccepted || json.Unmarshal(body, &run) != nil {
		t.Fatalf("scan = %d %s", status, body)
	}
	if run = awaitQueuedDiscoveryProofA267(t, h.servedHarness, operator, run.ID); run.Status != "completed" {
		t.Fatalf("the scan = %+v", run)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/accounts?provider_id=a260l3-host", operator, nil)
	var page struct {
		Items []a260Account `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
		t.Fatalf("list accounts = %d %s", status, body)
	}
	found := map[string]a260Account{}
	for _, a := range page.Items {
		found[a.Name] = a
	}
	for name, want := range map[string]string{
		"root":          "group:root sudo:ALL uid0",
		"orders-svc-a":  "group:sudo sudo:ALL",
		"orders-single": "sudo:commands",
	} {
		a, ok := found[name]
		if got := strings.Join(a.Privileges, " "); !ok || got != want || a.Details["sudoers"] != "listed by sudo" {
			t.Fatalf("%s reads %q %v (found %v), want %q listed by sudo; all: %+v", name, got, a.Details, ok, want, found)
		}
	}
	if _, ok := found["discover-admin"]; ok {
		t.Fatalf("the administrator's list right read as a privilege: %+v", found["discover-admin"])
	}
	if after := hostFiles(); after != before {
		t.Fatal("the scan changed the host's account files")
	}
	t.Logf("A260L3_SUDO_LIST_OK accounts=%d", len(found))
}
