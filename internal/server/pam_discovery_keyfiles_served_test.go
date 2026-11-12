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

// TestServedHostScanReadsTheConfiguredAuthorizedKeysFilesA260L2 is A260-L2: a
// Linux host's privileged account scan reads the authorized keys files sshd
// reads, not only ~/.ssh. The lab host's sshd takes AuthorizedKeysFile from
// an included file: each home's .ssh/authorized_keys and a central
// /etc/ssh/keys.d/%u. A sudo member's key sits only in the central
// directory, and a key in its authorized_keys2, which this sshd no longer
// reads, is not counted. The account says where its keys were read from and
// that an AuthorizedKeysCommand can add keys no file holds. The scan changes
// nothing on the host.
func TestServedHostScanReadsTheConfiguredAuthorizedKeysFilesA260L2(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
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
	defer secret.Wipe(der)
	lab := startLabSSHAccounts(t, adminPublic)
	hostShell := func(line string) string {
		t.Helper()
		out, err := lab.shell(line, nil)
		if err != nil {
			t.Fatalf("%s: %v %s", line, err, out)
		}
		return out
	}
	const centralKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEONBEKOQaw/bt2mEQDmf9AQ68I5RY375vL/1Fe94Slh alice@central"
	const unreadKey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBP6UiOzCUKMXMPaGQ3pH7FQEjY4DgBzEvVSIgotafOnSo4ZQfbmLQDHFsQI8Z0jczvlg9mZiJL2AULsQD9dsQ+k= old"
	hostShell("usermod -aG sudo orders-svc-a && mkdir -p /etc/ssh/keys.d /home/orders-svc-a/.ssh && " +
		"echo '" + centralKey + "' > /etc/ssh/keys.d/orders-svc-a && echo '" + unreadKey + "' > /home/orders-svc-a/.ssh/authorized_keys2 && " +
		"printf 'AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/keys.d/%%u\\nAuthorizedKeysCommand /usr/local/bin/lab-keys %%u\\nAuthorizedKeysCommandUser nobody\\n' " +
		"> /etc/ssh/sshd_config.d/20-keys.conf")
	if config := hostShell("grep -i '^Include' /etc/ssh/sshd_config"); !strings.Contains(config, "sshd_config.d") {
		t.Fatalf("the lab's sshd_config does not include sshd_config.d: %s", config)
	}
	hostState := func() string {
		return hostShell("cat /etc/passwd /etc/group /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /etc/ssh/keys.d/* /root/.ssh/authorized_keys " +
			"/home/*/.ssh/authorized_keys* 2>/dev/null | sha256sum")
	}
	before := hostState()

	adminPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	providers := []config.DynamicSecretProviderConfig{{TenantID: servedTestTenant, ID: "a260l2-host", Type: "unix", Addr: lab.addr, AdminUser: "root",
		HostKeyFingerprint: lab.fingerprint, PrivateKeyRef: writeServedCredentialFile(t, "a260l2-host-admin-key.pem", string(adminPEM)),
		AllowedRoles: []string{"host/single"}, RoleBindings: map[string]string{"host/single": "orders-single"}, MaxTTL: "1h", AllowStaticRotation: true}}
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
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a260l2-operator", "access:read", "access:targets.write")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/discovery/sources/a260l2-host", operator, "a260l2-save",
		map[string]any{"interval_seconds": 0}); status != http.StatusOK && status != http.StatusCreated {
		t.Fatalf("save the source = %d %s", status, body)
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/discovery/sources/a260l2-host/runs", operator, "a260l2-scan", nil)
	var run a260Run
	if status != http.StatusAccepted || json.Unmarshal(body, &run) != nil {
		t.Fatalf("scan = %d %s", status, body)
	}
	if run = awaitQueuedDiscoveryProofA267(t, h.servedHarness, operator, run.ID); run.Status != "completed" {
		t.Fatalf("scan run = %+v", run)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/accounts?provider_id=a260l2-host", operator, nil)
	var page struct {
		Items []a260Account `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
		t.Fatalf("list accounts = %d %s", status, body)
	}
	found := map[string]a260Account{}
	for _, account := range page.Items {
		found[account.Name] = account
	}
	member, root := found["orders-svc-a"], found["root"]
	if member.Name == "" || root.Name == "" {
		t.Fatalf("accounts = %+v", found)
	}
	// The central file's key is the sudo member's only key; authorized_keys2
	// is not read by this sshd, so its key is not counted.
	if got := member.Details["authorized_keys"]; got != "ssh-ed25519 SHA256:ZUpKtGMGRETPHM0PB9T33QPyS819RJFBPoNlAV+BA3Q" ||
		!strings.Contains(strings.Join(member.Privileges, " "), "authorized_keys:1") {
		t.Fatalf("orders-svc-a = %+v", member)
	}
	for name, account := range map[string]a260Account{"orders-svc-a": member, "root": root} {
		if account.Details["authorized_keys_files"] != ".ssh/authorized_keys /etc/ssh/keys.d/%u" || account.Details["authorized_keys_command"] != "configured" {
			t.Fatalf("%s does not say where its keys were read from: %+v", name, account.Details)
		}
	}
	// root's key (the administrator's) is still read from its home.
	if !strings.Contains(strings.Join(root.Privileges, " "), "authorized_keys:1") {
		t.Fatalf("root = %+v", root)
	}
	if after := hostState(); after != before {
		t.Fatalf("the scan changed the host: %s → %s", before, after)
	}
	t.Logf("A260L2_KEYFILES_OK %s", member.Details["authorized_keys_files"])
}
