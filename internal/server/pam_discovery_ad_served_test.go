// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
)

// a260SambaImage is the Samba Active Directory build the lab's DC runs, by
// digest.
const a260SambaImage = "nowsci/samba-domain@sha256:953f973514f19f236b0eb838b0e8c98c274b44f70c2bf7f817a0aa931e8f3eb9"

// TestServedActiveDirectoryDiscoveryA260: on a Samba Active Directory domain
// controller (the stand-in for Active Directory), discovery through the LDAP
// provider stages the domain's privileged users — direct and nested members
// of the groups that administer it, a disabled one marked disabled — and not
// a plain user; the scan changes no membership; a re-scan after a member is
// removed shows it removed.
func TestServedActiveDirectoryDiscoveryA260(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if out, err := exec.Command("docker", "image", "inspect", a260SambaImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned image %s is not present locally: %v\n%s", a260SambaImage, err, out)
	}
	const domainPassword = "A260-domain-Pw-1!" // #nosec G101 -- fabricated password of a throwaway test domain (CWE-798)
	id, addr := a201Container(t, "389", "--privileged", "--platform", "linux/amd64", "--hostname", "dc1",
		"-e", "DOMAIN=A260.TEST", "-e", "DOMAINPASS="+domainPassword, "-e", "NOCOMPLEXITY=true", "-e", "INSECURELDAP=true", a260SambaImage)
	samba := func(args ...string) (string, error) {
		return a201Exec(id, append([]string{"samba-tool"}, args...)...)
	}
	deadline := time.Now().Add(5 * time.Minute)
	for {
		if out, err := samba("user", "list", "-H", "ldap://127.0.0.1", "-U", "Administrator%"+domainPassword); err == nil && strings.Contains(out, "Administrator") {
			break
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", "--tail", "40", id).CombinedOutput() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
			t.Fatalf("the Samba DC did not come up\n%s", logs)
		}
		time.Sleep(3 * time.Second)
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := samba(args...); err != nil {
			t.Fatalf("samba-tool %v: %v %s", args, err, out)
		}
	}
	for _, user := range []string{"alice-admin", "bob-nested", "carol-plain", "dave-backup"} {
		run("user", "create", user, "A260-"+user+"-Pw-1!")
	}
	run("group", "addmembers", "Domain Admins", "alice-admin")
	run("group", "add", "tier0-ops")
	run("group", "addmembers", "tier0-ops", "bob-nested")
	run("group", "addmembers", "Domain Admins", "tier0-ops")
	run("group", "addmembers", "Backup Operators", "dave-backup")
	run("user", "disable", "dave-backup")
	memberships := func() string {
		t.Helper()
		var b strings.Builder
		for _, g := range []string{"Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Backup Operators", "tier0-ops"} {
			out, err := samba("group", "listmembers", g)
			if err != nil {
				t.Fatalf("list %s: %v %s", g, err, out)
			}
			b.WriteString(g + "=" + out + ";")
		}
		out, _ := samba("user", "list")
		b.WriteString("users=" + out)
		return b.String()
	}

	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "a260-ad", Type: "ldap", Addr: addr, AllowPlaintext: true,
		BindDN: "CN=Administrator,CN=Users,DC=a260,DC=test", PasswordRef: writeServedCredentialFile(t, "a260-ad-password", domainPassword),
		UsersDN: "CN=Users,DC=a260,DC=test", AllowedRoles: []string{"reader"},
		RoleBindings: map[string]string{"reader": "CN=Domain Users,CN=Users,DC=a260,DC=test"}, MaxTTL: "1h", UsernamePrefix: "a260lease",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, nil, nil, func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: registry.ForTenant(servedTestTenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: time.Second,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a260-ad-operator", "access:read", "access:targets.write")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/discovery/sources/a260-ad", operator, "a260-ad-save",
		map[string]any{"interval_seconds": 0}); status != http.StatusOK {
		t.Fatalf("save source = %d %s", status, body)
	}
	scan := func(key string) a260Run {
		t.Helper()
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/discovery/sources/a260-ad/runs", operator, key, nil)
		var run a260Run
		if status != http.StatusAccepted || json.Unmarshal(body, &run) != nil || run.Status != "queued" {
			t.Fatalf("scan = %d %s", status, body)
		}
		completed := awaitQueuedDiscoveryProofA267(t, h.servedHarness, operator, run.ID)
		if completed.Status != "completed" {
			t.Fatalf("native worker scan failed: %+v", completed)
		}
		return completed
	}
	listed := func() map[string]a260Account {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/accounts?provider_id=a260-ad", operator, nil)
		var page struct {
			Items []a260Account `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			t.Fatalf("list accounts = %d %s", status, body)
		}
		out := map[string]a260Account{}
		for _, a := range page.Items {
			out[a.Name] = a
		}
		return out
	}

	before := memberships()
	scan("a260-ad-scan-1")
	found := listed()
	has := func(name, privilege string) bool {
		for _, p := range found[name].Privileges {
			if p == privilege {
				return true
			}
		}
		return false
	}
	if !has("alice-admin", "group:Domain Admins") || !has("bob-nested", "group:Domain Admins") || !has("dave-backup", "group:Backup Operators") ||
		!has("Administrator", "group:Domain Admins") {
		t.Fatalf("directory accounts = %+v", found)
	}
	if !found["dave-backup"].Disabled || found["alice-admin"].Disabled || found["alice-admin"].Kind != "directory_user" {
		t.Fatalf("directory flags = %+v", found)
	}
	if _, ok := found["carol-plain"]; ok {
		t.Fatalf("a plain user was staged as privileged: %+v", found)
	}
	if after := memberships(); after != before {
		t.Fatalf("the scan changed the directory:\n%s\n→\n%s", before, after)
	}
	run("group", "removemembers", "tier0-ops", "bob-nested")
	run2 := scan("a260-ad-scan-2")
	if run2.Removed != 1 {
		t.Fatalf("the re-scan after removing the nested member = %+v", run2)
	}
	if _, ok := listed()["bob-nested"]; ok {
		t.Fatal("the removed nested member is still staged")
	}
}
