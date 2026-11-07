// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/infratest"
)

// TestESXiRotationA271: the bound local account's password changes through
// HostLocalAccountManager.UpdateUser in an administrator session; the new
// password signs in and the old one does not; a host that keeps the old
// password fails verification and is restored; a password with XML markup
// travels escaped; vpxuser is never bound; discovery lists each local user
// with its role; every session is logged out.
func TestESXiRotationA271(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	host := infratest.StartESXi("root", "esxi-root-password-1")
	defer host.Close()
	host.AddAccount("ops", "esxi-ops-password-1", -1)
	host.AddAccount("auditor", "esxi-auditor-password-1", -2)
	host.AddAccount("vpxuser", "managed-by-vcenter", -1)
	cfg := ESXiConfig{Endpoint: host.URL(), HTTPClient: host.Client(), AdminUser: "root", AdminPassword: []byte("esxi-root-password-1"),
		RoleAccounts: map[string]string{"esxi/ops": "ops"}}
	b, err := NewESXiBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for name, roles := range map[string]map[string]string{"vpxuser": {"esxi/v": "vpxuser"}, "administrator": {"esxi/root": "root"}} {
		bad := cfg
		bad.RoleAccounts = roles
		if _, err := NewESXiBackend(bad); err == nil {
			t.Fatalf("binding %s was accepted", name)
		}
	}
	ref, credential, err := b.CreateCredential(ctx, GenerateRequest{Role: "esxi/ops", LeaseID: "lease-1", Static: true})
	if err != nil {
		t.Fatal(err)
	}
	var issued struct{ Username, Password string }
	if err = json.Unmarshal(credential, &issued); err != nil || issued.Username != "ops" || ref != "ops/lease-1" || string(host.Password("ops")) != issued.Password {
		t.Fatalf("credential %q %v", ref, err)
	}
	if err = b.VerifyCredential(ctx, credential); err != nil || !host.SignsIn("ops", issued.Password) || host.SignsIn("ops", "esxi-ops-password-1") {
		t.Fatal("the account did not move to the new password alone:", err)
	}
	host.DropNextChanges(1)
	_, next, err := b.CreateCredential(ctx, GenerateRequest{Role: "esxi/ops", LeaseID: "lease-2", Static: true})
	if err != nil {
		t.Fatal(err)
	}
	if b.VerifyCredential(ctx, next) == nil {
		t.Fatal("a change the host did not take verified")
	}
	markup := "a<b>" + `&"c'`
	marked, _ := json.Marshal(map[string]string{"username": "ops", "password": markup})
	if err = b.RestoreStaticCredential(ctx, "esxi/ops", ref, marked); err != nil || string(host.Password("ops")) != markup {
		t.Fatalf("a password with markup did not travel escaped: %v %q", err, host.Password("ops"))
	}
	if err = b.RestoreStaticCredential(ctx, "esxi/ops", ref, credential); err != nil || !host.SignsIn("ops", issued.Password) {
		t.Fatal("rollback:", err)
	}
	accounts, err := b.DiscoverPrivilegedAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, a := range accounts {
		found[a.Name] = strings.Join(a.Privileges, " ") + "|" + a.Details["system_account"]
	}
	if found["ops"] != "role Admin|" || found["auditor"] != "role ReadOnly|" || found["vpxuser"] != "role Admin|true" || found["root"] != "role Admin|" {
		t.Fatalf("discovered %v", found)
	}
	if host.Sessions() != 0 {
		t.Fatalf("%d sessions were left open", host.Sessions())
	}
}
