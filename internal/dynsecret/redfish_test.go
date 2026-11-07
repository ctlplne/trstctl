// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/infratest"
)

// TestRedfishRotationA271: the bound account's password changes through a
// Redfish session, the new password opens a session and the old one does
// not; a controller that answers but keeps the old password fails
// verification and is restored; every session is logged out; discovery lists
// each account with its RoleId and never a password.
func TestRedfishRotationA271(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bmc := infratest.StartRedfish("Administrator", "admin-password-1")
	defer bmc.Close()
	bmc.AddAccount("ops", "ops-password-1", "Operator")
	bmc.AddAccount("monitor", "monitor-password-1", "ReadOnly")
	b, err := NewRedfishBackend(RedfishConfig{Endpoint: bmc.URL(), HTTPClient: bmc.Client(), AdminUser: "Administrator",
		AdminPassword: []byte("admin-password-1"), RoleAccounts: map[string]string{"bmc/ops": "ops"}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := NewRedfishBackend(RedfishConfig{Endpoint: bmc.URL(), HTTPClient: bmc.Client(), AdminUser: "Administrator",
		AdminPassword: []byte("x"), RoleAccounts: map[string]string{"bmc/admin": "Administrator"}}); err == nil {
		t.Fatal("a role bound to the administrator was accepted")
	}
	ref, credential, err := b.CreateCredential(ctx, GenerateRequest{Role: "bmc/ops", LeaseID: "lease-1", Static: true})
	if err != nil {
		t.Fatal(err)
	}
	var issued struct{ Username, Password string }
	if err = json.Unmarshal(credential, &issued); err != nil || issued.Username != "ops" || ref != "ops/lease-1" || string(bmc.Password("ops")) != issued.Password {
		t.Fatalf("credential %q %v", ref, err)
	}
	if err = b.VerifyCredential(ctx, credential); err != nil || !bmc.SignsIn("ops", issued.Password) || bmc.SignsIn("ops", "ops-password-1") {
		t.Fatal("the account did not move to the new password alone:", err)
	}
	bmc.DropNextChanges(1)
	_, next, err := b.CreateCredential(ctx, GenerateRequest{Role: "bmc/ops", LeaseID: "lease-2", Static: true})
	if err != nil {
		t.Fatal(err)
	}
	if b.VerifyCredential(ctx, next) == nil {
		t.Fatal("a change the controller did not take verified")
	}
	if err = b.RestoreStaticCredential(ctx, "bmc/ops", ref, credential); err != nil || !bmc.SignsIn("ops", issued.Password) {
		t.Fatal("rollback:", err)
	}
	accounts, err := b.DiscoverPrivilegedAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, a := range accounts {
		found[a.Name] = a.Privileges[0]
	}
	if found["ops"] != "role Operator" || found["monitor"] != "role ReadOnly" || found["Administrator"] != "role Administrator" {
		t.Fatalf("discovered %v", found)
	}
	if bmc.Sessions() != 0 {
		t.Fatalf("%d sessions were left open", bmc.Sessions())
	}
}
