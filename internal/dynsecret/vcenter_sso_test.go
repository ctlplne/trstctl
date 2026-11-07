// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/infratest"
)

// TestVCenterSSORotationA271: dir-cli in the appliance's root shell resets
// the bound SSO user's password, with the SSO administrator's password typed
// at dir-cli's prompt (never on a command line, which the appliance logs as
// Ran); the new password opens a REST session and the old one does not; an
// appliance that keeps the old password fails verification and is restored;
// the administrator cannot be bound; discovery lists the Administrators
// group; every REST session is ended.
func TestVCenterSSORotationA271(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	vc, err := infratest.StartVCenter("vsphere.local", "sso-admin-password-1")
	if err != nil {
		t.Fatal(err)
	}
	defer vc.Close()
	vc.AddUser("svc-backup", "svc-backup-password-1", true)
	vc.AddUser("reader", "reader-password-1", false)
	cfg := VCenterSSOConfig{Endpoint: vc.URL(), HTTPClient: vc.Client(), SSHAddress: vc.SSHAddr(), HostKeyFingerprint: vc.FingerprintSHA256(),
		RootUser: "root", RootKeyPKCS8: vc.RootKeyPKCS8(), SSOAdmin: "administrator@vsphere.local", SSOAdminPassword: []byte("sso-admin-password-1"),
		RoleAccounts: map[string]string{"sso/backup": "svc-backup"}}
	b, err := NewVCenterSSOBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	bad := cfg
	bad.RoleAccounts = map[string]string{"sso/admin": "administrator"}
	if _, err := NewVCenterSSOBackend(bad); err == nil {
		t.Fatal("a role bound to the SSO administrator was accepted")
	}
	ref, credential, err := b.CreateCredential(ctx, GenerateRequest{Role: "sso/backup", LeaseID: "lease-1", Static: true})
	if err != nil {
		t.Fatal(err)
	}
	var issued struct{ Username, Password string }
	if err = json.Unmarshal(credential, &issued); err != nil || issued.Username != "svc-backup@vsphere.local" || ref != "svc-backup/lease-1" ||
		string(vc.Password("svc-backup")) != issued.Password {
		t.Fatalf("credential %q %+v %v", ref, issued.Username, err)
	}
	if err = b.VerifyCredential(ctx, credential); err != nil || !vc.SignsIn("svc-backup", issued.Password) || vc.SignsIn("svc-backup", "svc-backup-password-1") {
		t.Fatal("the user did not move to the new password alone:", err)
	}
	for _, line := range vc.Ran() {
		if strings.Contains(line, "sso-admin-password-1") {
			t.Fatalf("the administrator's password reached a command line: %q", line)
		}
	}
	vc.DropNextChanges(1)
	_, next, err := b.CreateCredential(ctx, GenerateRequest{Role: "sso/backup", LeaseID: "lease-2", Static: true})
	if err != nil {
		t.Fatal(err)
	}
	if b.VerifyCredential(ctx, next) == nil {
		t.Fatal("a reset the appliance did not take verified")
	}
	if err = b.RestoreStaticCredential(ctx, "sso/backup", ref, credential); err != nil || !vc.SignsIn("svc-backup", issued.Password) {
		t.Fatal("rollback:", err)
	}
	accounts, err := b.DiscoverPrivilegedAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, a := range accounts {
		names = append(names, a.Name)
	}
	if !slices.Equal(names, []string{"administrator", "svc-backup"}) {
		t.Fatalf("discovered %v", names)
	}
	if vc.Sessions() != 0 {
		t.Fatalf("%d REST sessions were left open", vc.Sessions())
	}
}
