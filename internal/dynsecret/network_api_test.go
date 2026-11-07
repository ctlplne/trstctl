// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/netdevicetest"
)

// TestNetworkAPIRotationA270: on each HTTPS stand-in the bound account's
// password changes in place (EOS restates the account's privilege and role,
// which an omitted attribute would reset), the device saves it, the new
// password signs in and the old one is refused; EOS's enable password rotates
// and is proved by entering privileged mode; a device that reports the change
// but keeps the old password fails verification and is restored; a stored
// predecessor a command line cannot take is refused before the device is
// touched; discovery lists accounts with their level and never a hash.
func TestNetworkAPIRotationA270(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, tc := range []struct {
		vendor            string
		dialect           netdevicetest.Dialect
		adminLevel, level string
		role              string
		fact              string
	}{
		{"eos", netdevicetest.EOS, "15", "7", "network-operator", "privilege 7 role network-operator"},
		{"fortigate", netdevicetest.FortiOS, "super_admin", "prof_admin", "", "accprofile prof_admin"},
		{"bigip", netdevicetest.BIGIP, "admin", "operator", "", "role operator on all-partitions"},
	} {
		t.Run(tc.vendor, func(t *testing.T) {
			d, err := netdevicetest.StartAPI(tc.dialect, "netadmin", "admin-credential-1", tc.adminLevel)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			d.AddAccount("ops", "ops-password-1", tc.level, tc.role)
			roles := map[string]string{"net/ops": "ops"}
			if tc.vendor == "eos" {
				d.SetEnableSecret("enable-secret-1")
				roles["net/enable"] = NetworkEnableAccount
			}
			cfg := NetworkAPIConfig{Vendor: tc.vendor, Endpoint: d.URL(), HTTPClient: d.Client(), AdminUser: "netadmin", RoleAccounts: roles}
			if tc.vendor == "fortigate" {
				cfg.APIToken = []byte("admin-credential-1")
			} else {
				cfg.AdminPassword = []byte("admin-credential-1")
			}
			b, err := NewNetworkAPIBackend(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			bad := cfg
			bad.RoleAccounts = map[string]string{"net/admin": "netadmin"}
			if _, err := NewNetworkAPIBackend(bad); err == nil {
				t.Fatal("a role bound to the administrator was accepted")
			}
			saves := d.Saves()
			ref, credential, err := b.CreateCredential(ctx, GenerateRequest{Role: "net/ops", LeaseID: "lease-1", Static: true})
			if err != nil {
				t.Fatal(err)
			}
			var issued struct{ Username, Password string }
			if err = json.Unmarshal(credential, &issued); err != nil || issued.Username != "ops" || len(issued.Password) < 24 || ref != "ops/lease-1" {
				t.Fatalf("credential %q %v", ref, err)
			}
			if string(d.Password("ops")) != issued.Password || d.Level("ops") != tc.level || d.Role("ops") != tc.role {
				t.Fatalf("the device holds level %q role %q after the change", d.Level("ops"), d.Role("ops"))
			}
			if d.Saves() <= saves {
				t.Fatal("the change was not saved")
			}
			if err = b.VerifyCredential(ctx, credential); err != nil || !d.SignsIn("ops", issued.Password) {
				t.Fatal("the new password does not sign in:", err)
			}
			if d.SignsIn("ops", "ops-password-1") {
				t.Fatal("the old password still signs in")
			}
			d.DropNextChanges(1)
			_, next, err := b.CreateCredential(ctx, GenerateRequest{Role: "net/ops", LeaseID: "lease-2", Static: true})
			if err != nil {
				t.Fatal(err)
			}
			if err = b.VerifyCredential(ctx, next); err == nil {
				t.Fatal("a change the device did not take verified")
			}
			if err = b.RestoreStaticCredential(ctx, "net/ops", ref, credential); err != nil || !d.SignsIn("ops", issued.Password) {
				t.Fatal("rollback:", err)
			}
			spaced, _ := json.Marshal(map[string]string{"username": "ops", "password": "has a space"})
			if tc.vendor == "eos" {
				if err = b.RestoreStaticCredential(ctx, "net/ops", ref, spaced); err == nil || !d.SignsIn("ops", issued.Password) {
					t.Fatal("a predecessor the command line cannot take reached the device")
				}
				_, enable, err := b.CreateCredential(ctx, GenerateRequest{Role: "net/enable", LeaseID: "lease-3", Static: true})
				if err != nil {
					t.Fatal(err)
				}
				if string(d.EnableSecret()) == "enable-secret-1" {
					t.Fatal("the enable password did not change")
				}
				if err = b.VerifyCredential(ctx, enable); err != nil {
					t.Fatal("the new enable password does not enter privileged mode:", err)
				}
				wrong, _ := json.Marshal(map[string]string{"username": "enable", "password": "enable-secret-1"})
				if b.VerifyCredential(ctx, wrong) == nil {
					t.Fatal("the old enable password still enters privileged mode")
				}
			}
			accounts, err := b.DiscoverPrivilegedAccounts(ctx)
			if err != nil {
				t.Fatal(err)
			}
			found := map[string]string{}
			for _, a := range accounts {
				found[a.Name] = strings.Join(a.Privileges, " ")
				for _, p := range a.Privileges {
					if strings.Contains(p, "$") || strings.Contains(p, "ENC") {
						t.Fatalf("discovery surfaced a hash: %q", p)
					}
				}
			}
			if found["ops"] != tc.fact || found["netadmin"] == "" {
				t.Fatalf("discovered %v", found)
			}
		})
	}
}
