// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/netdevicetest"
)

func networkStandIn(t *testing.T, dialect netdevicetest.Dialect, adminRole string) *netdevicetest.Device {
	t.Helper()
	d, err := netdevicetest.Start(dialect, "netadmin", "admin-password-1", adminRole)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

func networkBackend(t *testing.T, vendor string, d *netdevicetest.Device, roles map[string]string) *NetworkDeviceBackend {
	t.Helper()
	b, err := NewNetworkDeviceBackend(NetworkDeviceConfig{Vendor: vendor, Address: d.Addr(), HostKeyFingerprint: d.FingerprintSHA256(),
		AdminUser: "netadmin", AdminPassword: []byte("admin-password-1"), RoleAccounts: roles})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

// TestNetworkDeviceRotationA270: on each stand-in the bound account's
// password changes in place (IOS-XE keeps its privilege), the new password
// signs in and the old one is refused; IOS-XE's enable secret rotates and is
// proved in privileged mode; a device that will not accept the new password
// is restored to the predecessor, which signs in again; discovery lists
// accounts with their privilege or class and never a hash.
func TestNetworkDeviceRotationA270(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, tc := range []struct {
		vendor    string
		dialect   netdevicetest.Dialect
		adminRole string
		role      string
		fact      string
	}{
		{"iosxe", netdevicetest.IOSXE, "privilege 15", "privilege 7", "privilege 7"},
		{"junos", netdevicetest.Junos, "super-user", "operator", "class operator"},
	} {
		t.Run(tc.vendor, func(t *testing.T) {
			d := networkStandIn(t, tc.dialect, tc.adminRole)
			d.AddAccount("ops", "ops-password-1", tc.role)
			roles := map[string]string{"net/ops": "ops"}
			if tc.vendor == "iosxe" {
				d.SetEnableSecret("enable-secret-1")
				roles["net/enable"] = NetworkEnableAccount
			}
			b := networkBackend(t, tc.vendor, d, roles)
			if _, err := NewNetworkDeviceBackend(NetworkDeviceConfig{Vendor: tc.vendor, Address: d.Addr(), HostKeyFingerprint: d.FingerprintSHA256(),
				AdminUser: "netadmin", AdminPassword: []byte("x"), RoleAccounts: map[string]string{"net/admin": "netadmin"}}); err == nil {
				t.Fatal("a role bound to the administrator was accepted")
			}
			ref, credential, err := b.CreateCredential(ctx, GenerateRequest{Role: "net/ops", LeaseID: "lease-1", Static: true})
			if err != nil {
				t.Fatal(err)
			}
			var issued struct {
				Username, Password string
			}
			if err = json.Unmarshal(credential, &issued); err != nil || issued.Username != "ops" || len(issued.Password) < 24 || ref != "ops/lease-1" {
				t.Fatalf("credential %q %v", ref, err)
			}
			if got := string(d.Password("ops")); got != issued.Password {
				t.Fatal("the device does not hold the issued password")
			}
			if d.Role("ops") != tc.role {
				t.Fatalf("rotation changed the account's level to %q", d.Role("ops"))
			}
			if err = b.VerifyCredential(ctx, credential); err != nil {
				t.Fatal("the new password does not sign in:", err)
			}
			target := crypto.SSHAccountTarget{Address: d.Addr(), HostKeyFingerprint: d.FingerprintSHA256()}
			if err = crypto.VerifySSHAccountPassword(ctx, target, "ops", []byte("ops-password-1")); err == nil {
				t.Fatal("the old password still signs in")
			}
			if d.Writes() == 0 {
				t.Fatal("the change was not saved to the device configuration")
			}
			// Rollback: the device keeps refusing the next password; the
			// predecessor is put back and signs in again.
			d.RejectChangedPasswords(true)
			_, next, err := b.CreateCredential(ctx, GenerateRequest{Role: "net/ops", LeaseID: "lease-2", Static: true})
			if err != nil {
				t.Fatal(err)
			}
			if err = b.VerifyCredential(ctx, next); err == nil {
				t.Fatal("a refused password verified")
			}
			d.RejectChangedPasswords(false)
			if err = b.RestoreStaticCredential(ctx, "net/ops", ref, credential); err != nil {
				t.Fatal("rollback:", err)
			}
			if got := string(d.Password("ops")); got != issued.Password {
				t.Fatal("rollback did not restore the predecessor")
			}
			if tc.vendor == "iosxe" {
				_, enable, err := b.CreateCredential(ctx, GenerateRequest{Role: "net/enable", LeaseID: "lease-3", Static: true})
				if err != nil {
					t.Fatal(err)
				}
				if string(d.EnableSecret()) == "enable-secret-1" {
					t.Fatal("the enable secret did not change")
				}
				if err = b.VerifyCredential(ctx, enable); err != nil {
					t.Fatal("the new enable secret does not enter privileged mode:", err)
				}
			}
			accounts, err := b.DiscoverPrivilegedAccounts(ctx)
			if err != nil {
				t.Fatal(err)
			}
			found := map[string]string{}
			for _, a := range accounts {
				found[a.Name] = strings.Join(a.Privileges, ",")
				for _, p := range a.Privileges {
					if strings.Contains(p, "$") {
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
