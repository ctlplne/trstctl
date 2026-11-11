// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/infratest"
	"trstctl.com/trstctl/internal/crypto/netdevicetest"
	"trstctl.com/trstctl/internal/pamdiscovery"
)

type privilegedAccountDiscoverer interface {
	DiscoverPrivilegedAccounts(context.Context) ([]pamdiscovery.Account, error)
}

// DEV-D1: every device provider names why a scan could not sign in, as the
// esxi provider does (A271-D1). An administrator credential the device refuses
// reads rejected, so an operator fixes the stored credential, and a device
// that does not answer reads unreachable, so they look at the network,
// instead of both reading as a plain error. Each stand-in refuses the way its
// device does: Redfish and vCenter sessions and iControl REST sign-ins with
// 401, eAPI basic authentication with 401, a FortiOS API token with 401,
// vCenter's dir-cli with LDAP error 49, and SSH (the IOS-XE and Junos CLIs,
// vCenter's root shell) by refusing every credential after the host proves
// its pinned key.
func TestDeviceProvidersClassifySignInRefusalsDEVD1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	expect := func(t *testing.T, b privilegedAccountDiscoverer, want, why string) {
		t.Helper()
		_, err := b.DiscoverPrivilegedAccounts(ctx)
		if got := SignInStatusOf(err); got != want {
			t.Fatalf("%s = %q (%v), want %s", why, got, err, want)
		}
	}

	t.Run("redfish", func(t *testing.T) {
		bmc := infratest.StartRedfish("Administrator", "admin-password-1")
		defer bmc.Close()
		b, err := NewRedfishBackend(RedfishConfig{Endpoint: bmc.URL(), HTTPClient: bmc.Client(), AdminUser: "Administrator",
			AdminPassword: []byte("not-the-admin-password"), RoleAccounts: map[string]string{"bmc/ops": "ops"}})
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		expect(t, b, SignInRejected, "a wrong administrator password")
		bmc.Close()
		expect(t, b, SignInUnreachable, "a controller that does not answer")
	})

	t.Run("vcenter-sso", func(t *testing.T) {
		vc, err := infratest.StartVCenter("vsphere.local", "sso-admin-password-1")
		if err != nil {
			t.Fatal(err)
		}
		defer vc.Close()
		other, err := infratest.StartVCenter("vsphere.local", "other-password-1")
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		backend := func(rootKey, adminPassword []byte) *VCenterSSOBackend {
			t.Helper()
			b, err := NewVCenterSSOBackend(VCenterSSOConfig{Endpoint: vc.URL(), HTTPClient: vc.Client(), SSHAddress: vc.SSHAddr(),
				HostKeyFingerprint: vc.FingerprintSHA256(), RootUser: "root", RootKeyPKCS8: rootKey,
				SSOAdmin: "administrator@vsphere.local", SSOAdminPassword: adminPassword, RoleAccounts: map[string]string{"sso/backup": "svc-backup"}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(b.Close)
			return b
		}
		expect(t, backend(vc.RootKeyPKCS8(), []byte("not-the-sso-password")), SignInRejected, "a wrong SSO administrator password (dir-cli error 49)")
		expect(t, backend(other.RootKeyPKCS8(), []byte("sso-admin-password-1")), SignInRejected, "a root key the appliance does not accept")
		right := backend(vc.RootKeyPKCS8(), []byte("sso-admin-password-1"))
		vc.Close()
		expect(t, right, SignInUnreachable, "an appliance that does not answer")
	})

	for _, tc := range []struct {
		vendor    string
		dialect   netdevicetest.Dialect
		adminRole string
	}{
		{"iosxe", netdevicetest.IOSXE, "privilege 15"},
		{"junos", netdevicetest.Junos, "super-user"},
	} {
		t.Run(tc.vendor, func(t *testing.T) {
			d, err := netdevicetest.Start(tc.dialect, "netadmin", "admin-password-1", tc.adminRole)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			b, err := NewNetworkDeviceBackend(NetworkDeviceConfig{Vendor: tc.vendor, Address: d.Addr(), HostKeyFingerprint: d.FingerprintSHA256(),
				AdminUser: "netadmin", AdminPassword: []byte("not-the-admin-password"), RoleAccounts: map[string]string{"net/ops": "ops"}})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			expect(t, b, SignInRejected, "a wrong administrator password")
			d.Close()
			expect(t, b, SignInUnreachable, "a device that does not answer")
		})
	}

	for _, tc := range []struct {
		vendor     string
		dialect    netdevicetest.Dialect
		adminLevel string
	}{
		{"eos", netdevicetest.EOS, "15"},
		{"fortigate", netdevicetest.FortiOS, "super_admin"},
		{"bigip", netdevicetest.BIGIP, "admin"},
	} {
		t.Run(tc.vendor, func(t *testing.T) {
			d, err := netdevicetest.StartAPI(tc.dialect, "netadmin", "admin-credential-1", tc.adminLevel)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			cfg := NetworkAPIConfig{Vendor: tc.vendor, Endpoint: d.URL(), HTTPClient: d.Client(), AdminUser: "netadmin", RoleAccounts: map[string]string{"net/ops": "ops"}}
			if tc.vendor == "fortigate" {
				cfg.APIToken = []byte("not-the-api-token")
			} else {
				cfg.AdminPassword = []byte("not-the-admin-password")
			}
			b, err := NewNetworkAPIBackend(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			expect(t, b, SignInRejected, "a wrong administrator credential")
			d.Close()
			expect(t, b, SignInUnreachable, "a device that does not answer")
		})
	}
}
