// SPDX-License-Identifier: BUSL-1.1

package config

import "testing"

func TestTenantNotificationPrivateEgressIsAnOperatorGrant(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	for _, cidr := range []string{"10.40.0.0/16", "192.168.2.3/32", "fd12:3456::/48"} {
		if errs := validateNotifications(Notifications{TenantPrivateEgress: []TenantPrivateEgress{{TenantID: tenant, CIDRs: []string{cidr}}}}); len(errs) != 0 {
			t.Fatalf("valid grant %s: %v", cidr, errs)
		}
	}
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "10.1.2.3/8", "10.0.0.0/7", "127.0.0.1/32", "169.254.169.254/32", "fd00:ec2::254/128", "8.8.8.8/32", "bad"} {
		t.Run(cidr, func(t *testing.T) {
			if errs := validateNotifications(Notifications{TenantPrivateEgress: []TenantPrivateEgress{{TenantID: tenant, CIDRs: []string{cidr}}}}); len(errs) == 0 {
				t.Fatal("unsafe grant accepted")
			}
		})
	}
	for _, grants := range [][]TenantPrivateEgress{
		{{TenantID: "not-a-tenant", CIDRs: []string{"10.0.0.0/8"}}},
		{{TenantID: "00000000-0000-0000-0000-000000000000", CIDRs: []string{"10.0.0.0/8"}}},
		{{TenantID: tenant}},
		{{TenantID: tenant, CIDRs: []string{"10.0.0.0/8"}}, {TenantID: tenant, CIDRs: []string{"192.168.0.0/16"}}},
		{{TenantID: tenant, CIDRs: []string{"10.0.0.0/8"}}, {TenantID: "11111111111111111111111111111111", CIDRs: []string{"192.168.0.0/16"}}},
	} {
		if errs := validateNotifications(Notifications{TenantPrivateEgress: grants}); len(errs) == 0 {
			t.Fatalf("invalid grants accepted: %+v", grants)
		}
	}
}
