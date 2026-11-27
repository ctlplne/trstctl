// SPDX-License-Identifier: BUSL-1.1

package api

import "testing"

func TestSpecialRouteBudgetCanonicalizesVerifiedTenantID(t *testing.T) {
	limiter := newSpecialRouteAbuseLimiter(SpecialRouteAbuseLimits{
		Global: 10, PerSource: 10, PerToken: 10, PerTenant: 1,
	})
	for n, tenant := range []string{
		"A1B2C3D4-1111-4111-8111-123456789ABC",
		"a1b2c3d4-1111-4111-8111-123456789abc",
	} {
		allowed, _ := limiter.allow(specialRouteAbuseRequest{TenantID: tenant, Source: "source", Family: "enrollment"})
		if allowed != (n == 0) {
			t.Fatalf("request %d allowed=%t", n, allowed)
		}
	}
}
