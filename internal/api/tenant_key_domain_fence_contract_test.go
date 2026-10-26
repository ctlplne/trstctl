// SPDX-License-Identifier: BUSL-1.1

package api

import "testing"

// Every tenant key-domain lifecycle route runs outside the route-wide shared
// tenant-key fence: status and unseal must work on a closed tenant, and migrate,
// seal, and rotate take the tenant's exclusive fence themselves, so holding the
// shared one around them deadlocks the request on itself.
func TestTenantKeyDomainLifecycleRoutesBypassTheRouteWideTenantFence(t *testing.T) {
	want := map[string]bool{
		"getTenantKeyDomain": false, "migrateTenantKeyDomain": false, "sealTenantKeyDomain": false,
		"unsealTenantKeyDomain": false, "rotateTenantKeyDomain": false,
	}
	for _, route := range New(nil, nil, nil).routes() {
		if _, ok := want[route.opID]; !ok {
			continue
		}
		want[route.opID] = true
		if !tenantCryptoExemptOperation(route.opID) {
			t.Errorf("%s runs under the route-wide tenant fence", route.opID)
		}
	}
	for operationID, found := range want {
		if !found {
			t.Errorf("missing tenant key-domain route %s", operationID)
		}
	}
}
