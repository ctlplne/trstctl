// SPDX-License-Identifier: BUSL-1.1

package succession_test

import (
	"testing"

	"trstctl.com/trstctl/internal/succession"
)

func TestTenantKeyHandleSeparatesTenantIdentityAndEpoch(t *testing.T) {
	a := succession.TenantKeyHandle("tenant-a", "spiffe://shared/db", 0)
	b := succession.TenantKeyHandle("tenant-b", "spiffe://shared/db", 0)
	c := succession.TenantKeyHandle("tenant-a", "spiffe://shared/db", 1)
	d := succession.TenantKeyHandle("tenant-a", "spiffe://shared/db:0", 0)
	if a == b || a == c || a == d || b == c || b == d || c == d {
		t.Fatal("tenant, identity or epoch collided in signer key handle")
	}
	if a != succession.TenantKeyHandle("tenant-a", "spiffe://shared/db", 0) {
		t.Fatal("tenant key handle is not deterministic")
	}
}
