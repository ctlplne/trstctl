// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import "testing"

// A grant may name the customer by the slug that provisioning will use, because
// the customer id is derived from that slug before the tenant exists; a uuid is
// taken as given. Nothing else could let an operator pre-delegate a customer
// from the documentation alone.
func TestResolveCustomerRefDerivesTheProvisionedIDFromASlug(t *testing.T) {
	id, derived := ResolveCustomerRef("acme-robotics")
	if !derived || id != CustomerID("acme-robotics") {
		t.Fatalf("slug resolution = %q derived=%t, want the derived customer id", id, derived)
	}
	if again, _ := ResolveCustomerRef("  Acme-Robotics "); again != id {
		t.Fatalf("slug resolution must be case- and space-insensitive like CustomerID: %q vs %q", again, id)
	}
	raw := "a9a5abb5-ecb7-5e17-afdc-e0551ab6454b"
	got, derived := ResolveCustomerRef(raw)
	if derived || got != raw {
		t.Fatalf("uuid resolution = %q derived=%t, want the uuid unchanged", got, derived)
	}
	if got, _ := ResolveCustomerRef("A9A5ABB5-ECB7-5E17-AFDC-E0551AB6454B"); got != raw {
		t.Fatalf("uuid resolution must canonicalize case: %q", got)
	}
}
