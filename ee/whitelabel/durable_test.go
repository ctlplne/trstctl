// SPDX-License-Identifier: LicenseRef-trstctl-EE

package whitelabel

import (
	"os"
	"strings"
	"testing"
)

// L3/AUD-14: a configured brand must survive a deploy, and the fallback must be
// VISIBLE.
//
// In-memory lost it silently: a provider configured their brand, saw it
// resolve, and their customers went back to our product name on the next
// restart with nothing in the running system saying why. For a white-label
// feature that is the whole value evaporating quietly.
func TestTheDurableBrandStoreIsReachableAndTheFallbackIsVisible(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("../../cmd/trstctl/ee_attach.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "eewhitelabel.InstallDurable(") {
		t.Fatal("ee_attach.go does not call InstallDurable.\n\n" +
			"A durable brand store nothing installs leaves every provider's branding evaporating " +
			"on the next deploy, with the fix sitting unused in the tree.")
	}
	if strings.Contains(string(src), "eewhitelabel.InstallInMemory()") {
		t.Fatal("ee_attach.go still installs the in-memory brand store")
	}
	if InstallDurable(nil).Durable {
		t.Fatal("an installation with no database claimed its branding would survive a deploy")
	}
}

// A brand nobody configured is the DEFAULT, not an error. Returning an error
// would blank a login page over a tenant that simply never set one.
func TestAnUnbackedBrandLookupIsNotAnError(t *testing.T) {
	t.Parallel()
	got, err := (&PGStore{}).TenantBrand(t.Context(), "t1")
	if err != nil {
		t.Fatalf("an unbacked lookup errored instead of falling back to the default: %v", err)
	}
	if got != nil {
		t.Fatalf("an unbacked lookup invented a brand: %+v", got)
	}
	byDomain, err := (&PGStore{}).TenantByDomain(t.Context(), "acme.example")
	if err != nil || byDomain != nil {
		t.Fatalf("an unbacked domain lookup returned %+v / %v", byDomain, err)
	}
}
