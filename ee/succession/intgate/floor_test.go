// SPDX-License-Identifier: LicenseRef-trstctl-EE

package intgate

import (
	"sort"
	"testing"
)

// TestProdCaller_EveryConstructorHasNonTestCaller is the PCAS-INT-CALL FLOOR. The
// constructor set is enumerated from the live AST, so a newly added exported
// ee/succession constructor is governed the moment it lands: it must either have a
// production caller or be recorded as an open gap in PendingWiring.
func TestProdCaller_EveryConstructorHasNonTestCaller(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}
	ctors, err := LiveConstructors(root)
	if err != nil {
		t.Fatalf("enumerate PCAS constructors: %v", err)
	}
	if len(ctors) == 0 {
		t.Fatal("PCAS production-caller gate enumerated zero constructors")
	}
	t.Logf("enumerated %d exported constructor(s) under %s (no hand-written mechanism list)", len(ctors), familyTree)

	var offenders []string
	for _, c := range ctors {
		refs, err := NonTestCallers(root, c, defaultSearchRoots)
		if err != nil {
			t.Fatalf("scan callers of %s: %v", c.Qualified(), err)
		}
		if len(refs) == 0 {
			if isPending(c.Pkg, c.Name) {
				t.Logf("PENDING %-46s recorded open wiring gap", c.Qualified())
				continue
			}
			offenders = append(offenders, c.Qualified()+" ("+c.File+")")
			continue
		}
		t.Logf("PASS %-46s %d non-test caller(s) -- first: %s:%d", c.Qualified(), len(refs), refs[0].File, refs[0].Line)
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("PCAS-INT-CALL FLOOR FAILED: %d ee/succession constructor(s) have ONLY test-only callers and are not recorded in PendingWiring. Wire the mechanism on its owning PCAS card, or record the gap; do not add product logic in intgate:\n  - %s",
			len(offenders), joinLines(offenders))
	}
}
