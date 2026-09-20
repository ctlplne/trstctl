// SPDX-License-Identifier: BUSL-1.1

package intgate

import (
	"sort"
	"testing"
)

func TestProdCaller_EveryConstructorHasNonTestCaller(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}
	ctors, err := LiveConstructors(root)
	if err != nil {
		t.Fatalf("enumerate VDEC constructors: %v", err)
	}
	if len(ctors) == 0 {
		t.Fatal("VDEC production-caller gate enumerated zero constructors")
	}

	var offenders []string
	for _, c := range ctors {
		refs, err := NonTestCallers(root, c, defaultSearchRoots)
		if err != nil {
			t.Fatalf("scan callers of %s: %v", c.Qualified(), err)
		}
		if len(refs) == 0 {
			offenders = append(offenders, c.Qualified()+" ("+c.File+")")
			continue
		}
		t.Logf("PASS %-46s %d non-test caller(s) -- first: %s:%d", c.Qualified(), len(refs), refs[0].File, refs[0].Line)
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("VDEC-INT-CALL FLOOR FAILED: %d internal/decommission constructor(s) have ONLY test-only callers. Wire each mechanism on its owning VDEC card; do not add product logic in intgate:\n  - %s",
			len(offenders), joinLines(offenders))
	}
}
