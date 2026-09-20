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
		t.Fatalf("enumerate XREC constructors: %v", err)
	}
	if len(ctors) == 0 {
		t.Fatal("XREC production-caller gate enumerated zero constructors")
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
		t.Logf("PASS %-42s %d non-test caller(s) -- first: %s:%d", c.Qualified(), len(refs), refs[0].File, refs[0].Line)
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("XREC-INT-CALL FLOOR FAILED: %d XREC constructor(s) have only test-only callers. Wire the mechanism through its owning card/package; do not add product logic in intgate:\n  - %s",
			len(offenders), joinLines(offenders))
	}
}

func TestProdCaller_SeamIsOnlySanctionedRoot(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}
	if err := verifySeamFilesExist(root); err != nil {
		t.Fatalf("seam file check: %v", err)
	}
	for _, s := range SanctionedSeams {
		ok, err := seamFileIsAlwaysLinked(root, s)
		if err != nil {
			t.Fatalf("parse seam %s: %v", s, err)
		}
		if !ok {
			t.Fatalf("sanctioned seam %s carries a trstctl_core build constraint; the core families must link in every build", s)
		}
	}
	results, err := AssertSeamOnlyRoot(root)
	if err != nil {
		t.Fatalf("compute seam roots: %v", err)
	}
	var offenders []string
	for _, r := range results {
		if !r.SeamRooted {
			offenders = append(offenders, r.Constructor.Qualified()+" ("+r.Constructor.File+")")
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("XREC-INT-CALL SEAM FAILED: %d XREC constructor(s) are not on a non-test caller chain rooted at cmd/*/ee_attach.go:\n  - %s",
			len(offenders), joinLines(offenders))
	}
}
