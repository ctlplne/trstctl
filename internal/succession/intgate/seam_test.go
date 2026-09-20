// SPDX-License-Identifier: BUSL-1.1

package intgate

import (
	"sort"
	"testing"
)

// TestProdCaller_SeamIsOnlySanctionedRoot proves every wired internal/succession constructor
// sits on a non-test caller chain rooted at a core attach seam, and that each seam still
// is linked in every build (no trstctl_core constraint).
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
	directCount := 0
	for _, r := range results {
		if r.DirectFromSeam {
			directCount++
		}
		if !r.SeamRooted {
			if isPending(r.Constructor.Pkg, r.Constructor.Name) {
				continue
			}
			offenders = append(offenders, r.Constructor.Qualified()+" ("+r.Constructor.File+")")
			continue
		}
		via := "transitively from an EE attach seam"
		if r.DirectFromSeam {
			via = "directly from a sanctioned EE attach seam file"
		}
		t.Logf("SEAM-ROOTED %-46s %s", r.Constructor.Qualified(), via)
	}
	if directCount == 0 {
		t.Errorf("no internal/succession constructor is called directly from a sanctioned seam file")
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("PCAS-INT-CALL SEAM FAILED: %d internal/succession constructor(s) are not on a non-test caller chain rooted at a sanctioned EE attach seam:\n  - %s",
			len(offenders), joinLines(offenders))
	}
}
