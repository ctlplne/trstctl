// SPDX-License-Identifier: LicenseRef-trstctl-EE

package intgate

import (
	"sort"
	"testing"
)

// TestProdCaller_SeamIsOnlySanctionedRoot proves every wired ee/succession constructor
// sits on a non-test caller chain rooted at an EE attach seam, and that each seam still
// carries its //go:build !trstctl_core edition fence.
func TestProdCaller_SeamIsOnlySanctionedRoot(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}
	if err := verifySeamFilesExist(root); err != nil {
		t.Fatalf("seam file check: %v", err)
	}
	for _, s := range SanctionedSeams {
		ok, err := seamFileHasCoreExclusionTag(root, s)
		if err != nil {
			t.Fatalf("parse seam %s: %v", s, err)
		}
		if !ok {
			t.Fatalf("sanctioned seam %s lost its //go:build !trstctl_core tag", s)
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
		t.Errorf("no ee/succession constructor is called directly from a sanctioned seam file")
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("PCAS-INT-CALL SEAM FAILED: %d ee/succession constructor(s) are not on a non-test caller chain rooted at a sanctioned EE attach seam:\n  - %s",
			len(offenders), joinLines(offenders))
	}
}
