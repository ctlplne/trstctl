// SPDX-License-Identifier: BUSL-1.1

package intgate

import (
	"sort"
	"testing"
)

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
			offenders = append(offenders, r.Constructor.Qualified()+" ("+r.Constructor.File+")")
			continue
		}
		via := "transitively from the attach_families seam"
		if r.DirectFromSeam {
			via = "directly from a sanctioned attach_families seam file"
		}
		t.Logf("SEAM-ROOTED %-46s %s", r.Constructor.Qualified(), via)
	}
	if directCount == 0 {
		t.Errorf("no VDEC constructor is called directly from a sanctioned seam file")
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("VDEC-INT-CALL SEAM FAILED: %d internal/decommission constructor(s) are not on a non-test caller chain rooted at cmd/*/ee_attach.go:\n  - %s",
			len(offenders), joinLines(offenders))
	}
}
