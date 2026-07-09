// SPDX-License-Identifier: LicenseRef-trstctl-EE

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
			offenders = append(offenders, r.Constructor.Qualified()+" ("+r.Constructor.File+")")
			continue
		}
		via := "transitively from the ee_attach seam"
		if r.DirectFromSeam {
			via = "directly from a sanctioned ee_attach seam file"
		}
		t.Logf("SEAM-ROOTED %-46s %s", r.Constructor.Qualified(), via)
	}
	if directCount == 0 {
		t.Errorf("no VDEC constructor is called directly from a sanctioned seam file")
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("VDEC-INT-CALL SEAM FAILED: %d ee/decommission constructor(s) are not on a non-test caller chain rooted at cmd/*/ee_attach.go:\n  - %s",
			len(offenders), joinLines(offenders))
	}
}
