//go:build !agidrta

// SPDX-License-Identifier: BUSL-1.1

package intgate

import (
	"sort"
	"testing"
)

// TestProdCaller_ReachableFromBinaryMain checks the lexical precondition of
// binary reachability in the default build. The optional whole-program RTA proof
// lives behind the agidrta tag and must be run explicitly; this proxy does not
// prove whole-program reachability. Both checks use the unconditional core seams.
func TestProdCaller_ReachableFromBinaryMain(t *testing.T) {
	t.Log("Whole-program RTA reachability requires the explicit agidrta build tag; this run checks only the lexical precondition.")
	t.Log("Run the authoritative proof with: go test -tags agidrta ./internal/agentid/intgate/...")
	t.Log("This default test asserts the lexical precondition of reachability (seam-rooted non-test caller chain + always-linked seam).")

	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	// Precondition A: the attach_families seams are present and always linked (in every
	// build the strong check compiles). If they were dropped/renamed the strong check
	// would have no attach root, so proxy-fail here too.
	if err := verifySeamFilesExist(root); err != nil {
		t.Fatalf("seam file check: %v", err)
	}
	for _, s := range SanctionedSeams {
		ok, err := seamFileIsAlwaysLinked(root, s)
		if err != nil {
			t.Fatalf("parse seam %s: %v", s, err)
		}
		if !ok {
			t.Fatalf("seam %s carries a trstctl_core build constraint; the core families must link in every build, which is what the strong RTA check compiles", s)
		}
	}

	// Precondition B: every REQUIRED constructor is seam-rooted through non-test callers
	// (the lexical implication of RTA reachability from the attach_families entrypoint). This
	// is computed exactly as the seam assertion does.
	results, err := AssertSeamOnlyRoot(root)
	if err != nil {
		t.Fatalf("compute seam roots: %v", err)
	}
	var notReachableProxy []string
	for _, r := range results {
		if !r.SeamRooted {
			notReachableProxy = append(notReachableProxy, r.Constructor.Qualified()+" (expected via: "+r.Constructor.SeededVia+")")
		}
	}
	if len(notReachableProxy) > 0 {
		sort.Strings(notReachableProxy)
		t.Fatalf("REACHABILITY PROXY FAILED: %d REQUIRED constructor(s) are not on a non-test caller chain rooted at the attach_families seam, so the strong RTA check would find them unreachable — wire each through the seam:\n  - %s",
			len(notReachableProxy), joinLines(notReachableProxy))
	}
	t.Logf("reachability proxy OK: all %d REQUIRED constructors are seam-rooted; run with -tags agidrta for the RTA proof.", len(results))
}
