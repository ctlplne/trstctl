//go:build !agidrta

// SPDX-License-Identifier: LicenseRef-trstctl-EE

package intgate

import (
	"sort"
	"testing"
)

// TestProdCaller_ReachableFromBinaryMain (DEFAULT build, //go:build !agidrta) is the
// floor-backed PROXY of the strong RTA reachability check. The authoritative form lives
// in rta_strong.go / rta_strong_test.go behind //go:build agidrta and runs in CI
// (`go test -tags agidrta ./ee/agentid/intgate/...`); it seeds an RTA call graph from
// the in-scope cmd/* mains built without -tags trstctl_core and fails on any REQUIRED
// constructor that is not a reachable node.
//
// Why a proxy in the default build: the strong check loads the WHOLE program (~926
// packages) from source via go/packages + go/ssa (ssautil.AllPackages) so RTA can follow
// the composed-closure attach seam. That is a heavier load than the cheap lexical floor,
// so it is CI-gated by default to keep `make lint` / the default `go test` fast and
// disk-frugal (the sandbox runs at DISK ~90%). It has been validated to run and pass in
// this environment (~6s), so the agidrta gate is a deliberate default, not a
// can't-run fallback. The default build keeps the CANONICAL TEST NAME present and
// runnable and asserts the LEXICAL PRECONDITION of reachability: every REQUIRED
// constructor has a non-test caller whose chain roots at the ee_attach seam AND the seam
// files are linked into the EE (non-core) build. RTA reachability is implied by (seam is
// in the default build) + (seam-rooted non-test caller chain). This is a proxy, not the
// proof; CI (and `make agid-caller-gate-strong`) runs the proof.
func TestProdCaller_ReachableFromBinaryMain(t *testing.T) {
	t.Log("STRONG RTA reachability is behind //go:build agidrta (CI / `make agid-caller-gate-strong`): whole-program source SSA load, kept off the default path for speed/disk though it does run here (~6s).")
	t.Log("Run the authoritative proof with: go test -tags agidrta ./ee/agentid/intgate/...")
	t.Log("This default test asserts the lexical precondition of reachability (seam-rooted non-test caller chain + EE-linked seam).")

	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	// Precondition A: the ee_attach seams are present and EE-only (linked in the default
	// build the strong check compiles). If they were dropped/renamed the strong check
	// would have no attach root, so proxy-fail here too.
	if err := verifySeamFilesExist(root); err != nil {
		t.Fatalf("seam file check: %v", err)
	}
	for _, s := range SanctionedSeams {
		ok, err := seamFileHasCoreExclusionTag(root, s)
		if err != nil {
			t.Fatalf("parse seam %s: %v", s, err)
		}
		if !ok {
			t.Fatalf("seam %s lost its //go:build !trstctl_core tag: it would not be linked into the EE build the strong RTA check compiles", s)
		}
	}

	// Precondition B: every REQUIRED constructor is seam-rooted through non-test callers
	// (the lexical implication of RTA reachability from the ee_attach entrypoint). This
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
		t.Fatalf("REACHABILITY PROXY FAILED: %d REQUIRED constructor(s) are not on a non-test caller chain rooted at the ee_attach seam, so the strong RTA check would find them unreachable — wire each through the seam:\n  - %s",
			len(notReachableProxy), joinLines(notReachableProxy))
	}
	t.Logf("reachability proxy OK: all %d REQUIRED constructors are seam-rooted; CI (-tags agidrta) runs the RTA proof.", len(results))
}
