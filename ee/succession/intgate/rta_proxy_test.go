// SPDX-License-Identifier: LicenseRef-trstctl-EE

//go:build !pcasrta

package intgate

import "testing"

// TestProdCaller_ReachableFromBinaryMain is the default-build proxy: the authoritative
// whole-program RTA proof is CI-only, so here it asserts the lexical precondition the
// RTA tier upgrades -- every wired ee/succession constructor is rooted at an EE attach
// seam.
func TestProdCaller_ReachableFromBinaryMain(t *testing.T) {
	t.Log("authoritative RTA proof runs with: go test -tags pcasrta ./ee/succession/intgate/...")
	t.Log("default build asserts the lexical reachability precondition: every ee/succession constructor is rooted at an EE attach seam")
	TestProdCaller_SeamIsOnlySanctionedRoot(t)
}
