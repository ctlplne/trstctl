// SPDX-License-Identifier: BUSL-1.1

//go:build !pcasrta

package intgate

import "testing"

// TestProdCaller_ReachableFromBinaryMain is the default-build proxy: the authoritative
// whole-program RTA proof is CI-only, so here it asserts the lexical precondition the
// RTA tier upgrades -- every wired internal/succession constructor is rooted at an EE attach
// seam.
func TestProdCaller_ReachableFromBinaryMain(t *testing.T) {
	t.Log("authoritative RTA proof runs with: go test -tags pcasrta ./internal/succession/intgate/...")
	t.Log("default build asserts the lexical reachability precondition: every internal/succession constructor is rooted at an EE attach seam")
	TestProdCaller_SeamIsOnlySanctionedRoot(t)
}
