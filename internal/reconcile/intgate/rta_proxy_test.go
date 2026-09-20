//go:build !xrecrta

// SPDX-License-Identifier: BUSL-1.1

package intgate

import "testing"

func TestProdCaller_ReachableFromBinaryMain(t *testing.T) {
	t.Log("authoritative RTA proof runs with: go test -tags xrecrta ./internal/reconcile/intgate/...")
	t.Log("default build asserts the lexical reachability precondition: every XREC constructor is rooted at the EE attach seam")
	TestProdCaller_SeamIsOnlySanctionedRoot(t)
}
