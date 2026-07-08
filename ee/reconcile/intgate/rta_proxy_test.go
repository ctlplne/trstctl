//go:build !xrecrta

// SPDX-License-Identifier: LicenseRef-trstctl-EE

package intgate

import "testing"

func TestProdCaller_ReachableFromBinaryMain(t *testing.T) {
	t.Log("authoritative RTA proof runs with: go test -tags xrecrta ./ee/reconcile/intgate/...")
	t.Log("default build asserts the lexical reachability precondition: every XREC constructor is rooted at the EE attach seam")
	TestProdCaller_SeamIsOnlySanctionedRoot(t)
}
