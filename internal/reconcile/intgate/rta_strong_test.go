//go:build xrecrta

// SPDX-License-Identifier: BUSL-1.1

package intgate

import (
	"sort"
	"testing"
)

// Whole-program reachability from a shipped binary's main is what keeps the XREC
// system claim honest (XREC-claim-16).
func TestProdCaller_ReachableFromBinaryMain(t *testing.T) {
	unreachable, pkgCount, err := rtaReachability()
	if err != nil {
		t.Fatalf("RTA reachability analysis: %v", err)
	}
	t.Logf("RTA loaded %d packages; seeded from cmd/trstctl and cmd/trstctl-signer main.main (no -tags trstctl_core)", pkgCount)
	if len(unreachable) == 0 {
		return
	}
	offenders := make([]string, 0, len(unreachable))
	for _, c := range unreachable {
		offenders = append(offenders, c.Qualified()+" ("+c.File+")")
	}
	sort.Strings(offenders)
	t.Fatalf("XREC-INT-CALL STRONG CHECK FAILED: %d XREC constructor(s) are not RTA-reachable from an in-scope binary main built without -tags trstctl_core:\n  - %s",
		len(offenders), joinLines(offenders))
}
