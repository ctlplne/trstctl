// SPDX-License-Identifier: BUSL-1.1

//go:build pcasrta

package intgate

import (
	"sort"
	"testing"
)

// TestProdCaller_ReachableFromBinaryMain is the authoritative PCAS-INT-CALL STRONG
// check: an RTA call graph over the whole program proves each wired internal/succession
// constructor is genuinely reachable from a shipped binary entrypoint, not merely
// referenced by a non-test-but-dead helper.
func TestProdCaller_ReachableFromBinaryMain(t *testing.T) {
	unreachable, pkgCount, err := rtaReachability()
	if err != nil {
		t.Fatalf("RTA reachability analysis: %v", err)
	}
	t.Logf("RTA loaded %d packages; seeded from cmd/trstctl, cmd/trstctl-signer and cmd/trstctl-agent main.main (no -tags trstctl_core)", pkgCount)
	if len(unreachable) == 0 {
		return
	}
	offenders := make([]string, 0, len(unreachable))
	for _, c := range unreachable {
		offenders = append(offenders, c.Qualified()+" ("+c.File+")")
	}
	sort.Strings(offenders)
	t.Fatalf("PCAS-INT-CALL STRONG CHECK FAILED: %d internal/succession constructor(s) are not RTA-reachable from an in-scope binary main built without -tags trstctl_core:\n  - %s",
		len(offenders), joinLines(offenders))
}
