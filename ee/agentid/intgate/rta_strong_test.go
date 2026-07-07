//go:build agidrta

// SPDX-License-Identifier: LicenseRef-trstctl-EE

package intgate

import (
	"sort"
	"testing"
)

// TestProdCaller_ReachableFromBinaryMain (STRONG, //go:build agidrta) is the machine
// proof that every REQUIRED ee/agentid constructor is an RTA-reachable node from the
// main.main of an in-scope cmd/* binary built WITHOUT -tags trstctl_core. It is the
// authoritative form of the reachability criterion; the default build ships a
// floor-backed proxy of the same name (rta_proxy_test.go) that documents this CI gate
// and asserts the lexical precondition, because the whole-program load is too
// disk/memory-heavy to be the always-on default in the sandbox.
//
// Run in CI with: go test -tags agidrta ./ee/agentid/intgate/...
func TestProdCaller_ReachableFromBinaryMain(t *testing.T) {
	unreachable, pkgCount, err := rtaReachability()
	if err != nil {
		t.Fatalf("RTA reachability analysis: %v", err)
	}
	t.Logf("RTA loaded %d packages; seeded from cmd/trstctl, cmd/trstctl-signer, cmd/trstctl-agent main.main (no -tags trstctl_core)", pkgCount)

	if len(unreachable) > 0 {
		var names []string
		for _, c := range unreachable {
			names = append(names, c.Qualified()+" ("+c.File+")")
		}
		sort.Strings(names)
		t.Fatalf("STRONG CHECK FAILED: %d REQUIRED ee/agentid constructor(s) are NOT RTA-reachable from any in-scope binary main built without -tags trstctl_core — the lexical floor found a non-test caller, but it is not on a live call path from an entrypoint (a dead non-test helper). Wire it through the ee_attach seam:\n  - %s",
			len(unreachable), joinLines(names))
	}
	for _, c := range requiredConstructors() {
		t.Logf("REACHABLE %s", c.Qualified())
	}
}
