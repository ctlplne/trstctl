// SPDX-License-Identifier: BUSL-1.1

package intgate

import (
	"sort"
	"testing"
)

// TestProdCaller_EveryConstructorHasNonTestCaller is the FLOOR check: every REQUIRED
// internal/agentid* exported constructor must have at least one NON-TEST caller. The DEFERRED
// allow-list (internal/agentid/verify -- the external RP SDK) is excepted, mirroring the PCAS
// gate's DEFERRED tier. This test MUST pass on the current tree (the AGID-INT-CALL
// wiring landed: the cmd/trstctl attach -> internal/agentid/api -> internal/agentid/orchestrator
// worker path, plus the cmd/trstctl-signer in-signer gate attach, give every mechanism
// a production caller).
//
// If a REQUIRED constructor has ONLY test-only callers, this fails and NAMES it -- and
// per the card, the fix is to wire it on its own mechanism card (AGID-01…11), NOT to
// add product code here.
func TestProdCaller_EveryConstructorHasNonTestCaller(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	var offenders []string
	for _, c := range Inventory {
		if c.Tier == TierDeferred {
			// DEFERRED (external-consumer-only). Its invariant is "no CONTROL-PLANE caller":
			// it may be used within its own SDK package (e.g. verify/sample.go conformance
			// helper, or agentstack's own package), but nothing OUTSIDE the package on the
			// cmd/internal attach path may call it -- else it is really wired and must be
			// PROMOTED to REQUIRED (the PCAS DEFERRED discipline: an accidental wiring is a
			// forcing function, not a silent pass).
			cp, err := ControlPlaneCallers(root, c.Name, c.File, defaultSearchRoots)
			if err != nil {
				t.Fatalf("scan control-plane callers of %s: %v", c.Qualified(), err)
			}
			if len(cp) != 0 {
				t.Errorf("DEFERRED %s now has %d CONTROL-PLANE caller(s) %v: it is external-consumer-only (%s) and must have no cross-package control-plane caller; if it is genuinely wired, PROMOTE it to TierRequired in inventory.go and document the control-plane path (PCAS DEFERRED discipline)",
					c.Qualified(), len(cp), cp, c.SeededVia)
			} else {
				t.Logf("DEFERRED %-46s external-consumer-only OK (0 control-plane callers) — %s", c.Qualified(), c.SeededVia)
			}
			continue
		}

		refs, err := NonTestCallers(root, c.Name, c.File, defaultSearchRoots)
		if err != nil {
			t.Fatalf("scan callers of %s: %v", c.Qualified(), err)
		}
		if len(refs) == 0 {
			offenders = append(offenders, c.Qualified()+" ("+c.File+")")
			continue
		}
		t.Logf("PASS %-46s %d non-test caller(s) — first: %s:%d", c.Qualified(), len(refs), refs[0].File, refs[0].Line)
	}

	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("AGID-INT-CALL FLOOR FAILED: %d REQUIRED internal/agentid constructor(s) have ONLY test-only callers (a mechanism built and unit-tested but never wired into a running binary). Wire each on its own mechanism card (AGID-01…11), do NOT add product code in intgate:\n  - %s",
			len(offenders), joinLines(offenders))
	}
}

// TestConstructorInventory_MatchesSource is the DRIFT GUARD: the static Inventory must
// exactly match the live AST enumeration of exported constructors across the in-scope
// packages. Adding a NEW exported internal/agentid constructor without classifying it here
// (REQUIRED vs DEFERRED) fails this test, so the floor can never silently miss a new
// mechanism; deleting/renaming one without updating Inventory also fails. This keeps the
// gate honest as the AGID family grows.
func TestConstructorInventory_MatchesSource(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	// Build the set the Inventory claims, keyed by "pkg\x00Name".
	inInventory := map[string]bool{}
	for _, c := range Inventory {
		inInventory[ctorKey(c.Pkg, c.Name)] = true
	}

	// Enumerate the live AST per in-scope package.
	inSource := map[string]bool{}
	for _, pkg := range InScopePackages {
		names, err := ExportedConstructors(root, pkg)
		if err != nil {
			t.Fatalf("enumerate constructors in %s: %v", pkg, err)
		}
		for _, n := range names {
			inSource[ctorKey(pkg, n)] = true
		}
	}

	var missingFromInventory, staleInInventory []string
	for k := range inSource {
		if !inInventory[k] {
			missingFromInventory = append(missingFromInventory, humanKey(k))
		}
	}
	for k := range inInventory {
		if !inSource[k] {
			staleInInventory = append(staleInInventory, humanKey(k))
		}
	}
	sort.Strings(missingFromInventory)
	sort.Strings(staleInInventory)

	if len(missingFromInventory) > 0 {
		t.Errorf("inventory DRIFT: %d exported constructor(s) exist in source but are NOT classified in intgate/inventory.go (add each as TierRequired if it must be production-wired, or TierDeferred if it is external-consumer-only):\n  - %s",
			len(missingFromInventory), joinLines(missingFromInventory))
	}
	if len(staleInInventory) > 0 {
		t.Errorf("inventory DRIFT: %d entry(ies) in intgate/inventory.go no longer exist in source (renamed/removed) — update inventory.go:\n  - %s",
			len(staleInInventory), joinLines(staleInInventory))
	}
}

// TestDeferredAllowList_IsMinimal pins the DEFERRED allow-list to its exact, justified
// set so broadening it (deferring something to dodge the gate) is a conscious, reviewed
// diff. Two entries, both external-consumer-only:
//   - PACKAGE internal/agentid/verify: the offline relying-party verifier SDK (AGID-claim-28),
//     consumed outside this repo (the card's sanctioned DEFERRED tier).
//   - SYMBOL internal/agentid/agentstack.New: the issuer-side representation builder that
//     ingests the raw secret prompt; a control-plane caller would violate AN-8 (and AN-4
//     keeps the signer from linking agentstack). Same external-consumer class as verify.
func TestDeferredAllowList_IsMinimal(t *testing.T) {
	wantPkgs := map[string]bool{"internal/agentid/verify": true}
	gotPkgs := map[string]bool{}
	for _, d := range DeferredPackages {
		gotPkgs[d] = true
	}
	for d := range gotPkgs {
		if !wantPkgs[d] {
			t.Errorf("DEFERRED package allow-list has an unexpected entry %q: only internal/agentid/verify (the external RP SDK, AGID-claim-28) is a wholly external-consumer package; do not defer other packages to bypass the gate", d)
		}
	}
	for d := range wantPkgs {
		if !gotPkgs[d] {
			t.Errorf("DEFERRED package allow-list is missing %q (the external RP SDK)", d)
		}
	}

	wantSyms := map[string]bool{"internal/agentid/agentstack\x00New": true}
	for k := range DeferredSymbols {
		if !wantSyms[k] {
			t.Errorf("DEFERRED symbol allow-list has an unexpected entry %q: symbol-level deferral is reserved for issuer-side/external-consumer builders (agentstack.New) justified by the AN-8/AN-4 boundary; do not defer mechanism constructors to bypass the gate", humanKey(k))
		}
	}
	for k := range wantSyms {
		if !DeferredSymbols[k] {
			t.Errorf("DEFERRED symbol allow-list is missing %q (the issuer-side agent-stack representation builder)", humanKey(k))
		}
	}
}

func humanKey(k string) string {
	for i := 0; i < len(k); i++ {
		if k[i] == '\x00' {
			return k[:i] + "." + k[i+1:]
		}
	}
	return k
}

func joinLines(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += "\n  - "
		}
		out += s
	}
	return out
}
