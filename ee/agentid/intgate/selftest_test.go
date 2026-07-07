// SPDX-License-Identifier: LicenseRef-trstctl-EE

package intgate

import "testing"

// TestGate_IsNotVacuous is the gate-of-the-gate (mirroring the PCAS
// check-actions-pinned_selftest.sh discipline): it proves the floor primitives actually
// discriminate, so a green gate is meaningful and not a rubber stamp. It asserts:
//
//   - a fabricated constructor name that no source calls yields ZERO callers (the
//     primitive does not spuriously match), AND
//   - the DEFERRED verify.NewLocalPolicy has ZERO control-plane (cross-package) callers
//     (its deferred assertion rests on a real fact), AND
//   - a genuinely wired constructor (reach/engine.NewEngine) yields >=1 caller (the
//     primitive is not just always returning empty).
//
// If the caller-scan ever regressed to "always empty" (which would make the whole gate
// pass vacuously), the third assertion fails; if it regressed to "always matches", the
// first fails.
func TestGate_IsNotVacuous(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	// (1) A fabricated name appears in no source file: zero callers.
	if refs, err := NonTestCallers(root, "NewNonexistentFabricatedCtorXYZ", "ee/agentid/reach/ceiling.go", defaultSearchRoots); err != nil {
		t.Fatalf("scan fabricated name: %v", err)
	} else if len(refs) != 0 {
		t.Fatalf("expected 0 callers for a fabricated constructor name, got %d: %v (the caller scan spuriously matches — the gate could pass vacuously)", len(refs), refs)
	}

	// (2) The DEFERRED RP SDK has no cross-package control-plane caller.
	if cp, err := ControlPlaneCallers(root, "NewLocalPolicy", "ee/agentid/verify/helpers.go", defaultSearchRoots); err != nil {
		t.Fatalf("scan verify control-plane callers: %v", err)
	} else if len(cp) != 0 {
		t.Fatalf("verify.NewLocalPolicy unexpectedly has %d control-plane caller(s): %v", len(cp), cp)
	}

	// (3) A genuinely wired constructor yields callers.
	if wired, err := NonTestCallers(root, "NewEngine", "ee/agentid/reach/engine/engine.go", defaultSearchRoots); err != nil {
		t.Fatalf("scan NewEngine callers: %v", err)
	} else if len(wired) == 0 {
		t.Fatal("reach/engine.NewEngine reported 0 callers — the caller scan is broken (it must find the orchestrator issuance-worker caller); the gate would pass vacuously")
	} else {
		t.Logf("gate-of-the-gate OK: fabricated=0 callers, verify control-plane=0, NewEngine callers=%d", len(wired))
	}
}
