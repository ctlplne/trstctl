// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package intgate is the PCAS-INT-CALL production-caller reachability gate for the
// ee/succession family. It ASSERTS reachability and adds no product logic.
//
// WHY. The PCAS audit (2026-07-06) found every PCAS mechanism was reachable only from
// _test.go -- built and unit-tested, but never wired into a running binary (INT-INV-1:
// "delivered != tested"). The first remedy, scripts/pcas_prod_caller_gate.sh, pins a
// HAND-WRITTEN list of mechanism patterns: it proves what is on the list and is blind
// to everything that is not, so an ee/succession mechanism added later is invisible to
// it. This package removes that blind spot the way the three sibling families already
// do (ee/agentid/intgate, ee/reconcile/intgate, ee/decommission/intgate): it ENUMERATES
// the live AST, so a newly added exported constructor is in scope the moment it is
// written. The shell gate stays as the complement -- it covers the mechanism entry
// points that are not constructors (Mint, Import, IssueLeafCertificate, ...), which a
// constructor enumeration cannot see.
//
// THREE TIERS, mirroring the siblings.
//
//  1. FLOOR (runs in `make lint` via `make pcas-caller-gate`, and as the default
//     `go test` here). Every exported constructor / factory / Attach* under
//     ee/succession must have at least one NON-TEST caller. A caller is "non-test" iff
//     it is a .go reference outside the constructor's own defining function that is not
//     in a *_test.go file, not under mock/fake/testkit/testdata, not in generated
//     *.pb.go, and not behind a test-only build tag. This tier is lexical (AST only),
//     so it needs no whole-program load and always runs.
//
//  2. SEAM. The only sanctioned production roots are the EE attach seams
//     (cmd/trstctl/ee_attach.go, cmd/trstctl-signer/ee_attach.go and
//     cmd/trstctl-agent/cosign_attach.go, all three //go:build !trstctl_core). A
//     constructor made reachable ONLY through a test helper does not satisfy the gate.
//
//  3. STRONG (CI, behind //go:build pcasrta). An RTA call graph
//     (golang.org/x/tools/go/callgraph/rta) seeded from the main.main of cmd/trstctl,
//     cmd/trstctl-signer and cmd/trstctl-agent, each built WITHOUT -tags trstctl_core so
//     the seams are linked. Every in-scope constructor must be a reachable node. It
//     loads the whole program and is heavy, so it is CI-gated; the floor is the
//     runnable default and TestProdCaller_ReachableFromBinaryMain degrades to a
//     seam-backed proxy when the pcasrta tag is absent.
//
// PendingWiring (pending.go) is a RATCHET, not an allow-list to grow. It names the
// exported ee/succession constructors that are test-only TODAY, each with the observed
// gap. It only ever shrinks: TestPendingWiring_NoStaleEntry FAILS the moment a listed
// constructor gains a production caller, forcing the entry's removal, and any
// constructor NOT listed must already be wired. A newly added unwired constructor
// therefore fails the floor immediately -- the property the hand-written pattern list
// could never have.
//
// SCOPE. This gate governs the ee/succession tree. ee/rpverify is the offline
// relying-party verifier, an external-consumer SDK with no in-repo control-plane caller
// by construction (the same tier ee/agentid/intgate defers ee/agentid/verify into), and
// ee/translog is not enumerated here yet; extending the enumeration to ee/translog is
// tracked separately.
package intgate
