// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package intgate is the AGID-INT-CALL production-caller reachability gate: the
// analyzer that PROVES every ee/agentid mechanism has a real production caller and
// LOCKS that property so a regression to test-only fails the build. It asserts; it
// adds no product logic (a claimed mechanism with no production caller is a wiring
// gap on that mechanism's own card, AGID-01…11, not something this package fixes).
//
// WHY. The PCAS audit (2026-07-06) found every PCAS mechanism was reachable only from
// _test.go -- built and unit-tested, but never wired into a running binary
// (INT-INV-1: "delivered != tested"). scripts/pcas_prod_caller_gate.sh made that
// machine-checkable for PCAS. AGID-INT-CALL is the same forcing function for the
// Agent Identity Lifecycle Enforcement family: the patent independents (1, 16, 24,
// 28, 31, 32, 33) read on mechanisms, and "claims read on shipped product" requires
// those mechanisms be reachable from a running binary. This gate proves exactly that.
//
// THREE CHECKS, mirroring the PCAS two-tier gate.
//
//  1. FLOOR (runs in `make lint` via `make agid-caller-gate`, and as the default
//     `go test` here). For every exported constructor / factory / Attach* in the
//     in-scope ee/agentid packages, at least one NON-TEST caller must exist. A caller
//     is "non-test" iff it is a .go reference outside the constructor's own defining
//     file that does NOT live in a *_test.go file, under a /mock, /fake, or /testkit
//     directory, under testdata/, or behind a test-only build tag. If every caller of
//     a REQUIRED constructor is test-only, the floor FAILS and names the constructor.
//     This is a lexical (AST + grep-equivalent) check: it needs no whole-program load
//     and therefore always runs, even on a disk-constrained sandbox.
//
//  2. STRONG (CI, behind `//go:build agidrta`). An RTA call graph
//     (golang.org/x/tools/go/callgraph/rta) seeded from the main.main of cmd/trstctl,
//     cmd/trstctl-signer, and cmd/trstctl-agent, each built WITHOUT `-tags
//     trstctl_core` (so the ee_attach seam is linked). Every in-scope constructor must
//     be a REACHABLE node; any that is not is listed and FAILS. This is the machine
//     proof that the lexical floor's "non-test caller" is actually on a live call path
//     from a binary entrypoint, not a non-test-but-still-dead helper. It loads the
//     whole program (911+ packages) and is heavy, so it is CI-gated; the floor is the
//     runnable default and TestProdCaller_ReachableFromBinaryMain degrades to a
//     floor-backed proxy when the agidrta tag is absent (documented on the test).
//
//  3. SEAM. The only sanctioned production root is the ee_attach seam
//     (cmd/trstctl/ee_attach.go, cmd/trstctl-signer/ee_attach.go, both //go:build
//     !trstctl_core). A constructor made reachable ONLY through a test helper (an
//     export_test.go, a *_test.go, a testkit) does not count: TestProdCaller_
//     SeamIsOnlySanctionedRoot asserts every REQUIRED constructor's non-test caller
//     chain roots at the ee_attach seam (the control-plane attach for the API +
//     orchestrator worker, or the signer attach for the in-signer gate), and that a
//     purely test-helper caller is rejected.
//
// TWO TIERS (the PCAS REQUIRED/DEFERRED split).
//
//   - REQUIRED: on the shipped AGID critical path. cmd/trstctl attaches the AGID
//     external API (ee/agentid/api) and the licensed-outbox worker
//     (ee/agentid/orchestrator) under the FeatureAgentDelegation block; the worker
//     DRIVES reach.NewEngine, broker.IssueChainBound, revoke.NewCascade ->
//     NewExecutor -> NewTerminalTransition, and constructs the ceiling policy, tool
//     sets, directive reader, and precondition. cmd/trstctl-signer attaches the
//     in-signer delegation gate (delegation.NewSignerGate). Each REQUIRED constructor
//     MUST have a non-test caller; a regression fails the gate.
//
//   - DEFERRED (allow-listed): ee/agentid/verify (and its ./wasm build) is the
//     proprietary OFFLINE relying-party verifier SDK (patent AGID-claim-28). It is consumed
//     OUTSIDE this repository -- by a relying party's own service or a browser WASM
//     bundle -- so it legitimately has no in-repo control-plane caller, exactly as the
//     PCAS gate's DEFERRED tier exempts the offline PCAS-07 relying-party verifier.
//     Inventing a cmd/trstctl "caller" for an offline third-party verifier would be a
//     contrived, meaningless invocation, so none is invented and the gate exempts the
//     package (rationale in ee/agentid/verify/doc.go). Every OTHER previously
//     test-only AGID mechanism DOES gain a non-test control-plane caller; only /verify
//     is deferred, and only because its consumer is external by construction.
//
// The inventory of in-scope constructors and their tier is the single source of truth
// (inventory.go); the floor cross-checks the live AST against it so ADDING a new
// exported ee/agentid constructor without either wiring it or classifying it fails the
// drift guard (TestConstructorInventory_MatchesSource). This keeps the gate honest as
// the family grows.
package intgate
