// SPDX-License-Identifier: BUSL-1.1

// Package intgate checks production-caller reachability for the core agent
// identity family. It asserts wiring and adds no product logic.
//
// The default floor compares the constructor inventory with the live source AST
// and requires each required constructor to have a non-test caller. Generated
// code, test files, test helpers, and test-only build tags do not satisfy it.
// Seam checks require those caller chains to start at the unconditional
// cmd/trstctl/attach_families.go or cmd/trstctl-signer/attach_families.go assembly.
// These are ordinary package tests; no commercial license gate attaches AGID.
//
// The optional strong check constructs a whole-program RTA graph from the binary
// main functions. Run it with:
//
//	go test -tags agidrta ./internal/agentid/intgate/... -count=1
//
// Without that tag, the named reachability test checks the lexical precondition.
// A non-test caller chain alone is not the whole-program RTA proof.
//
// The required tier covers shipped API, outbox, delegation, and signer paths.
// internal/agentid/verify is the external-consumer offline verifier SDK, so it is
// exempt from the requirement for an in-repository control-plane caller. Do not
// invent a meaningless product call to satisfy that check. Inventory and drift
// tests keep the distinction explicit when constructors are added or removed.
package intgate
