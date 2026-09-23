// SPDX-License-Identifier: BUSL-1.1

// Package intgate checks production-caller reachability for the core PCAS family.
// It adds no product logic. Its default tests enumerate exported constructors in
// internal/succession and require non-test callers rooted at the unconditional
// cmd/trstctl/attach_families.go, cmd/trstctl-signer/attach_families.go, or
// cmd/trstctl-agent/cosign_attach.go seams.
//
// The default floor is a lexical AST check. It excludes test files, generated
// protobuf code, test helpers, and test-only build tags. PendingWiring records
// existing gaps and may only shrink; entries must disappear when production
// wiring is added, and a newly unwired constructor fails. The floor
// runs as an ordinary package test, not through an edition-specific Make target.
//
// The optional strong check uses a whole-program RTA call graph rooted at the
// three binary main functions. Run it with:
//
//	go test -tags pcasrta ./internal/succession/intgate/... -count=1
//
// Without that tag, the named reachability test checks the lexical precondition;
// it is not a whole-program RTA proof. scripts/pcas_prod_caller_gate.sh remains an
// optional complementary check for non-constructor mechanism entry points.
//
// Scope is internal/succession. The external-consumer verifier internal/rpverify
// has no required in-repository control-plane caller, and internal/translog is
// not enumerated by this package.
package intgate
