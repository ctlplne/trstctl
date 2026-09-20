// SPDX-License-Identifier: BUSL-1.1

// Package intgate is the VDEC-INT-CALL production-caller reachability gate.
//
// It asserts only: it does not add product wiring. The default tier is a lexical
// floor for make lint: every exported VDEC constructor / factory / Attach* has a
// non-test caller rooted at the EE attach seam. The strong CI tier, behind
// //go:build vdecrta, builds an RTA call graph from cmd/trstctl and
// cmd/trstctl-signer main.main compiled without -tags trstctl_core.
package intgate
