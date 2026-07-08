// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package intgate proves that delivered XREC mechanisms are not test-only.
//
// The default gate is lexical and cheap enough for make lint: it enumerates
// exported XREC constructors/factories under ee/reconcile and ee/federation,
// then proves each has a non-test caller and a caller chain rooted at the
// tagged EE attach seam. The strong CI gate, behind //go:build xrecrta, builds
// an RTA call graph from cmd/trstctl and cmd/trstctl-signer main.main in the
// default EE build and proves those constructors are whole-program reachable.
//
// This package asserts production reachability. It must not add XREC product
// wiring or business logic.
package intgate
