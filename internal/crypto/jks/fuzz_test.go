// SPDX-License-Identifier: BUSL-1.1

package jks_test

// FuzzDecode drives arbitrary bytes through the Java KeyStore decoder. A JKS
// blob is an operator-supplied file (migration import), so a hostile or
// truncated keystore must fail closed — never panic, and never hand back key
// or certificate material alongside a nil error (TEST-FUZZASSERT-001
// reject-forgery invariant: a decode that "fails" must not leak partial
// material).

// FuzzDecodeTrustedCertificates fuzzes the trust-store decode path (no private
// keys) with the same fail-closed contract.
