// SPDX-License-Identifier: BUSL-1.1

package certinfo_test

// FuzzInspect drives arbitrary bytes through the X.509 inventory parser (PEM
// unwrap → crypto/x509 → metadata extraction). Inspect runs on every certificate
// observed by discovery, CT monitoring, and the CBOM, so a hostile or truncated
// certificate must fail closed (an error), never panic. TEST-FUZZASSERT-001.
//
// This test lives inside the AN-3 crypto boundary (internal/crypto/certinfo), so
// it may use crypto/x509 directly to mint a valid seed certificate.
