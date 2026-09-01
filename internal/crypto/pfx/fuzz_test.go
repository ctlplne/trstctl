// SPDX-License-Identifier: MPL-2.0

package pfx_test

// FuzzDecode drives arbitrary bytes through the PKCS#12 (.pfx/.p12) decoder. A
// PFX blob is an operator-supplied import file, so a hostile or truncated
// container must fail closed — never panic, and never return key or chain
// material with a nil error only to pair it with a decode failure
// (TEST-FUZZASSERT-001 reject-forgery invariant).
