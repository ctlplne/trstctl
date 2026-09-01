// SPDX-License-Identifier: MPL-2.0

package crypto_test

// FuzzParseSCEPRequest hardens the SCEP pkiMessage parser (an untrusted-input parser per
// TEST-FUZZASSERT-001): no input — random bytes, truncated DER, a valid SignedData with a hostile
// envelope — may crash it; it must always return cleanly (a request or an error), never
// both, and never panic.
