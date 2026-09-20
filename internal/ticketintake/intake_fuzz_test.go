// SPDX-License-Identifier: BUSL-1.1

package ticketintake_test

// FuzzParseProviderPageAUD47 keeps both untrusted provider decoders on the
// normal Go fuzzing path. Any byte sequence may be rejected, but it must not
// panic or escape the decoder's bounded result contract.
