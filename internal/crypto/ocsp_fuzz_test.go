// SPDX-License-Identifier: BUSL-1.1

package crypto_test

// FuzzParseOCSPRequestSerial hardens the public OCSP responder's ASN.1 request
// parser. /ocsp/{tenant} accepts attacker-supplied DER and routes it through
// crypto.ParseOCSPRequestSerial; no malformed input may panic, and parse failures
// must stay classified as ErrMalformedOCSPRequest so the served HTTP path can
// return a client-fault status instead of an internal responder error.
