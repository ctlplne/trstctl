// SPDX-License-Identifier: MPL-2.0

// Package protocols groups the credential-issuance and enrollment protocol
// servers, each implemented in its own subpackage: acme (RFC 8555), ari
// (RFC 9773 renewal info), est (RFC 7030), scep (RFC 8894), cmp (RFC 4210/6712),
// spiffe (the SPIFFE Workload API), and ssh (the SSH CA).
//
// Every protocol parser that touches untrusted input is fuzzed and validated
// by property-based and differential tests, and all signing routes through the
// internal/crypto boundary (AN-3).
//
// Status: these are complete, tested implementations, NOT placeholders. ACME is
// additionally differential-tested against Pebble in CI; EST against OpenSSL's
// PKCS#7 (and libest on the CI backstop); CMP's PKIMessage is conformance-checked
// against OpenSSL's ASN.1 parser. None is yet mounted on the served control-plane
// listener of the running binary — serving them (with auth and tenant scoping) is
// tracked as EXC-WIRE-02. See docs/limitations.md "Protocols" for the
// served-vs-library status of each.
package protocols
