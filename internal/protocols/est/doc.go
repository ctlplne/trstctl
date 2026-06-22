// Package est implements the RFC 7030 EST enrollment server for device
// enrollment.
//
// Status: this is a complete, tested implementation (/cacerts + /simpleenroll +
// /simplereenroll round-trips, a fuzzed parser, and an external-reference
// differential against OpenSSL's PKCS#7 — plus the libest client on the CI
// backstop), NOT a placeholder.
//
// Served: the handler IS mounted on the served control-plane TLS listener of the
// running binary (EXC-WIRE-02) by internal/server/protocol_mounts.go at
// /.well-known/est/... (Bearer-API-token authenticated on top of TLS), with auth and
// tenant scoping, behind the shared signer-backed (AN-4), tenant-scoped (AN-1),
// event-sourced (AN-2), idempotent (AN-5), profile-gated issuance seam. It activates
// only when an issuing CA is provisioned (a signer is configured) and fails closed
// otherwise. Durable-state caveat: SCEP/CMP share a sealed RSA *transport* identity
// (deliberately not the CA key) that must live on shared persistent storage in HA;
// EST itself carries no such transport key. See docs/limitations.md "Protocols".
package est
