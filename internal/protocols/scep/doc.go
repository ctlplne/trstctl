// Package scep implements the RFC 8894 SCEP enrollment server, compatible with
// MDM-style clients.
//
// Status: this is a complete, tested implementation (a real PKIOperation enroll
// round-trip plus a fuzzed parser), NOT a placeholder.
//
// Served: the handler IS mounted on the served control-plane TLS listener of the
// running binary (EXC-WIRE-02) by internal/server/protocol_mounts.go at /scep, with
// auth and tenant scoping, behind the shared signer-backed (AN-4), tenant-scoped
// (AN-1), event-sourced (AN-2), idempotent (AN-5), profile-gated issuance seam. It
// activates only when an issuing CA is provisioned (a signer is configured) and fails
// closed otherwise. Durable-state caveat: SCEP uses a sealed RSA *transport* identity
// at protocols.ra_key_file for CMS (deliberately not the CA key, which stays in the
// signer — AN-4); keep that file on shared persistent storage in HA so cached clients
// survive restarts and rolling deploys. See docs/limitations.md "Protocols".
package scep
