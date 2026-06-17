# internal/protocols — issuance & enrollment protocol servers

This tree groups the credential-issuance/enrollment protocol servers, one per
subpackage: `acme` (RFC 8555) + `ari` (RFC 9773), `est` (RFC 7030), `scep` (RFC 8894),
`cmp` (RFC 4210/6712), `spiffe` (the SPIFFE Workload API), and `ssh` (the SSH CA). This
file captures the conventions every subpackage shares; the root `AGENTS.md` contract is
canonical for architecture.

## Untrusted input is the threat model here

Every one of these parses bytes off the wire from a client we do not control. So:

- **Fuzz every parser that touches untrusted input** and wire it for OSS-Fuzz / the CI
  fuzz-smoke job (root `AGENTS.md` contract). A new parser without a `FuzzXxx` target fails the
  coverage guard (`TestEveryUntrustedParserIsFuzzed`).
- **Property-based tests** for each protocol parser, and **differential tests** against an
  independent implementation where one exists: ACME vs **Pebble** (CI job), EST vs
  OpenSSL's PKCS#7 (every `make test`; libest on the CI backstop), CMP's PKIMessage vs
  OpenSSL's ASN.1 parser. Don't remove a differential to go green; ratchet up.
- **Fail closed.** A malformed/oversized/unauthenticated request is rejected, never
  best-effort accepted. Validators reject by default (no accept-everything path in the
  production build — see `acme` `dvmethod.go`).

## Crypto & custody

All signing routes through `internal/crypto` (AN-3); these packages import no `crypto/*`
directly and never hold a CA private key (it lives in the signer, AN-4).

## Served-vs-library honesty (don't over-claim)

These are **complete, tested implementations, NOT placeholders**, and they are now
**mounted on the served control-plane listener** of the running binary (EXC-WIRE-02):
`internal/server` builds each protocol server behind one issuance seam (`protocolIssuer`)
that signs through the out-of-process signer (AN-4) over `internal/crypto` (AN-3),
tenant-scopes (AN-1), event-sources the mint (AN-2), dedupes a retried enrollment (AN-5),
and runs on the protocols bulkhead (AN-7). ACME/EST/SCEP/CMP are served over HTTP on the
control-plane mux; the SPIFFE Workload API is a gRPC service on a UDS (`RunSPIFFE`); the
SSH CA is served at `/ssh/...` (issuance + the OpenSSH binary KRL). Each is gated by a
`protocols.<name>.enabled` config flag and binds a tenant via `protocols.<name>.tenant_id`
(fail-closed when no tenant is set). Served end-to-end acceptance tests
(`internal/server/protocols_served*_test.go`) drive each protocol with a real client
against the assembled `server.Build` → `Handler()` over the embedded stack + a real
signer. Keep `docs/limitations.md` "Protocols" and each subpackage's `doc.go` honest: a
`doc.go` must not call a complete protocol a placeholder, and the docs must match whether
`internal/server`/`internal/api`/`cmd` imports the protocol package
(`go test ./docs/...` enforces both directions).
