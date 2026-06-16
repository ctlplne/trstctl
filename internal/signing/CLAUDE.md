# internal/signing — the isolated signing service (AN-4, the sacred process)

This package is the logic of `cmd/trstctl-signer`: the **only** process that performs
private-key operations. A compromise here is, per the root `CLAUDE.md`, "the company is
over" — treat every change with the scrutiny of the signer threat model
(`docs/design/signing-service.md`). This file captures the package-local rules; the
canonical architecture rules live in the root `CLAUDE.md`.

## Hard invariants any change MUST preserve (AN-4)

- **No HTTP server, no SQL driver, no heavy dependency.** This process speaks gRPC over a
  peer-authenticated Unix domain socket (or mTLS across nodes) and nothing else. Do not
  import `net/http` as a server, any `database/sql`/`pgx` driver, or a third-party logging
  framework. The transport dependency is minimal and fully audited. (`tools/trstctllint`
  notes the signer's `net/http` constraint; keep it client-only at most.)
- **Never run in-process with the control plane.** In single-node mode the control plane
  launches this as a **child process** (`StartChild`); it is reached only over the UDS.
  Do not add a path that links the signer's signing logic into the control-plane address
  space.
- **Private keys never cross the boundary.** Keys are `crypto.LockedSigner` values held in
  locked, zeroized memory (AN-8) and only ever leave as *signatures*. No RPC returns raw
  key bytes; the keystore seals keys at rest. A key lives in RAM for the operation, not
  indefinitely.
- **Peer-authenticate the UDS.** The socket is `0600` and the peer uid is checked
  (`SO_PEERCRED` on Linux). Do not relax the socket mode or skip the peer check.
- **Never sign attacker-chosen material unbounded.** Sign only well-formed, policy-gated
  requests; the control plane is the policy/RA gate, the signer is the custody boundary.
  Two cheap signer-side bounds are enforced here and must not be weakened: **per-key
  purpose/algorithm constraints** (`constraints.go`, SIGNER-002/003 — a key minted for one
  purpose refuses a Sign for another, sealed with the key, restored across restart) and
  **dual-control intent attestation for crown-jewel keys** (`attestation.go`, RED-003 — a
  key marked `requireAuth` refuses every Sign that does not carry a valid authorization
  token over the *exact* signing tuple, including the digest, minted by an approval
  authority holding a secret the on-socket caller does not). The token is bound to the
  digest, so it cannot be replayed onto different bytes; a signer with no authorizer fails
  closed on a dual-control key. The dual-control opt-in and the per-Sign token travel as
  gRPC **metadata** (the wire proto is frozen — do not add fields), and the MAC routes
  through `internal/crypto.SignAuthorizer` (AN-3), key in mlock'd memory (AN-8).

## Crypto routing

All cryptographic operations route through `internal/crypto` (AN-3). This package does
**not** import `crypto/*` directly; it depends on `crypto.LockedSigner`/`DigestSigner`.

## The proto contract

The gRPC contract is `internal/signing/proto/signer.proto`. It is wire-frozen: `buf
breaking` gates a removed/renumbered field, a changed type, or a removed RPC/message in
CI. Additive changes are fine; regenerate with `make generate` and keep the `.pb.go` in
sync. The proto and the signer binary are CODEOWNERS-protected.

## Tests

Changes ship with the round-trip + persistence tests in this package (sign/verify across
the UDS, sealed-keystore reload across restart via `NewPersistentServer`). Do not weaken
the AN-4 surface assertions.
