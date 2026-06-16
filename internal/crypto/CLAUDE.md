# internal/crypto — the AN-3 cryptography boundary (the only crypto/* importer)

This is the single package in the tree permitted to import the standard library's
`crypto/*`. Everything cryptographic — X.509 and SSH signing, JOSE/JWS verification,
envelope sealing, PQC, the TSA's CMS encoding — routes through the backend-agnostic types
and interfaces defined here (`Algorithm`, `Hash`, `PublicKey`, `Signer`, `KeyGenerator`,
`DigestSigner`, `LockedSigner`). Callers depend only on these; adding an algorithm or a
hardware backend is a single-package change. This file captures the package-local rules;
the root `CLAUDE.md` is canonical.

## The boundary is enforced — keep it intact (AN-3)

- **Nothing outside this package imports `crypto/*`.** `tools/trstctllint` fails CI on any
  stdlib `crypto/*` import elsewhere. The rule covers only stdlib today, so **also keep
  third-party crypto (`golang.org/x/crypto`, `cloudflare/circl`) inside this boundary** —
  do not introduce them in other packages (CRYPTO-002).
- **Add, don't fork.** A new algorithm/scheme is a new backend or registration *here*
  (a CIRCL scheme + known-answer tests for PQC; a backend implementing `Signer`), not a
  parallel crypto path. SSH and X.509 both sign through this boundary — the SSH CA is
  another implementation behind it, not a separate stack.

## Memory safety for key material (AN-8)

- **Secrets live in `[]byte`, never `string`.** Several packages here are tagged
  key-handling, so `trstctllint` rejects `string`-typed key/secret parameters and fields.
- **Locked, zeroized buffers.** Private material is held in `secret.Buffer`/`LockedSigner`
  values that are `mlock`'d, `MADV_DONTDUMP`, and explicitly zeroized; a key lives in RAM
  for the operation, not indefinitely. Don't copy key bytes into a `string`, a log, an
  error, or a long-lived buffer. `runtime.KeepAlive` guards the lifetime where needed.

## Untrusted parsers are fuzzed

Parsers here that touch untrusted input (X.509, JOSE, CMS/PKCS#7, SSH wire) are fuzzed and
covered by `TestEveryUntrustedParserIsFuzzed`; a new one needs a `FuzzXxx` target and a
committed seed corpus. The JOSE/JWS verifier is a verified strength — tamper tests must be
deterministic (`-race -count`-stable), never substituting a byte that may already match.

## Don't move crypto out, and ask before HSM/stack changes

Do not relocate crypto outside this package, and treat a new backend that changes the
custody model (e.g. wiring a live HSM/KMS into the control-plane address space) as an
architecture decision — see the root `CLAUDE.md` §8 and the EXC-CRYPTO epics.
