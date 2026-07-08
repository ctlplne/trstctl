<!-- SPDX-License-Identifier: LicenseRef-trstctl-EE -->

# AGENTS.md - ee/reconcile/digest

This package owns XREC R-11 through R-14: no-secret Merkle leaves, the sorted
Merkle tree with inclusion/absence proofs, policy-posture summaries, canonical
state-digest bodies, and the signer-side artifact signer.

- Keep all XREC-specific logic in `ee/reconcile/digest`; core may see only the
  generic `internal/signing` artifact-signing seam.
- Do not import `crypto/*`; use `internal/crypto` for hashing, signing, and
  verification.
- Do not import SQL, NATS, HTTP servers, or control-plane stores. This package is
  linked into `cmd/trstctl-signer`, so it must stay AN-4-small.
- Digest bodies, posture summaries, proofs, and signed artifacts must contain
  identifiers, hashes, counts, and timestamps only. Never serialize private keys,
  token values, API keys, passwords, or secret values.
- The verifier must trust a signer key by key ID and public key. Do not accept
  an arbitrary embedded public key as sufficient authority.
