<!-- SPDX-License-Identifier: LicenseRef-trstctl-EE -->

# PCAS key custody — claims 16 & 26 (INT-07)

This note maps the patent's key-custody claims to the code, and states what the
delivered path guarantees versus what a hardware deployment adds.

## Where succession keys live

Since INT-03, a succession successor key is generated **inside the isolated signer**
through the signer's own key factory (`internal/signing.Server.GenerateSuccessorKey`
→ `KeyFactory.GenerateSigningKeyFromProto`), stored in the signer keystore under a
deterministic per-epoch handle, and used only via the in-signer `DigestSigner`. The
predecessor is resolved the same way. The control plane never receives private key
material; it requests a mint over the transport and receives only public material and
the opaque record (claims 1/12/49).

## Claim 16 — locked, non-dumpable, zeroized buffers (DELIVERED)

The default key factory returns `crypto.GenerateLockedKey`, a `*crypto.LockedSigner`
whose private scalars live in an **mlock'd, `MADV_DONTDUMP`, explicitly zeroized-on-
`Destroy`** buffer (AN-8; see `internal/crypto/locked.go`). The signer process
additionally hardens itself with `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0`
(`internal/signing/harden_linux.go`). So every succession key sits in locked memory
that is excluded from core dumps and wiped on destruction — exactly claim 16.

Pinned by `internal/signing.TestINT07_SuccessorKeyIsLockedAndZeroizable`: a
`GenerateSuccessorKey` result is held as a `*crypto.LockedSigner`, signs, and is
removed + zeroized via `DestroyKey`. The mlock/zeroize primitives themselves are
covered by `internal/crypto`'s `LockedSigner` tests.

## Non-release (DELIVERED)

The signer's wire contract (`internal/signing/proto/signer.proto`) exposes
`GenerateKey`, `GetPublicKey`, `Sign`, `DestroyKey`, `Health`, `MintSuccessor` — and
**no operation that returns a key's private bytes**. Private material leaves the
signer only sealed-at-rest under a KEK (the persistent-keystore `SealedBytes` path),
never in the clear. Pinned by `TestINT07_NoSuccessorKeyExportOverTransport`
(reflects the client interface; fails on any export-suggesting method) and by the
AN-4 `buf breaking` gate, which would flag an added export RPC.

## Claim 26 — HSM / module custody boundary (SEAM DELIVERED; module test needs a module)

Claim 26's hardware embodiment is the same enforcement component (the signer,
mediating all use) with the key factory backed by a **module-resident** backend, so
private material never exists outside the module. This plugs in at the existing
`signing.WithKeyFactory` seam — the same seam the EE build uses for post-quantum
algorithms — with no change to the mint path. The PKCS#11 primitives already exist
in-tree (`internal/kms/pkcs11`, `github.com/miekg/pkcs11`), and
`internal/succession/minter.SoftHSM` is the software double used to exercise the module
semantics in unit tests.

What is **not** delivered here is a full integration test against a real module: it
requires a provisioned SoftHSM2 / PKCS#11 token, which is a deployment/CI resource and
is not available in this build environment. The module-resident `KeyFactory` adapter
and its SoftHSM2-backed integration test are tracked for the environment that provides
a token; the software-locked embodiment (claim 16) is the default and is fully
delivered and tested.
