# Code signing & timestamping — prove an artifact is genuine, and prove when

## What it is

**Code signing** is putting a verifiable signature on a software artifact — a binary, a
container image, an SBOM — so anyone can confirm it came from you and wasn't tampered
with. **Timestamping** is getting a trusted third party to attest *when* something was
signed, so the signature stays verifiable even after the signing certificate expires.
trstctl provides both: a governed code-signing service and an RFC 3161 timestamping
authority (TSA).

The mental model: code signing is a tamper-evident wax seal on a package — break it and
everyone can tell. Timestamping is the postmark the post office stamps on it: an
independent record of *when* it was sealed, which is what lets you trust an old seal long
after the signer's ID card has expired.

## Why it exists

Software supply-chain attacks work by slipping malicious artifacts into a trusted
pipeline. Signing every artifact and verifying signatures before you run them closes that
door. But signing has two operational hazards: the signing key is extremely valuable (so
it must never sit in a build script), and signatures normally become unverifiable once
the signing certificate expires (so long-lived artifacts "rot"). trstctl addresses both
— keys stay in an [HSM](../glossary.md)/the isolated signer, every signature is policy-
and approval-gated, and the TSA provides the timestamps that give signatures long-term
validity.

## How it works

### The code-signing service (F50)

The service signs the *digest* (hash) of an artifact, never the artifact itself, so it
works for anything — a 4 KB manifest or a 4 GB image. Two modes:

- **Key-based signing.** Every request first passes a **gate**: a policy + just-in-time
  [approval](incident-and-jit.md) check (`MaySign(tenant, principal, key, digest)`). A
  denial is audited (`codesign.refused`) and signs nothing. On approval, the key is
  resolved to a signer handle and the digest is signed through `internal/crypto`
  (**AN-3**) — the private key lives in the isolated signer and never leaves it
  (**AN-4**). The signature, public key, and algorithm come back; the act is audited
  (`codesign.signed`, **AN-2**).
- **Keyless signing (Sigstore/Fulcio style).** Instead of a long-lived key, the caller
  presents a verified [attestation](workload-identity.md) (e.g. a CI job's OIDC identity)
  and a fresh ephemeral key. trstctl signs with the ephemeral key and binds the
  signature to the **verified** identity: the Fulcio SAN and issuer are **derived from
  the attestation** (its verified subject and issuer), not taken from caller-supplied
  strings — a request whose claimed SAN/issuer contradicts the attestation is refused
  (`codesign.keyless.refused`), and a request with no verified attestation is rejected
  outright (PKIGOV-011). The attestation *is* the authorization — there's no standing
  key to steal, and a caller cannot attach an arbitrary identity to a signature.

Verification (`Verify`, `VerifyKeyless`) also routes through `internal/crypto`. The
service is tenant-scoped (**AN-1**) and keeps digests/signatures as `[]byte` (**AN-8**).

*Code:* `internal/codesign` (`Service`, `Sign`, `SignKeyless`, `Verify`).

### The timestamping authority (F51)

A TSA answers a simple question with a signed token: "here is a hash; certify the time
right now." trstctl's TSA (RFC 3161) builds a `TSTInfo` record — policy, hash algorithm,
the submitted hash, a monotonic serial, and the generation time — and signs it with its
TSA key through `internal/crypto` (**AN-3**), with the key in the isolated signer
(**AN-4**). Each issuance is audited (`tsa.timestamp.issued`, **AN-2**).

The payoff is **long-term validity (LTV)**. A `VerifyLongTermValidity` check confirms the
token's signature *and* that its timestamp falls within the signing certificate's validity
window — so you can prove an artifact was signed while the certificate was still good,
even years later after that certificate has expired. That's what keeps a five-year-old
signed release verifiable.

*Code:* `internal/tsa` (`Authority`, `Timestamp`, `Verify`, `VerifyLongTermValidity`).

## Use it

Both are Go-library services today (see status below). Conceptually, signing an image
digest and timestamping it:

```go
// 1) sign the artifact's digest (gated by policy + approval)
sig, err := codesign.Sign(ctx, codesign.SignRequest{
    Principal:    "release-pipeline",
    KeyID:        "release-key",          // resolved to an HSM-backed signer
    ArtifactType: "oci-image",
    Digest:       imageDigest,            // the SHA-256 of the image
})

// 2) timestamp the signature for long-term validity
tok, err := tsa.Timestamp(ctx, crypto.SHA256Sum(sig.Value))
```

A verifier later checks both the signature and, via `VerifyLongTermValidity`, that the
timestamp falls inside the signing certificate's lifetime.

## Pitfalls & limits

- **Serving status:** the code-signing service and the TSA are library-complete and
  tested, but are **not yet wired** into the running control plane (no API route or CLI
  command). Treat them as built, pending an exposed surface — see
  [Current limitations](../limitations.md).
- **TSA wire format is real RFC 3161 CMS (INTEROP-005); code-signing bundle is still
  pragmatic.** The TSA now emits a real **RFC 3161 `TimeStampToken`** — a CMS `SignedData`
  over a DER `TSTInfo` with `eContentType id-ct-TSTInfo`, in `Token.DER` with content
  type `application/timestamp-reply` — so a stock verifier (`openssl ts -verify`, a
  DSS/ESS validator) can parse it; it is no longer a bespoke JSON manifest (the JSON
  struct fields remain only for the in-process LTV/message-imprint checks). The
  **code-signing** output, by contrast, is still trstctl's own structure: full **Sigstore
  bundle** interop is a documented follow-up, so if you need byte-level interop with an
  external cosign verifier, confirm that encoding first.
- **Keys belong in the signer.** Use HSM/KMS-backed keys (see
  [Issuance & CAs](issuance-and-cas.md)) so signing keys never live in a build agent.
- **Keyless still needs a real attestation** — it's only as strong as the OIDC identity
  you verify, and that identity is now **enforced**: `SignKeyless` derives the signed
  SAN/issuer from the verified attestation and refuses a request that supplies a
  conflicting SAN/issuer or carries no verified attestation (PKIGOV-011). Wiring the
  full Sigstore/Fulcio certificate-issuance flow (a short-lived Fulcio cert over the
  ephemeral key, Rekor transparency-log inclusion) behind a served, RBAC-gated surface
  is tracked with the code-signing wire-in work; the in-process binding above is what
  the library enforces today.

## Reference

- **Code signing:** `Service.Sign` (key-based, gated), `Service.SignKeyless`
  (attestation-based), `Verify`, `VerifyKeyless`.
- **Timestamping:** `Authority.Timestamp`, `Verify`, `VerifyLongTermValidity` (RFC 3161).
- **Events:** `codesign.signed`, `codesign.refused`, `codesign.keyless.signed`,
  `tsa.timestamp.issued`.
- **Related:** the signing key lives behind the [signing service](../design/signing-service.md)
  (AN-4); the supply-chain story is in [Supply chain](../supply-chain.md).

## See also

[Issuance & certificate authorities](issuance-and-cas.md) (HSM-backed keys) ·
[Workload identity](workload-identity.md) (the attestation behind keyless signing) ·
[Supply chain](../supply-chain.md) · [Signing-service design](../design/signing-service.md) ·
glossary: [HSM/KMS](../glossary.md), [attestation](../glossary.md),
[fingerprint](../glossary.md)

**Covers:** F50, F51
