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
  resolved to a signer handle and the digest is signed through the single crypto path —
  the private key lives in the separate, isolated signing service and never leaves it, so
  it is never present in the API process. The signature, public key, and algorithm come
  back; the act is recorded as an immutable `codesign.signed` event.
- **Keyless signing (Sigstore/Fulcio style).** Instead of a long-lived key, the caller
  presents a verified [attestation](workload-identity.md) (e.g. a CI job's OIDC identity)
  and a fresh ephemeral key. trstctl signs with the ephemeral key and binds the
  signature to the **verified** identity: the Fulcio SAN and issuer are **derived from
  the attestation** (its verified subject and issuer), not taken from caller-supplied
  strings — a request whose claimed SAN/issuer contradicts the attestation is refused
  (`codesign.keyless.refused`), and a request with no verified attestation is rejected
  outright. The attestation *is* the authorization — there's no standing
  key to steal, and a caller cannot attach an arbitrary identity to a signature.

Verification (`Verify`, `VerifyKeyless`) also routes through the single crypto path. The
service keeps each tenant's data isolated at the database layer and holds
digests/signatures as wipeable `[]byte` buffers that are zeroed after use, never strings.

### The timestamping authority (F51)

A TSA answers a simple question with a signed token: "here is a hash; certify the time
right now." trstctl's TSA (RFC 3161) builds a `TSTInfo` record — policy, hash algorithm,
the submitted hash, a monotonic serial, and the generation time — and signs it with its
TSA key through the single crypto path, with the key in the separate, isolated signing
service rather than the API process. Each issuance is recorded as an immutable
`tsa.timestamp.issued` event.

The payoff is **long-term validity (LTV)**. A `VerifyLongTermValidity` check confirms the
token's signature *and* that its timestamp falls within the signing certificate's validity
window — so you can prove an artifact was signed while the certificate was still good,
even years later after that certificate has expired. That's what keeps a five-year-old
signed release verifiable.

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

- **Serving status:** the TSA is now served by the running control plane at `/tsa`
  when `protocols.tsa.enabled` plus `protocols.tsa.tenant_id` are set. It accepts
  `application/timestamp-query` `TimeStampReq` bodies and returns
  `application/timestamp-reply` `TimeStampResp` bodies; a required CI job proves
  `openssl ts -query` -> HTTP POST -> `openssl ts -verify` end to end. The code-signing
  service remains library-complete and tested, but is **not yet wired** into a public API
  route or CLI command — see [Current limitations](../limitations.md).
- **TSA wire format is real RFC 3161; code-signing bundle is still
  pragmatic.** The TSA emits a real **RFC 3161 `TimeStampToken`** — a CMS `SignedData`
  over a DER `TSTInfo` with `eContentType id-ct-TSTInfo`, in `Token.DER` — and the
  served handler wraps it in the required `TimeStampResp` envelope for stock verifiers
  (`openssl ts -verify`, DSS/ESS validators). It is no longer a bespoke JSON manifest
  (the JSON struct fields remain only for the in-process LTV/message-imprint checks).
  The **code-signing** output, by contrast, is still trstctl's own structure: full
  **Sigstore bundle** interop is a documented follow-up, so if you need byte-level
  interop with an external cosign verifier, confirm that encoding first.
- **Keys belong in the signer.** Use HSM/KMS-backed keys (see
  [Issuance & CAs](issuance-and-cas.md)) so signing keys never live in a build agent.
- **Keyless still needs a real attestation** — it's only as strong as the OIDC identity
  you verify, and that identity is now **enforced**: `SignKeyless` derives the signed
  SAN/issuer from the verified attestation and refuses a request that supplies a
  conflicting SAN/issuer or carries no verified attestation. Wiring the
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
- **Related:** the signing key lives behind the separate, isolated
  [signing service](../design/signing-service.md), never in the API process; the
  supply-chain story is in [Supply chain](../supply-chain.md).

## See also

[Issuance & certificate authorities](issuance-and-cas.md) (HSM-backed keys) ·
[Workload identity](workload-identity.md) (the attestation behind keyless signing) ·
[Supply chain](../supply-chain.md) · [Signing-service design](../design/signing-service.md) ·
glossary: [HSM/KMS](../glossary.md), [attestation](../glossary.md),
[fingerprint](../glossary.md)

**Covers:** F50, F51
