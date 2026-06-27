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
  an HSM/PKCS#11-backed resolver in production, or a software resolver for eval/test
  deployments. The private key lives behind the resolver/signer boundary and never
  appears in the request, response, logs, or API process memory. The signature, public
  key, and algorithm come back; the act is recorded as an immutable `codesign.signed`
  event. The transparency-log publication is queued as an outbox row
  (`transparency.rekor` by default), so the request thread never calls Rekor inline.
- **Keyless signing (Sigstore/Fulcio style).** Instead of a long-lived key, the caller
  presents a verified [attestation](workload-identity.md) (for example, a CI job's OIDC
  identity). The served API verifies that proof through the configured Fulcio-style
  attestor, generates a fresh ephemeral key, signs the digest, and binds the signature
  to the **verified** identity: the Fulcio SAN and issuer are **derived from the
  attestation** (its verified subject and issuer), not taken from caller-supplied
  strings. A request whose claimed SAN/issuer contradicts the attestation is refused
  (`codesign.keyless.refused`), and a request with no verified attestation is rejected
  outright. The signed bundle is queued to Rekor through outbox, just like key-based
  signing.

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

### In the console

The `/codesign` screen is a real signing console with **key-backed** and **keyless (Fulcio)**
modes: it submits only the artifact digest and renders the returned signature receipt, so
private keys and artifact bytes never enter the browser. See
[The web console](../web-console.md).

## Use it

The served code-signing API is disabled unless the deployment composition supplies a
`CodeSigningConfig` with a key resolver, optional signing gate, Fulcio-style attestors,
and a Rekor/transparency outbox handler. When it is enabled, sign an artifact digest
through the REST API or CLI. The authenticated token subject becomes the signer
principal; there is no trusted `principal` field in the request body.

Key-based signing:

```bash
cat > code-sign.json <<'JSON'
{
  "key_id": "release-key",
  "artifact_type": "oci-image",
  "digest": "4EW4IfBBkDngEwN3v+ChO06PV2er4tF7nEVmFev3x1g="
}
JSON

trstctl-cli --idempotency-key release-sign-2026-06-25 code-signing sign -f code-sign.json
```

Keyless/Sigstore signing:

```bash
cat > code-sign-keyless.json <<'JSON'
{
  "artifact_type": "oci-image",
  "digest": "4EW4IfBBkDngEwN3v+ChO06PV2er4tF7nEVmFev3x1g=",
  "identity_method": "github_oidc",
  "identity_payload": "eyJqd3QiOiJleGFtcGxlIn0=",
  "fulcio_san": "repo:acme/payments:ref:refs/heads/main",
  "fulcio_issuer": "https://token.actions.githubusercontent.com"
}
JSON

trstctl-cli --idempotency-key release-keyless-2026-06-25 code-signing keyless -f code-sign-keyless.json
```

Both responses return `algorithm`, `signature`, `public_key_der`,
`artifact_type`, and `transparency_destination`; key-based responses include `key_id`,
and keyless responses include the verified `fulcio_san` and `fulcio_issuer`. The
`signature` and `public_key_der` fields are base64 JSON bytes. A verifier checks the
signature over the same digest, then uses the Rekor inclusion record once the outbox
worker has delivered the transparency entry.

For long-term validity, timestamp the returned signature through the TSA:

```bash
openssl ts -query -data signature.bin -sha256 -cert -out signature.tsq
curl -sS -H 'Content-Type: application/timestamp-query' \
  --data-binary @signature.tsq \
  https://trstctl.example.com/tsa \
  -o signature.tsr
```

## Pitfalls & limits

- **Serving status:** code signing is served at `POST /api/v1/code-signing/sign` and
  `POST /api/v1/code-signing/keyless`, with matching `trstctl-cli code-signing sign`
  and `trstctl-cli code-signing keyless` commands. The surface is fail-closed with
  `501` until the deployment wires `CodeSigningConfig`; mutations require
  `Idempotency-Key` and the `keys:write` permission. The TSA is served by the running
  control plane at `/tsa` when `protocols.tsa.enabled` plus
  `protocols.tsa.tenant_id` are set; it returns `application/timestamp-reply`
  `TimeStampResp` bodies.
- **TSA wire format is real RFC 3161; code-signing bundle is pragmatic JSON plus
  Rekor outbox.** The TSA emits a real **RFC 3161 `TimeStampToken`** — a CMS `SignedData`
  over a DER `TSTInfo` with `eContentType id-ct-TSTInfo`, in `Token.DER` — and the
  served handler wraps it in the required `TimeStampResp` envelope for stock verifiers
  (`openssl ts -verify`, DSS/ESS validators). It is no longer a bespoke JSON manifest
  (the JSON struct fields remain only for the in-process LTV/message-imprint checks).
  Code signing returns trstctl's JSON signature receipt and queues Rekor publication
  through outbox. The Rekor payload contains digest, signature, public key, key id or
  Fulcio identity, and no private material or artifact bytes. If you need byte-level
  cosign bundle interchange, validate that bundle encoding in your deployment.
- **Keys belong in the signer.** Use HSM/KMS-backed keys (see
  [Issuance & CAs](issuance-and-cas.md)) so signing keys never live in a build agent.
- **Keyless still needs a real attestation** — it's only as strong as the OIDC identity
  you verify, and that identity is enforced: the served keyless path derives the signed
  SAN/issuer from the verified attestation and refuses a request that supplies a
  conflicting SAN/issuer or carries no verified attestation.

## Reference

- **Code signing:** `POST /api/v1/code-signing/sign`,
  `POST /api/v1/code-signing/keyless`, `trstctl-cli code-signing sign`,
  `trstctl-cli code-signing keyless`, `Service.Sign`, `Service.SignKeyless`,
  `Verify`, `VerifyKeyless`.
- **Timestamping:** `Authority.Timestamp`, `Verify`, `VerifyLongTermValidity` (RFC 3161).
- **Events:** `codesign.signed`, `codesign.refused`, `codesign.keyless.signed`,
  `attestation.verified`, `tsa.timestamp.issued`; Rekor publication uses the
  `transparency.rekor` outbox destination.
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
