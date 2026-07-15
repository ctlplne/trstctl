# Code signing & timestamping — prove an artifact is genuine, and prove when

## What it is

**Code signing** is putting a verifiable signature on a software artifact — a binary, a
container image, an SBOM — so anyone can confirm it came from you and wasn't tampered
with. **Timestamping** is getting a trusted third party to attest *when* something was
signed, so the signature stays verifiable even after the signing certificate expires.
trstctl provides both: a governed code-signing service and an RFC 3161 timestamping
authority (TSA).

## Why it exists

Software supply-chain attacks slip malicious artifacts into a trusted pipeline. Signing
every artifact and verifying signatures before you run them closes that door. But
signing has two hazards: the key is extremely valuable, so it must never sit in a
build script, and signatures normally become unverifiable once the certificate
expires, so long-lived artifacts "rot." trstctl addresses both — keys stay in an
[HSM](../glossary.md)/the isolated signer, the signing path composes with the live
policy and distinct-approver gates when enabled, and the TSA supplies the timestamps
that give signatures long-term validity.

## How it works

### The code-signing service (F50)

The service signs the *digest* (hash) of an artifact, never the artifact itself, so it
works for anything from a 4 KB manifest to a 4 GB image. Two modes:

- **Key-based signing.** The API seals the complete command with tenant- and
  operation-bound AAD and projects it as a `codesign.command` outbox row (event
  `codesign.commanded`) in one PostgreSQL transaction. The bounded outbox worker opens
  it and, when `ca.policy.enabled` and/or `ca.policy.require_approval` is configured,
  evaluates `MaySign(tenant, principal, key, digest)` through the same OPA evaluator
  and distinct-approver store the served lifecycle gate uses; a denial is audited
  (`codesign.refused`) and signs nothing. On approval, the key resolves to a signer
  handle — persistent and purpose-constrained in production, or an explicitly
  configured ephemeral resolver for eval/test — and the digest is signed through the
  signer boundary, where the private key never appears in the request, response, logs,
  or API process memory. The isolated signer journals the operation before replying,
  so a crash after signing replays the same bytes instead of signing twice, and the
  result returns as an immutable `codesign.signed` event. `codesign.completed` then
  atomically queues transparency-log publication (`transparency.rekor` by default);
  the request thread only polls its own operation, never calling the signer or Rekor
  inline or holding a database transaction while waiting.
- **Keyless signing (Sigstore/Fulcio style).** Instead of a long-lived key, the caller
  presents a verified [attestation](workload-identity.md) — for example, a CI job's
  OIDC identity — sealed inside the command, never plaintext in the event log,
  PostgreSQL, or outbox. The outbox worker verifies that proof through the configured
  Fulcio-style attestor, creates a deterministic ephemeral signer handle, and signs the
  digest. The bound Fulcio SAN/issuer come from the verified attestation, never
  caller-supplied strings: a claim that contradicts the attestation is refused
  (`codesign.keyless.refused`), and no verified attestation is rejected outright.
  Completion atomically queues both the Rekor bundle and a durable `codesign.cleanup`
  command; the handle derives deterministically from the operation ID even if a crash
  loses the in-memory value first. Cleanup is idempotent and records
  `codesign.ephemeral.destroyed`, so a crash cannot strand an ephemeral handle.

Verification (`Verify`, `VerifyKeyless`) routes through the same signer boundary, with
each tenant's data isolated at the database layer and digests/signatures held as
wipeable, zeroed `[]byte` buffers, never strings.

### The timestamping authority (F51)

A TSA answers one question with a signed token: here is a hash, certify the time right
now. trstctl's TSA (RFC 3161) builds a `TSTInfo` record — policy, hash algorithm, the
submitted hash, a monotonic serial, and the generation time — and signs it through the
signer boundary, kept in the isolated signing service rather than the API process.
Each issuance is recorded as an immutable `tsa.timestamp.issued` event.

The payoff is long-term validity (LTV): a `VerifyLongTermValidity` check confirms the
signature and that the timestamp falls within the signing certificate's validity
window, so you can prove an artifact was signed while the certificate was still good,
even years after it has expired — what keeps a five-year-old signed release
verifiable.

### In the console

The `/codesign` screen offers key-backed and keyless (Fulcio) signing: it submits only
the artifact digest and renders the returned signature receipt, so private keys and
artifact bytes never enter the browser. See [The web console](../web-console.md).

## Use it

The code-signing API requires the shipped `code_signing` configuration, which
tenant-binds signer handles and Fulcio-style attestors and pins the Rekor log public
key. Sign exactly one 32-byte SHA-256 artifact digest through the REST API or CLI —
trstctl signs those exact bytes and never hashes the digest again. The authenticated
token subject becomes the signer principal; the request body carries no trusted
`principal` field. See [Configuration](../configuration.md#code-signing) for a complete
production example.

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
  "identity_payload": "eyJqd3QiOiJleGFtcGxlIn0="
}
JSON

trstctl-cli --idempotency-key release-keyless-2026-06-25 code-signing keyless -f code-sign-keyless.json
```

Both responses return `algorithm`, `signature`, `public_key_der`, `artifact_type`, and
`transparency_destination` (base64 JSON bytes for the key fields); key-based responses
also include `key_id`, keyless responses the verified `fulcio_san`/`fulcio_issuer`. The
outbox worker submits an official Rekor v1 HashedRekord, confirms it binds the digest,
signature, and public key, and checks the signed-entry timestamp against the
operator-pinned log key before acknowledging delivery — on an idempotent `409` it
instead follows the same-origin Rekor `Location` and re-verifies the existing entry.

`Idempotency-Key` binds the canonical command: a replay returns the original response
byte-for-byte without signing again, and reusing the key for a different digest, key,
artifact type, principal, or identity proof is rejected. A terminal worker failure
projects an immutable `codesign.failed` fact before the outbox dead-letters it, even if
the caller disconnected; failure values are closed-form codes, never an upstream error
string that could echo identity material.

When `ca.policy.require_approval` is enabled, the first denied response is `403` with
a non-secret `approval_required:codesign:<sha256>` resource. A distinct approver
records `{"action":"sign"}` for it through
`POST /api/v1/identities/{resource}/approvals`; the requester resubmits the same
principal/key/digest with a new `Idempotency-Key`. The resource binds the tenant-scoped
principal, key (or keyless identity), and exact digest, so it cannot authorize another
caller or artifact — the approval route requires `certs:issue`, the signing request
`keys:write`.

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
  and `trstctl-cli code-signing keyless` commands. The shipped binary builds the
  service from `code_signing`, fails closed with `501` while that configuration is
  disabled, and fails closed at startup if an enabled configuration lacks an isolated
  signer, tenant-bound keys/attestors, or pinned Rekor log trust. Mutations require
  `Idempotency-Key` and `keys:write`; policy and distinct-approver enforcement engage
  when `ca.policy.enabled` / `ca.policy.require_approval` are set, otherwise RBAC plus
  signer purpose constraints are the authorization boundary. The TSA is served at
  `/tsa` when
  `protocols.tsa.enabled` plus `protocols.tsa.tenant_id` are set, returning
  `application/timestamp-reply` `TimeStampResp` bodies.
- Wire formats differ by surface: the TSA emits a real RFC 3161 `TimeStampToken` — a
  CMS `SignedData` over a DER `TSTInfo` — wrapped in the required `TimeStampResp`
  envelope for stock verifiers (`openssl ts -verify`, DSS/ESS validators). Code signing
  itself returns trstctl's JSON signature receipt and queues Rekor publication through
  outbox: the payload holds digest, signature, public key, key id or Fulcio identity,
  and no private material or artifact bytes. For byte-level cosign bundle interchange,
  validate that encoding separately.
- Keys belong in the signer: the code-signing resolver uses persistent,
  purpose-constrained keys inside the isolated `trstctl-signer`, so signing keys never
  live in a build agent. The separately served HSM/KMS and CA custody paths are not
  currently a code-signing key resolver — don't call a configured handle
  hardware-backed unless that bridge is added and independently proven.
- Keyless still needs a real attestation: it's only as strong as the OIDC identity you
  verify. The served keyless path derives the signed SAN/issuer from that attestation
  and refuses a conflicting SAN/issuer, or none at all.

## Reference

- **Code signing:** `POST /api/v1/code-signing/sign`,
  `POST /api/v1/code-signing/keyless`, `trstctl-cli code-signing sign`,
  `trstctl-cli code-signing keyless`, `Service.Sign`, `Service.SignKeyless`,
  `Verify`, `VerifyKeyless`.
- **Timestamping:** `Authority.Timestamp`, `Verify`, `VerifyLongTermValidity` (RFC 3161).
- **Events:** `codesign.commanded`, `codesign.completed`, `codesign.failed`,
  `codesign.ephemeral.destroyed`, `codesign.signed`, `codesign.refused`,
  `codesign.keyless.signed`, `attestation.verified`, `tsa.timestamp.issued`; worker
  execution uses `codesign.command`/`codesign.cleanup`, and Rekor publication uses the
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
