# Code signing & timestamping — prove an artifact is genuine, and prove when

## What it is

**Code signing** is putting a verifiable signature on a software artifact — a binary, a
container image, an SBOM — so anyone can confirm it came from you and wasn't tampered
with. **Timestamping** is getting a trusted third party to attest _when_ something was
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

The service signs the _digest_ (hash) of an artifact, never the artifact itself, so it
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
  PostgreSQL, or outbox. The outbox worker verifies that proof with the configured,
  locally pinned OIDC public keys, creates a deterministic ephemeral signer handle,
  and signs the digest. The bound Fulcio SAN/issuer come from the verified
  attestation, never caller-supplied strings: a claim that contradicts it is refused
  (`codesign.keyless.refused`), and no verified attestation is rejected outright.
  Completion atomically queues both the Rekor bundle and a durable `codesign.cleanup`
  command; the handle derives deterministically from the operation ID even if a crash
  loses the in-memory value first. Cleanup is idempotent and records
  `codesign.ephemeral.destroyed`, so a crash cannot strand an ephemeral handle.
  The service records the verified OIDC issuer and identity as Fulcio binding
  metadata. It does not request a Fulcio certificate or return a portable
  attestation of that identity. The proof itself is not sent to Fulcio or Rekor.
  A relying party can verify the signature with the returned public key;
  independent identity verification needs a separate
  portable certificate or attestation workflow.

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

Open **Software Trust → Software signing**. The `/codesign` screen offers key-backed
and keyless (OIDC-bound) signing: it submits only
the artifact digest and renders the returned signature receipt, so private keys and
artifact bytes never enter the browser. See [The web console](../web-console.md).

For timestamping, open **Certificates → Protocols**, then **Set up and operate
methods**. **Timestamp authority readiness** checks the exact running process before
you send an artifact hash. It confirms the tenant-bound `/tsa` mount, active protocol
profile, stable timestamping-only certificate, isolated signer connection, immutable
audit path, and bounded responder capacity. The check is deliberately effect-free: it issues no
timestamp, reads no certificate file, contacts no signer or network, and performs no
write. A failed gate names the safe repair and leaves **Check again** available.

Readiness is not interoperability proof. The OpenSSL query, HTTP POST, and verify
commands in the same Protocols workspace are the real wire test. OpenSSL hashes the
artifact locally; trstctl receives only the hash inside the RFC 3161 request. The
artifact and its private signing key never enter the console or timestamp service.

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
also include `key_id`, keyless responses the verified `fulcio_san`/`fulcio_issuer`
binding values. Those names describe what Fulcio would certify; the response
does not include a Fulcio certificate. The outbox worker submits an official
Rekor v1 HashedRekord, confirms it binds the digest,
signature, and public key, and checks the signed-entry timestamp against the
operator-pinned log key before acknowledging delivery — on an idempotent `409` it
instead follows the same-origin Rekor `Location` and re-verifies the existing entry.

`Idempotency-Key` binds the canonical command: a replay returns the original response
byte-for-byte without signing again, and reusing the key for a different digest, key,
artifact type, principal, or identity proof is rejected. A terminal worker failure
projects an immutable `codesign.failed` fact before the outbox dead-letters it, even if
the caller disconnected; failure values are closed-form codes, never an upstream error
string that could echo identity material. A request whose deadline passes before the
outcome is confirmed, including in the middle of a database write, is answered as the
deadline (a retryable `503` with `Retry-After`), never as a socket error; retrying with
the same `Idempotency-Key` returns the recorded command's result.

When `ca.policy.require_approval` is enabled, the first request is refused (`403`) with
a non-secret `approval_required:codesign:<sha256> request_id=<id> intent_digest=<digest>`,
and an immutable approval request is recorded. A distinct approver grants it with
`POST /api/v1/approval-requests/{id}/approvals` (`{"intent_digest": "<digest>"}`) or refuses
it with `.../denials` and a reason; the requester repeats the same request with the same
`Idempotency-Key`, which signs once and consumes the approval. The approval binds the
tenant, the principal, the key (or keyless identity), the artifact type — which names the
signing mechanism, such as `pkcs11:CKM_ECDSA_SHA256` or `notation:ECDSA-SHA-256` — the exact
digest and the idempotency key, and expires: a modified artifact, another signer, key or
mechanism, a used approval, an expired one or another tenant's cannot sign. Repeating an
approved request returns the recorded signature without signing again. The approval
routes require `certs:issue`, the signing request `keys:write`.

For long-term validity, timestamp the returned signature through the TSA:

```bash
openssl ts -query -data signature.bin -sha256 -cert -out signature.tsq
curl -sS -H 'Content-Type: application/timestamp-query' \
  --data-binary @signature.tsq \
  https://trstctl.example.com/tsa \
  -o signature.tsr
```

An authenticated automation can review the same zero-effect runtime gates with
`POST /api/v1/protocols/tsa/qualification` using `certs:read`. Its response contains
only readiness booleans, the public endpoint and policy OID, bounded explanations,
and recovery steps. It never returns tenant IDs, certificate bytes or paths, signer
handles, request bodies, tokens, or keys. Timestamp issuance remains exclusively at
the public protocol endpoint `POST /tsa`.

The equivalent headless operator command is:

```console
trstctl protocols tsa qualify
```

It calls that same read-only qualification surface. It sends no request body or
mutation headers and cannot issue a timestamp; use the OpenSSL flow above for the
real RFC 3161 proof.

### Sign with Notation, cosign and other stock tools

Stock signing tools need a certificate that names the signing key; the key itself
stays in the isolated signer. Get a certificate request the key signs inside the
signer, have your CA issue a certificate with the `codeSigning` extended key usage
from it, and configure the chain (leaf first) beside the key as
`code_signing.keys[].certificate_chain_file`:

```bash
echo '{"common_name": "Acme release signing"}' > csr.json
trstctl-cli code-signing keys csr release-key -f csr.json | jq -r .csr_pem > release-key.csr
# your CA issues the certificate; save the chain, leaf first, as the configured file
trstctl-cli code-signing keys certificate release-key
```

Startup refuses a chain whose leaf does not carry the key's public key or lacks the
`codeSigning` usage. Each certificate request is recorded as `codesign.csr_signed`.
The signing clients in [`clients/signing`](https://github.com/ctlplne/trstctl/tree/main/clients/signing) (MPL-2.0,
standard library only) hash locally, have trstctl sign the digest, and return the
signature with the chain; permissions, policy and approvals apply to every signature.

- **Notation:** install the `notation-trstctl` plugin and add a key with
  `notation key add release --plugin trstctl --id release-key`; `notation sign`
  then signs through trstctl. Verify with a Notation trust policy rooted at your CA.
  The plugin offers ECDSA P-256 keys: trstctl signs SHA-256 digests, and Notation
  pairs P-384 with SHA-384 and RSA with RSASSA-PSS.
- **cosign:** `cosign generate` writes the payload for an image, trstctl signs its
  SHA-256 digest, and `cosign attach signature` stores the signature in the registry:

```bash
cosign generate registry.example.com/app@sha256:<digest> > payload.json
printf '{"key_id":"release-key","artifact_type":"oci-image","digest":"%s"}' \
  "$(openssl dgst -sha256 -binary payload.json | base64)" > sign.json
trstctl-cli code-signing sign -f sign.json | jq -r .signature > payload.sig
cosign attach signature --payload payload.json --signature payload.sig registry.example.com/app@sha256:<digest>
trstctl-cli code-signing keys certificate release-key | jq -r .public_key_der | base64 -d |
  openssl pkey -pubin -inform DER -out release-key.pub
cosign verify --key release-key.pub --insecure-ignore-tlog=true registry.example.com/app@sha256:<digest>
```

`--insecure-ignore-tlog` tells cosign not to look for its own log bundle; trstctl
records each signature in Rekor through the outbox as described above.

- **Keys in an HSM or cloud KMS:** a code-signing key can be an Enterprise managed
  key (`managed_key_provider`, `managed_key_id`; see
  [Configuration](../configuration.md#code-signing)) instead of a signer handle. The
  stock tools above use it the same way; each signature runs in the HSM or KMS through
  the isolated signer, authorized per signature and journaled by the signing command.
  A PKCS#11 managed key is RSA-2048, or EC P-256 or P-384 (P9-L3): generated inside the
  token, sign-only and never extractable (an EC private key also may not derive); an EC
  key signs the digest with `CKM_ECDSA`, and trstctl stores and verifies its ASN.1 form.
- **jarsigner, osslsigncode and other PKCS #11 tools:** `libtrstctl-pkcs11`
  (`make signing-clients`) is a PKCS #11 module with one token whose PIN is your
  API token and whose objects are the keys `TRSTCTL_PKCS11_KEYS` names, each with
  its certificate chain. The private-key handles are sensitive and never
  extractable; the module signs with ECDSA P-256 and RSA keys
  (`CKM_ECDSA`, `CKM_ECDSA_SHA256`, `CKM_RSA_PKCS`, `CKM_SHA256_RSA_PKCS`) and
  does nothing else. jarsigner loads it through SunPKCS11 and osslsigncode through
  the OpenSSL pkcs11 engine; see [`clients/signing`](https://github.com/ctlplne/trstctl/tree/main/clients/signing)
  for both command lines.
- **signtool and other Windows CNG tools:** `trstctl-ksp.dll`
  (`make signing-ksp-windows`) is a CNG key storage provider. Install it from an
  elevated prompt with `trstctl-ksp-register install trstctl-ksp.dll`; it offers the
  keys `TRSTCTL_KSP_KEYS` names as key containers (ECDSA P-256 and RSA) and signs
  SHA-256 hashes, RSA with PKCS #1 v1.5. It creates, imports and exports no private
  key. signtool names the provider and the key:
  `signtool sign /fd sha256 /f release.cer /csp "trstctl Key Storage Provider" /kc release-key app.exe`.

While a signing approval is pending, the Notation plugin, the PKCS #11 module and the
Windows provider hold the tool's request open — resending the same request, which is
what the approver grants — for up to `TRSTCTL_APPROVAL_WAIT` (default `10m`; `0` does not wait), and the
tool signs once the approval is granted. A request trstctl refuses — a missing
`keys:write`, a policy denial, an approval that is denied or expired, or a wait that
runs out — stops the tool with trstctl's reason; Notation reports it as
`ACCESS_DENIED`, the PKCS #11 module as `CKR_FUNCTION_REJECTED` and the Windows
provider as `NTE_PERM`.

### Rotating and revoking the TSA certificate

Every certificate the TSA signs under is an entry of its issuing CA's ledger, so
the CA's CRL (`/crl/<tenant>.crl`) and OCSP responder (`/ocsp/<tenant>`) answer
for it like any other certificate the CA issued. **Protocols → TSA certificates**
(or `trstctl protocols tsa certificates list`) shows each one as active, retired
or revoked.

Rotate when the key must be replaced:

```console
echo '{"revoke_previous_reason":"keyCompromise"}' > rotate.json
trstctl protocols tsa certificates rotate -f rotate.json
```

A new key is generated in the isolated signer under its own handle, certified by
the same CA, persisted to `protocols.tsa_cert_file`, and used for every later
timestamp. With a reason, the outgoing certificate is revoked and the CRL is
published again; without one it is retired and stays valid for the timestamps it
signed. A certificate rotated out earlier can be revoked later with
`trstctl protocols tsa certificates revoke <serial> -f reason.json`. The active
certificate cannot be revoked in place — rotate instead, so the TSA never signs
under a revoked certificate. Both changes need `issuers:write` and are served only
to the TSA's own tenant.

Audit exports carry the CA's OCSP answer for every TSA certificate their
timestamps rely on, and `trstctl audit verify --tsa-root ...` checks it: a
certificate revoked for key or CA compromise refuses every timestamp it signed,
one revoked for another reason refuses only the timestamps at or after its
revocation, and `--tsa-crl` lets an auditor bring a fresher CRL.

## Preview, execute, recover, prove

The console and headless client now use the same two-step safety contract:

1. **Preview** validates one exact SHA-256 digest, artifact type, tenant, caller,
   managed-key ID or keyless identity proof, approval posture, isolated-signer
   algorithm, and Rekor destination. The server returns a keyed request fingerprint
   plus a configuration fingerprint. It does not resolve a live signer, attest the
   identity proof, append an event, reserve idempotency, write SQL, or contact
   Fulcio/Rekor. The keyless proof is never returned in the plan.
2. **Execute** sends that fingerprint with one retained `Idempotency-Key`. The server
   recomputes readiness and the keyed fingerprint before a command can exist. A
   changed digest, caller, signer, proof, or runtime configuration returns `409` and
   signs nothing.
3. **Recover** retries an uncertain response with the unchanged request and the same
   idempotency key. A new command requires a new preview. The recent-outcomes ledger
   shows durable signing and transparency failures without opening the sealed command.
4. **Prove** verifies the returned signature against the exact input digest and public
   key, then confirms the operation is `completed` and Rekor state is `verified`.

Managed-key automation:

```console
trstctl-cli code-signing preview -f code-sign.json
trstctl-cli --idempotency-key release-sign-1 code-signing sign -f reviewed-code-sign.json
```

Keyless automation uses `code-signing keyless-preview` followed by
`code-signing keyless`. Put the returned `request_fingerprint` in the execution
body as `preview_fingerprint`; never put an OIDC proof in logs or evidence.

## Pitfalls & limits

- **Serving status:** code signing is reviewed at `POST /api/v1/code-signing/preview`
  and `POST /api/v1/code-signing/keyless/preview`, then served at
  `POST /api/v1/code-signing/sign` and `POST /api/v1/code-signing/keyless`, with
  matching `trstctl-cli code-signing preview`, `code-signing keyless-preview`,
  `code-signing sign`, and `code-signing keyless` commands. The shipped binary builds the
  service from `code_signing`, fails closed with `501` while that configuration is
  disabled, and fails closed at startup if an enabled configuration lacks an isolated
  signer, tenant-bound keys/attestors, or pinned Rekor log trust. Mutations require
  `Idempotency-Key` and `keys:write`; policy and distinct-approver enforcement engage
  when `ca.policy.enabled` / `ca.policy.require_approval` are set, otherwise RBAC plus
  signer purpose constraints are the authorization boundary. The TSA is served at
  `/tsa` when
  `protocols.tsa.enabled` plus `protocols.tsa.tenant_id` are set, returning
  `application/timestamp-reply` `TimeStampResp` bodies. The console readiness check
  is a preview, not a synthetic timestamp: only a real request to `/tsa` calls the
  signer and emits `tsa.timestamp.issued`.
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

- **Code signing:** `POST /api/v1/code-signing/preview`,
  `POST /api/v1/code-signing/keyless/preview`, `POST /api/v1/code-signing/sign`,
  `POST /api/v1/code-signing/keyless`, `GET /api/v1/code-signing/keys/{key_id}/certificate`,
  `POST /api/v1/code-signing/keys/{key_id}/csr`, `trstctl-cli code-signing keys certificate`,
  `trstctl-cli code-signing keys csr`, the `notation-trstctl` plugin, the `libtrstctl-pkcs11` module,
  the `trstctl-ksp` Windows provider and `trstctl-ksp-register`,
  `trstctl-cli code-signing preview`,
  `trstctl-cli code-signing keyless-preview`, `trstctl-cli code-signing sign`,
  `trstctl-cli code-signing keyless`, `Service.Sign`, `Service.SignKeyless`,
  `Verify`, `VerifyKeyless`.
- **Timestamping:** `Authority.Timestamp`, `Verify`, `VerifyLongTermValidity` (RFC 3161).
- **Events:** `codesign.commanded`, `codesign.completed`, `codesign.failed`,
  `codesign.ephemeral.destroyed`, `codesign.signed`, `codesign.refused`,
  `codesign.keyless.signed`, `codesign.csr_signed`, `attestation.verified`, `tsa.timestamp.issued`; worker
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
