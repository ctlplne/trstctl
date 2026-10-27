# Agent delegation — chain-bound identities for AI agents

## What it is

Agent delegation issues a short-lived credential to an AI agent only after the
isolated signer verifies a delegation chain: a root principal delegates a
narrow slice of authority, every hop must be no broader than its parent, and
the signer checks the whole chain before any agent key is generated.

Agent delegation is part of the core (`internal/agentid`, since 2026-09-20). Its
`/api/v1/agent-delegation/*` routes attach in every build through
`cmd/trstctl/attach_families.go` and appear in the running server's OpenAPI document.
The free single-hop attested workload credential path
([Workload identity](workload-identity.md), including the AI-agent broker at
`POST /api/v1/broker/agent-identities`) is separate and unchanged.

Served state: **Conditional** in the vocabulary
[Current limitations](../limitations.md) defines — the served path exists in the
running binary, but it is inert until the operator provisions the signer trust
floors listed below. Until then, a chain-bound request is refused rather than
issued unverified.

## Why it exists

Agents spawn agents. Without a chain rule, a leaf agent can end up holding
broader authority than the principal that started the chain — and nobody can
prove otherwise after the fact. Chain-bound issuance makes narrowing
mechanical: authority can only shrink hop by hop, the signer refuses to mint
when a hop widens, and relying parties can re-check the recorded chain
offline.

## How it works

The control plane owns the API, tenant-scoped PostgreSQL rows (RLS-isolated),
the event log, and the outbox. The signer owns private-key operations and
reads only local public-trust files; it has no SQL, NATS, or HTTP access. An
issuance request enqueues `agentid.issue-chain-bound` in the durable outbox;
the worker computes the reachability verdict, calls the signer over
`GatedIssue`, records the attestation binding, and stores the returned public
credential material. The signer refuses before keygen if the root anchor is
absent, a hop widens authority, attestation fails, reachability is outside
the ceiling, or the requested TTL exceeds the sub-hour ceiling.

The signer’s public-trust floors live under the **signer process's** key store
(`TRSTCTL_SIGNER_KEY_STORE_DIR`, default `data/signer/keys`). The root-anchor API
sends the tenant-bound public key to that signer over the authenticated signer
transport; the control plane does not write a local copy and assume it reached
the signer. For an external signer, configure its durable key store on the
signer host. The control plane seals one reachability-verdict private key under
its own `TRSTCTL_SIGNER_KEY_STORE_DIR` path using the deployment KEK. It sends
only that key's public DER over the authenticated signer transport and verifies
the signer's independent readback before starting AGID delivery. The signer
keeps the first public key for that key ID across restarts and rejects a changed
binding. Control-plane and signer paths can be separate volumes. Attestors reach
the signer the same way: the attestor API sends a tenant's attestor public key
and its attestation method over the authenticated signer transport and reads the
exact binding back. An operator can still place a deployment-wide attestor in
the signer's floor by hand; a tenant's own attestor under the same key ID decides
for that tenant:

```text
<signer key store dir>/agid-root-anchors/<tenant_id>/<key_id>.pem      # root anchor, public key DER wrapped as PEM
<signer key store dir>/agid-root-anchors/<tenant_id>/<key_id>.authref  # non-secret auth reference
<signer key store dir>/agid-reach-verdict-keys/agentid-reach-verdict.der  # RPC-provisioned public key
<signer key store dir>/agid-tenant-attestors/<tenant_id>/<key_id>.pem     # tenant attestor, RPC-provisioned
<signer key store dir>/agid-tenant-attestors/<tenant_id>/<key_id>.method  # the attestation method it vouches for
<signer key store dir>/agid-attestors/<key_id>.der                        # deployment-wide attestor, operator-provisioned
<signer key store dir>/agid-attestor-spent/<evidence_digest>.spent
<control-plane key store dir>/agid-control-plane/reachability-verdict-v1.sealed  # KEK-sealed private key
```

The signer floor files hold public material only. The control-plane sealed
private file never enters the signer volume. The signer verifies each verdict
signature against its first-writer public key before issuing. Spent-evidence
markers are written before an attested key
operation completes, so replayed attestation evidence stays refused across a
signer restart.

## Use it

Register a tenant root anchor. A `key_id` is bound to its first public key and
authentication reference: an identical request can be retried, while a changed
binding returns 409 and needs a new key ID. Supply exactly one public-key
source: `public_pem` as shown below, or `public_der` as base64 JSON bytes.
The console API playground includes a PEM placeholder; replace it with the
root principal's real **public** key before sending. Replaying the same
`Idempotency-Key` returns the original
result. A successful response reports `provisioned: true` only after an
independent read of the exact public key and authentication reference from the
signer. An immutable tenant/key event rebuilds the SQL registry after a crash.
If the signer is unavailable, retry the same request after it returns;
the event and tenant registry may already hold the first binding. A list response marks
an anchor unprovisioned when the signer readback is absent or differs:

```http
POST /api/v1/agent-delegation/root-anchors
Idempotency-Key: <stable operation key>
Content-Type: application/json

{
  "key_id": "root-key-1",
  "public_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "auth_ref": "webauthn:root-principal-credential"
}
```

Register the tenant's attestor: the service that checks a workload's raw
attestation (a TPM quote, a cloud instance identity document) and signs a
portable attestation the signer can verify offline. The request carries only the
attestor's **public** key and the one attestation method its evidence is for.
Like a root, a `key_id` keeps its first key and method: an identical request can
be retried, and a changed binding returns 409 and needs a new key ID. The
response reports the attestation `class` the method grants and
`provisioned: true` only after the signer read back the exact binding:

```http
POST /api/v1/agent-delegation/attestors
Idempotency-Key: <stable operation key>
Content-Type: application/json

{
  "key_id": "tpm-verifier-1",
  "method": "tpm",
  "public_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
}
```

The signer then verifies attestation evidence on this tenant's issuances against
this key. Evidence must name the registered method, cannot claim a class above
that method's (`software`, then `virtual-tpm` for cloud and workload identity
methods, `hardware-tpm`, `hsm`), and is never accepted for another tenant.

Issue a chain-bound credential:

```http
POST /api/v1/agent-delegation/issuances
Idempotency-Key: <stable issuance key>
Content-Type: application/json

{
  "agent_id": "agent:payments-reconciler",
  "trust_anchor_ref": "root-key-1",
  "designated_class": "agent-worker",
  "chain": "<base64 encoded preconditions body>",
  "agent_stack_repr": "<base64 encoded agent-stack JSON representation>",
  "attestation": "<base64 encoded evidence>",
  "attestation_method": "tpm",
  "scopes": ["read:invoices"],
  "resource_values": ["payments"],
  "ttl_seconds": 1200
}
```

After the worker drains the outbox, read the results; queue a cascaded
revocation when a subject is compromised:

```http
GET  /api/v1/agent-delegation/root-anchors
GET  /api/v1/agent-delegation/attestors
GET  /api/v1/agent-delegation/issuance?issuance_id=...  # follow the POST receipt to status and credential_id
GET  /api/v1/agent-delegation/credential?credential_id=...
GET  /api/v1/agent-delegation/credential-status?credential_id=...  # active, revoked, expired or unknown
GET  /api/v1/agent-delegation/chain?credential_id=...
GET  /api/v1/agent-delegation/issuing-ca         # the tenant's issuing CA, for relying services to pin
POST /api/v1/agent-delegation/revocations        # {"subject":"agent:...","reason":"compromise","publish_downstream":true}
GET  /api/v1/agent-delegation/revocations/incomplete-jobs?directive_id=...
GET  /api/v1/agent-delegation/revocations/evidence?directive_id=...
```

The downloadable `trstctl-cli` exposes the same thirteen routes. Set
`TRSTCTL_SERVER`, `TRSTCTL_TOKEN`, `TRSTCTL_TENANT`, and `TRSTCTL_CA_FILE` for
the deployment, then use a stable idempotency key for each mutation. Request
JSON can be supplied from a private file or standard input; the CLI does not
store or print the bearer token. Query IDs are required locally before a read
is sent, including IDs containing a slash:

```sh
trstctl-cli agent-delegation roots list
trstctl-cli --idempotency-key root-qa-1 agent-delegation roots register -f root-anchor.json
trstctl-cli agent-delegation attestors list
trstctl-cli --idempotency-key attestor-qa-1 agent-delegation attestors register -f attestor.json
trstctl-cli --idempotency-key issue-qa-1 agent-delegation issue -f issuance.json
trstctl-cli agent-delegation issuance get --issuance_id '<issuance_id from the 202 receipt>'
trstctl-cli agent-delegation credential get --credential_id '<credential_id from the issued result>'
trstctl-cli agent-delegation credential status --credential_id '<credential_id from the issued result>'
trstctl-cli agent-delegation issuing-ca get
trstctl-cli agent-delegation chain get --credential_id '<credential_id from the issued result>'
trstctl-cli --idempotency-key revoke-qa-1 agent-delegation revoke -f revocation.json --force
trstctl-cli agent-delegation revocations incomplete-jobs --directive_id directive-1
trstctl-cli agent-delegation revocations evidence --directive_id directive-1
```

## Relying services

A relying service is whatever an agent calls with its credential: a tool
server, an API, another agent. It decides each call itself, from material it
pinned and two reads:

1. **Pin the tenant's issuing CA.** `GET /api/v1/agent-delegation/issuing-ca`
   returns the certificate of the CA that certifies this tenant's agent
   credentials, and its `spki_sha256`. Each tenant has its own CA, so a pinned
   CA never honors another tenant's credentials. Its key is held by the signer
   and survives restarts; the certificate is re-issued over the same key before
   it expires, so `spki_sha256` is the durable pin. Pin the tenant's root
   anchors (`GET /api/v1/agent-delegation/root-anchors`) too.
2. **Verify offline.** Check the presented credential (X.509 DER) against the
   pinned CA with trstctl's relying-party verifier
   (`internal/agentid/verify`): it confirms the signature, that the bound agent
   stack is one you approved, that the requested tool is in the bound tool
   manifest, and that the bound authority class may perform the operation.
3. **Bind the credential to the caller.** The credential's key stays in the
   signer, so it is not a proof of possession. Authenticate the agent with its
   own identity (an X.509-SVID from the agent identity broker, over mutual
   TLS), read the credential's chain once
   (`GET /api/v1/agent-delegation/chain`), verify it hop by hop from a pinned
   root to the chain head the credential binds, and require its final delegate
   to be the authenticated agent.
4. **Check status.** `GET /api/v1/agent-delegation/credential-status` reports
   `active`, `revoked` (a revocation's cascade recorded a job against the
   credential; `revocation_evidenced` turns true once the job's effect is
   recorded with signed evidence), `expired`, or `unknown`. Honor only
   `active`, and compare `credential_sha256` with the credential presented.
   The answer is never cached by HTTP (`Cache-Control: no-store`); reuse it for
   a bounded window you choose.

A revoked delegation stops working at a relying service within the time the
revocation's cascade takes to reach the credential (the outbox dispatcher sweeps
once a second, so normally a second or two) plus that service's status reuse
window. Without a status check, an outstanding credential stays usable until it
expires, at most its sub-hour TTL. The relying service needs a token scoped
only to `agents:read`.

Two reference integrations do all of the above with open-source agent
frameworks, unmodified: an MCP tool server on the MCP Go SDK and an agent on the
Agent Development Kit for Go, under `test/interop/agentframeworks`. Their lab
test runs them against the real signer: the in-scope call is honored, an
out-of-scope call and the same credential presented by another agent are
refused, a revocation stops calls within the two-second status window the lab
configures, and the tool server's audit log records the delegation path behind
every decision.

## Pitfalls & limits

- Provisioning-gated: the routes attach in every build, but a chain-bound request
  is refused until the signer trust floors above are provisioned.
- The TTL ceiling is sub-hour by design; a request above it is refused, not
  clamped.
- Register root anchors through the API, CLI, or console. The signer stores its
  public root floor under its own durable key store; an absent anchor is a
  refusal, not a fallback. The control plane provisions and reads back the
  reachability public floor and each tenant attestor over the authenticated
  signer RPC. A list response marks an attestor unprovisioned when the signer
  readback is absent or differs; registering the same binding again
  re-provisions it, for example after the signer volume was replaced.
- A deployment-wide attestor placed by hand under `agid-attestors/` still
  serves every tenant that has not registered the same key ID, with no method
  binding. Prefer tenant registration: it is recorded, rebuilt after read-model
  loss, and bound to one method.
- At upgrade, a pre-event root row gains a registered authority event only
  after the isolated signer returns the exact tenant, key, public key, and
  authentication reference. An explicit signer `NotFound` records the old
  public tuple as **unprovisioned** history; the root remains visible with
  `provisioned: false` after restart and read-model rebuild, and cannot
  authorize issuance. A different signer tuple or signer transport failure
  still blocks startup. A one-shot rebuild refuses a SQL-only row until a
  paired signer/control-plane start records one of those two source facts.
  An operator can provision an unprovisioned root by registering the exact
  public tuple through the normal API, CLI, or console path. If the signer
  floor is restored separately, paired startup independently checks the exact
  tuple and records a registered event before treating it as authority.
- The chain is verified by the signer, not the API: a compromised control
  plane cannot mint a widened credential.
- An issuance POST is only a queue acknowledgement. Follow its `status_url`
  until status is `issued`, then use the returned `credential_id` for the public
  credential and chain. `pending` can be retried, `failed` needs operator
  recovery, and `result_unavailable` means delivery or the immutable result
  exists but the exact public credential is not readable. The status read never
  guesses a result from another request naming the same agent. Historical
  credentials issued before receipt binding have no invented receipt mapping.

## Reference

- **Mutations** (all require `Idempotency-Key`):
  `POST /api/v1/agent-delegation/root-anchors`, `.../attestors`,
  `.../issuances`, `.../revocations`.
- **Reads:** `.../root-anchors`, `.../attestors`, `.../issuance?issuance_id=`, `.../credential?credential_id=`,
  `.../credential-status?credential_id=`, `.../chain?credential_id=`, `.../issuing-ca`,
  `.../revocations/incomplete-jobs?directive_id=`, `.../revocations/evidence?directive_id=`.
- **Outbox job:** `agentid.issue-chain-bound`; signer calls: `GatedIssue`,
  `GetAgentIssuingCA`.
- **Trust floors:** the key-store layout above; all tenant-scoped storage is
  RLS-isolated, and key material never leaves the signing boundary.

## See also

[Workload identity](workload-identity.md) (the free attestation chain and
AI-agent broker) · [Signing service design](../design/signing-service.md) ·
[Editions](../editions.md) · [Current limitations](../limitations.md)
