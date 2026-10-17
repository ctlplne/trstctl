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
signer host. Its reachability and attestor trust floors still need operator
provisioning at that signer:

```text
<signer key store dir>/agid-root-anchors/<tenant_id>/<key_id>.pem      # root anchor, public key DER wrapped as PEM
<signer key store dir>/agid-root-anchors/<tenant_id>/<key_id>.authref  # non-secret auth reference
<signer key store dir>/agid-reach-verdict-keys/agentid-reach-verdict.der
<signer key store dir>/agid-attestors/<key_id>.der
<signer key store dir>/agid-attestor-spent/<evidence_digest>.spent
```

All floor files hold public material only. The control plane holds the
reachability-verdict signing handle; the signer verifies the verdict signature
before issuing. Spent-evidence markers are written before an attested key
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
GET  /api/v1/agent-delegation/credential?credential_id=...
GET  /api/v1/agent-delegation/chain?credential_id=...
POST /api/v1/agent-delegation/revocations        # {"subject":"agent:...","reason":"compromise","publish_downstream":true}
GET  /api/v1/agent-delegation/revocations/incomplete-jobs?directive_id=...
GET  /api/v1/agent-delegation/revocations/evidence?directive_id=...
```

The downloadable `trstctl-cli` exposes the same eight routes. Set
`TRSTCTL_SERVER`, `TRSTCTL_TOKEN`, `TRSTCTL_TENANT`, and `TRSTCTL_CA_FILE` for
the deployment, then use a stable idempotency key for each mutation. Request
JSON can be supplied from a private file or standard input; the CLI does not
store or print the bearer token. Query IDs are required locally before a read
is sent, including IDs containing a slash:

```sh
trstctl-cli agent-delegation roots list
trstctl-cli --idempotency-key root-qa-1 agent-delegation roots register -f root-anchor.json
trstctl-cli --idempotency-key issue-qa-1 agent-delegation issue -f issuance.json
trstctl-cli agent-delegation credential get --credential_id 'agent:qa/credential'
trstctl-cli agent-delegation chain get --credential_id 'agent:qa/credential'
trstctl-cli --idempotency-key revoke-qa-1 agent-delegation revoke -f revocation.json --force
trstctl-cli agent-delegation revocations incomplete-jobs --directive_id directive-1
trstctl-cli agent-delegation revocations evidence --directive_id directive-1
```

## Pitfalls & limits

- Provisioning-gated: the routes attach in every build, but a chain-bound request
  is refused until the signer trust floors above are provisioned.
- The TTL ceiling is sub-hour by design; a request above it is refused, not
  clamped.
- Register root anchors through the API, CLI, or console. The signer stores its
  public root floor under its own durable key store; an absent anchor is a
  refusal, not a fallback. Reachability and attestor public floors still need
  operator provisioning at the signer.
- At upgrade, a pre-event root row gains an immutable event only after the
  isolated signer returns the exact tenant, key, public key, and authentication
  reference. A missing or different signer floor blocks startup. A one-shot
  rebuild refuses a SQL-only legacy row; start the paired signer/control plane
  to reconcile it before invoking rebuild or restore.
- The chain is verified by the signer, not the API: a compromised control
  plane cannot mint a widened credential.

## Reference

- **Mutations** (all require `Idempotency-Key`):
  `POST /api/v1/agent-delegation/root-anchors`, `.../issuances`,
  `.../revocations`.
- **Reads:** `.../root-anchors`, `.../credential?credential_id=`,
  `.../chain?credential_id=`, `.../revocations/incomplete-jobs?directive_id=`,
  `.../revocations/evidence?directive_id=`.
- **Outbox job:** `agentid.issue-chain-bound`; signer call: `GatedIssue`.
- **Trust floors:** the key-store layout above; all tenant-scoped storage is
  RLS-isolated, and key material never leaves the signing boundary.

## See also

[Workload identity](workload-identity.md) (the free attestation chain and
AI-agent broker) · [Signing service design](../design/signing-service.md) ·
[Editions](../editions.md) · [Current limitations](../limitations.md)
