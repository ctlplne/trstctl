# Agent delegation — chain-bound identities for AI agents

## What it is

Agent delegation issues a short-lived credential to an AI agent only after the
isolated signer verifies a delegation chain: a root principal delegates a
narrow slice of authority, every hop must be no broader than its parent, and
the signer checks the whole chain before any agent key is generated.

This is a licensed Enterprise capability (the `agent-delegation` license
feature) implemented under `ee/`. Its `/api/v1/agent-delegation/*` routes are
attached only when the license is present and are not part of the MPL-core
OpenAPI document. The free single-hop attested workload credential path
([Workload identity](workload-identity.md), including the AI-agent broker at
`POST /api/v1/broker/agent-identities`) is separate and unchanged.

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

The signer's public-trust floors live under the signer key store
(`TRSTCTL_SIGNER_KEY_STORE_DIR`, default `data/signer/keys`; for an external
signer, provision the same files where the signer can read them):

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

Register (or update) a tenant root anchor. `public_der` as base64 JSON bytes
is also accepted; replaying the same `Idempotency-Key` returns the original
result, and when `TRSTCTL_SIGNER_KEY_STORE_DIR` is configured the anchor is
mirrored into the signer floor:

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

## Pitfalls & limits

- Licensed and gated: without the `agent-delegation` license feature the
  routes are not attached. This page describes the EE build, not MPL core.
- The TTL ceiling is sub-hour by design; a request above it is refused, not
  clamped.
- Root-anchor and attestor floors are operator-provisioned files — an absent
  anchor is a refusal, not a fallback.
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
