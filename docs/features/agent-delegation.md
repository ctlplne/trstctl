# Agent delegation - chain-bound identities for AI agents

## What it is

Agent delegation lets an operator issue a short-lived agent credential only after an
isolated signer verifies a delegation chain. The simple version: a root principal delegates
a narrow slice of authority, each hop must be no broader than its parent, and the signer
checks the whole chain before any agent key is generated.

This is an Enterprise feature gated by the `agent-delegation` license feature. The free
single-hop attested workload credential path is separate and unchanged.

## Runtime pieces

The control plane owns the API, tenant-scoped PostgreSQL rows, event log, and outbox. The
signer owns private-key operations and reads only local public-trust files for AGID root
anchors, reachability-verdict signer keys, and attestation verifier keys; it does not
connect to SQL, NATS, or HTTP.

The root-anchor floor is:

```text
<signer key store dir>/agid-root-anchors/<tenant_id>/<key_id>.pem
<signer key store dir>/agid-root-anchors/<tenant_id>/<key_id>.authref
```

The reachability-verdict trust floor is:

```text
<signer key store dir>/agid-reach-verdict-keys/agentid-reach-verdict.der
```

The attestation verifier floor and spent-evidence replay floor are:

```text
<signer key store dir>/agid-attestors/<key_id>.der
<signer key store dir>/agid-attestor-spent/<evidence_digest>.spent
```

For the default child signer this is under `TRSTCTL_SIGNER_KEY_STORE_DIR`
(`data/signer/keys` by default). For an external signer, point the control plane at the
operator-managed directory that the signer can read, or provision the same files out of
band. Root-anchor files contain public key DER wrapped as PEM plus a non-secret auth
reference. The reachability-verdict and attestor files contain public key DER only. The
control plane holds the reachability-verdict signing handle, and the signer verifies the
verdict signature before issuing. The signer creates spent-evidence marker files before an
attested key operation completes, so replayed attestation evidence stays refused after
signer restart.

## Register a root anchor

Register or update a tenant root anchor:

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

`public_der` is also accepted as base64 JSON bytes. The route writes the tenant-scoped
`agent_root_anchors` row and, when `TRSTCTL_SIGNER_KEY_STORE_DIR` is configured, mirrors
the anchor into the signer floor. Replaying the same `Idempotency-Key` returns the original
result.

List the anchors visible to the tenant:

```http
GET /api/v1/agent-delegation/root-anchors
```

## Issue a chain-bound credential

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

The API enqueues `agentid.issue-chain-bound` in the durable outbox. The worker computes the
reachability verdict, calls the signer over `GatedIssue`, records the attestation binding,
and records the returned public credential material. The signer refuses before keygen if
the root anchor is absent, a hop widens authority, attestation fails, reachability is not
inside the ceiling, or the requested TTL exceeds the sub-hour ceiling.

After the worker drains the outbox, fetch the public signer-minted credential bytes:

```http
GET /api/v1/agent-delegation/credential?credential_id=...
```

Fetch the ordered delegation chain that relying parties can re-check offline:

```http
GET /api/v1/agent-delegation/chain?credential_id=...
```

## Revoke and inspect evidence

Queue a cascaded revocation:

```http
POST /api/v1/agent-delegation/revocations
Idempotency-Key: <stable revocation key>
Content-Type: application/json

{
  "subject": "agent:payments-reconciler",
  "reason": "compromise",
  "publish_downstream": true
}
```

Operators can then read:

- `GET /api/v1/agent-delegation/revocations/incomplete-jobs?directive_id=...`
- `GET /api/v1/agent-delegation/revocations/evidence?directive_id=...`
- `GET /api/v1/agent-delegation/credential?credential_id=...`
- `GET /api/v1/agent-delegation/chain?credential_id=...`

All mutation routes require `Idempotency-Key`; all storage is tenant-scoped with RLS; the
signer process keeps key material behind the signing boundary.
