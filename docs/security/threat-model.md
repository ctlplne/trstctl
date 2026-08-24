# Product threat model

This is the product-level threat model for trstctl. It complements the deeper
[signing service design & threat model](../design/signing-service.md), which
covers that component in full; here we model the whole control plane —
assets, trust boundaries, adversaries, and the guarantees that back those
defenses.

> trstctl is pre-1.0; this model describes the architecture as built. What is
> served by the running binary versus library-level is documented in
> [Current limitations](../limitations.md).

## Assets

- **CA private keys** — the crown jewels; whoever holds one can mint trust.
- Leaf private keys and secrets — credential material in transit.
- The event log — the source of truth; its integrity defines all state.
- The audit trail — tamper-evidence and attribution for every change.
- Tenant isolation — one tenant must never read or affect another.

## Trust boundaries (and the guarantees behind them)

- **Signer process boundary.** Private-key operations run in a separate
  process, reached over gRPC on a Unix domain socket, with no HTTP server and
  no SQL driver. Compromising the control plane does not yield the CA key;
  the signer is the bulkhead around the crown jewels.
- Cryptography boundary. All cryptographic operations route through a
  single isolated path; nothing else touches crypto primitives directly,
  so the attack surface for misuse is one auditable module.
- Tenant boundary. Every row carries a `tenant_id`; isolation is enforced
  by PostgreSQL row-level security, not application code, and fails
  closed — an unset tenant sees nothing.
- Memory boundary for key material. Secrets live in locked, zeroed, wipeable
  buffers, never plain strings, in RAM only briefly.
- Secrets at rest (R3.1). Upstream CA and connector credentials are stored
  envelope-encrypted: a per-credential, tenant-bound data key (AES-256-GCM)
  encrypts the secret, wrapped by a key-encryption key — local today, HSM/KMS
  tomorrow. The database holds ciphertext only; plaintext never reaches
  config dumps, logs, or errors.
- Network boundary. The served API is TLS by default (R1.3) and fails closed
  without auth (R1.2: API tokens / OIDC sessions, RBAC); bulkheads and rate
  limits keep one caller from starving the rest.

## Integrity & attribution

- Event-sourced state. The append-only event log is authoritative; the read
  model and audit trail are projections of it, so state can be rebuilt and
  re-derived independently.
- Idempotency + outbox. Every mutation takes an idempotency key; every
  external call writes to a journaled outbox in the same transaction as the
  state change, so a retried issuance cannot mint two certificates and
  effects stay exactly-once.
- **Tamper-evident audit (R2.1).** Audit records form a hash-linked chain
  signed with a persistent key and carry the acting principal; `VerifyChain`
  detects any reordering, omission, or edit.

## Adversaries and mitigations (STRIDE, abbreviated)

- Spoofing — TLS + token/OIDC auth, fail-closed; signer peer authentication.
- Tampering — event-sourcing + the hash-linked signed audit chain; RLS.
- Repudiation — every event records its actor; the audit chain is verifiable.
- Information disclosure — RLS tenant isolation; wipeable secret memory;
  redacted logs/config.
- Denial of service — bounded per-subsystem lanes + rate limiting; pools shed
  fast.
- Elevation of privilege — RBAC; the signer boundary (a compromised control
  plane is not a compromised CA key).

## Out of scope / residual risk (honest)

- **CA-key custody at rest.** The issuing CA key is persisted, sealed at rest
  in the signer's key store and preserved across restarts (R3.2); Helm
  `externalKMS` can wrap the key-store DEKs via an operator-supplied KMS/HSM
  adapter. Break-glass issue/rotation/cross-signing binds tenant-scoped
  requests to single-use, quorum-authenticated ceremonies; private operations
  stay in the separate signer.
  Reconciliation is served at `POST /api/v1/breakglass/reconcile` and
  recorded as `breakglass.issued` audit events
  ([limitations](../limitations.md),
  [incident response](../runbooks/incident-response.md)).
- **Plugin trust model & blast radius.** The shipped first-party CA and
  connector integrations run as trusted in-process Go code, not in the WASM
  sandbox, so their blast radius if one is defective or malicious is the
  control plane's own address space: the PostgreSQL connection pool (still
  RLS-scoped per tenant), the signer *client* handle (which can request
  signatures over the peer-authenticated UDS channel), and credential
  material in flight — never the CA private key itself, which stays in the
  separate signer process. Mitigations: code review, the conformance suite,
  the connector SDK's capability-scoped `Sandbox` facade, and bounded
  per-subsystem lanes. WASM isolation (wazero) — no ambient capabilities, no
  DB pool or signer handle, contained by test — is reserved for third-party
  plugins; moving first-party integrations into that sandbox is future work
  ([limitations](../limitations.md)).
- Host & operator security. trstctl assumes a reasonably trusted host, with
  custodians/operators protecting their own credentials.

## Reporting

Security issues: use the [private disclosure process](reporting.md).
