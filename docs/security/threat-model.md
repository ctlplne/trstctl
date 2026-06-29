# Product threat model

This is the product-level threat model for trstctl. It complements — and does not
replace — the deeper, security-critical
[signing service design & threat model](../design/signing-service.md), which covers
the single most sensitive component in full. Here we model the whole control plane:
its assets, trust boundaries, the adversaries it defends against, and the
architectural guarantees that back those defenses.

> trstctl is pre-1.0; this model describes the architecture as built. What is
> served by the running binary versus library-level is in
> [Current limitations](../limitations.md), and informs the "exposure" column
> below.

## Assets

- **CA private keys** — the crown jewels; whoever holds one can mint trust.
- **Leaf private keys and secrets** — credential material in transit through the
  platform.
- **The event log** — the source of truth; its integrity defines all state.
- **The audit trail** — tamper-evidence and attribution for every change.
- **Tenant isolation** — one tenant must never read or affect another.

## Trust boundaries (and the guarantees behind them)

- **Signer process boundary.** Private-key operations run in a separate
  process with its own address space, reached over gRPC on a Unix domain socket (or
  mTLS across nodes), with no HTTP server and no SQL driver. Compromising the
  control plane does not by itself yield the CA key; the signer is the bulkhead
  around the crown jewels. Full detail:
  [signing service design](../design/signing-service.md).
- **Cryptography boundary.** All cryptographic operations route through a
  single isolated path; nothing else touches the low-level crypto primitives. The
  attack surface for crypto misuse is one auditable module, and adding an HSM/KMS is
  one change there.
- **Tenant boundary.** Every row carries a `tenant_id`; isolation is enforced
  by PostgreSQL row-level security, not application code, and fails **closed** (an
  unset tenant sees nothing). A forgotten `WHERE` cannot leak across tenants — the
  architecture linter blocks repository queries that don't filter on `tenant_id`.
- **Memory boundary for key material.** Secrets live in locked, zeroed, wipeable
  buffers, never plain strings; they exist in RAM for milliseconds, not indefinitely.
- **Secrets at rest (R3.1).** Upstream CA and connector credentials are stored
  **envelope-encrypted**: a per-credential data key
  encrypts the secret (AES-256-GCM, bound to its tenant/identity), and a
  key-encryption key — a local key today, an HSM/KMS tomorrow — wraps the data key.
  The database holds ciphertext only; plaintext never reaches config dumps, logs,
  or errors.
- **Network boundary.** The served API is TLS by default (R1.3) and fails closed
  without auth (R1.2: API tokens / OIDC sessions, RBAC); bulkheads and per-tenant
  rate limiting keep one caller from starving the rest.

## Integrity & attribution

- **Event-sourced state.** The append-only event log is authoritative; the
  relational read model and the audit trail are projections of it, so state can be
  rebuilt and independently re-derived.
- **Idempotency + outbox.** Every mutation takes an idempotency key and
  every external call is written to a journaled outbox in the same transaction as the
  state change — a retried issuance cannot mint two certificates, and effects are
  exactly-once.
- **Tamper-evident audit (R2.1).** Audit records form a hash-linked chain signed
  with a persistent key and carry the acting principal; `VerifyChain` detects any
  reordering, omission, or edit.

## Adversaries and mitigations (STRIDE, abbreviated)

- **Spoofing** — TLS + token/OIDC auth, fail-closed; signer peer authentication.
- **Tampering** — event-sourcing + the hash-linked signed audit chain; RLS.
- **Repudiation** — every event records its actor; the audit chain is verifiable.
- **Information disclosure** — RLS tenant isolation; wipeable secret-memory
  handling; redacted logs and config output.
- **Denial of service** — bounded per-subsystem lanes + per-tenant rate limiting;
  pools shed fast.
- **Elevation of privilege** — RBAC; the signer boundary (a compromised control
  plane is not a compromised CA key).

## Out of scope / residual risk (honest)

- **CA-key custody at rest.** The issuing CA key is **persisted, sealed at rest** in
  the signer's key store and **preserved across restarts** (R3.2). Helm
  `externalKMS` can wrap the signer key-store DEKs through an operator-supplied
  KMS/HSM adapter instead of mounting the local signer KEK. What remains future
  work is non-extractable HSM/KMS-resident CA private keys and online m-of-n
  break-glass issuance. Recovery reconciliation of signed break-glass bundles is
  served at `POST /api/v1/breakglass/reconcile` and records
  `breakglass.issued` audit events ([limitations](../limitations.md),
  [incident response](../runbooks/incident-response.md)).
- **Plugin trust model & blast radius.** The shipped first-party CA and connector
  integrations run as **trusted in-process Go code**, not in the WASM sandbox. Their
  **blast radius** if one is defective or malicious is therefore the control plane's
  own address space: the PostgreSQL connection pool (the application role, still
  RLS-scoped per tenant), the signer *client* handle (it can **request** signatures
  over the peer-authenticated UDS channel), and any credential material in flight. It is **not**
  the CA private key — that stays in the separate signer process, so even a
  compromised connector cannot exfiltrate it. Mitigations: code review, the
  conformance suite, the connector SDK's capability-scoped `Sandbox` facade (each
  connector receives only the operations it declares), and the bounded per-subsystem
  lanes. The genuine WASM isolation (wazero) is the boundary for
  **third-party** plugins — a loaded plugin has no ambient capabilities and only the
  host functions its grant permits, the host holds no DB pool or signer handle, and
  a deliberately misbehaving plugin is proven contained by test. Moving the
  first-party integrations into that sandbox is future work
  ([limitations](../limitations.md)).
- **Host & operator security.** trstctl assumes a reasonably trusted host and that
  custodians/operators protect their own credentials.

## Reporting

Security issues: see
[SECURITY.md](https://github.com/ctlplne/trstctl/blob/main/SECURITY.md) for
the private disclosure process and contact.
