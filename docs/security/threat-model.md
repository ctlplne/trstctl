# Product threat model

This is the product-level threat model for certctl. It complements — and does not
replace — the deeper, security-critical
[signing service design & threat model](../design/signing-service.md), which covers
the single most sensitive component in full. Here we model the whole control plane:
its assets, trust boundaries, the adversaries it defends against, and the
architectural guarantees (the **AN-1…AN-8** non-negotiables) that back those
defenses.

> certctl is pre-1.0; this model describes the architecture as built. What is
> served by the running binary versus library-level is in
> [Current limitations](../limitations.md), and informs the "exposure" column
> below.

## Assets

- **CA private keys** — the crown jewels; whoever holds one can mint trust.
- **Leaf private keys and secrets** — credential material in transit through the
  platform.
- **The event log** — the source of truth (AN-2); its integrity defines all state.
- **The audit trail** — tamper-evidence and attribution for every change.
- **Tenant isolation** — one tenant must never read or affect another.

## Trust boundaries (and the guarantees behind them)

- **Signer process boundary (AN-4).** Private-key operations run in a separate
  process with its own address space, reached over gRPC on a Unix domain socket (or
  mTLS across nodes), with no HTTP server and no SQL driver. Compromising the
  control plane does not by itself yield the CA key; the signer is the bulkhead
  around the crown jewels. Full detail:
  [signing service design](../design/signing-service.md).
- **Cryptography boundary (AN-3).** All cryptographic operations route through a
  single package; nothing else imports `crypto/*`. The attack surface for crypto
  misuse is one auditable module, and adding an HSM/KMS is one change there.
- **Tenant boundary (AN-1).** Every row carries a `tenant_id`; isolation is enforced
  by PostgreSQL row-level security, not application code, and fails **closed** (an
  unset tenant sees nothing). A forgotten `WHERE` cannot leak across tenants — the
  architecture linter blocks repository queries that don't filter on `tenant_id`.
- **Memory boundary for key material (AN-8).** Secrets live in locked, zeroed
  `[]byte`, never `string`; they exist in RAM for milliseconds, not indefinitely.
- **Secrets at rest (R3.1).** Upstream CA and connector credentials are stored
  **envelope-encrypted** (`internal/crypto/seal`): a per-credential data key
  encrypts the secret (AES-256-GCM, bound to its tenant/identity), and a
  key-encryption key — a local key today, an HSM/KMS tomorrow — wraps the data key.
  The database holds ciphertext only; plaintext never reaches config dumps, logs,
  or errors.
- **Network boundary.** The served API is TLS by default (R1.3) and fails closed
  without auth (R1.2: API tokens / OIDC sessions, RBAC); bulkheads and per-tenant
  rate limiting (AN-7) keep one caller from starving the rest.

## Integrity & attribution

- **Event-sourced state (AN-2).** The append-only event log is authoritative; the
  relational read model and the audit trail are projections of it, so state can be
  rebuilt and independently re-derived.
- **Idempotency + outbox (AN-5, AN-6).** Every mutation takes an idempotency key and
  every external call is written to an outbox in the same transaction as the state
  change — a retried issuance cannot mint two certificates, and effects are
  exactly-once.
- **Tamper-evident audit (R2.1).** Audit records form a hash-linked chain signed
  with a persistent key and carry the acting principal; `VerifyChain` detects any
  reordering, omission, or edit.

## Adversaries and mitigations (STRIDE, abbreviated)

- **Spoofing** — TLS + token/OIDC auth, fail-closed; signer peer authentication.
- **Tampering** — event-sourcing + the hash-linked signed audit chain; RLS.
- **Repudiation** — every event records its actor; the audit chain is verifiable.
- **Information disclosure** — RLS tenant isolation; AN-8 memory handling; redacted
  logs and config output.
- **Denial of service** — AN-7 bulkheads + per-tenant rate limiting; bounded pools
  shed fast.
- **Elevation of privilege** — RBAC; the signer boundary (a compromised control
  plane is not a compromised CA key).

## Out of scope / residual risk (honest)

- **CA-key custody at rest.** The assembled issuing CA key is RAM-generated and not
  yet persisted to an HSM/sealed store; persistent custody and a served break-glass
  flow are future work ([limitations](../limitations.md),
  [incident response](../runbooks/incident-response.md)).
- **In-process integrations.** CA and connector integrations are trusted in-process
  Go code today; the WASM sandbox exists but the integrations are not yet isolated
  through it.
- **Host & operator security.** certctl assumes a reasonably trusted host and that
  custodians/operators protect their own credentials.

## Reporting

Security issues: see
[SECURITY.md](https://github.com/imfeelingtheagi/certctl/blob/main/SECURITY.md) for
the private disclosure process and contact.
