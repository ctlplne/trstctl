# Secrets — store, issue, rotate, and encrypt the credentials machines use

## What it is

A [secret](../glossary.md) is any sensitive value software needs but shouldn't expose:
a database password, an API token, an encryption key. trstctl is a full secrets
platform alongside its certificate work — it stores secrets encrypted, hands out
short-lived ones on demand, rotates them safely, encrypts data on behalf of apps,
syncs secrets to other platforms, and governs who can read or change them.

The mental model: think of a bank. The **vault** stores valuables encrypted (the secret
store). The **safe-deposit clerk** issues a temporary key that self-destructs after an
hour (dynamic secrets). The **armored-car service** moves valuables to other branches
(secret sync). The **teller window** encrypts your deposit without you ever seeing the
master key (encryption-as-a-service). And every action needs ID and is logged
(auth + approvals + audit).

> **One honest note up front.** Most of the *secrets* domain is now **served**: the
> **secret store** (CRUD + rotation), **one-time secret sharing**, the **dynamic PKI
> secret**, and **machine login** are mounted on the running control plane under
> `/api/v1/secrets/*` (off by default — `secrets.enable_api` — and fail-closed when off).
> **Secret-sync to external stores** is still built-and-tested **library** code with no
> served surface yet. So most of this page is a live endpoint today; sync you still drive
> via its programmatic APIs. See [Current limitations](../limitations.md). This page is
> honest about that throughout.

## Why it exists

Leaked secrets are one of the most common breach causes, because the traditional
approach — long-lived secrets copied into config files, environment variables, images,
and CI — spreads them everywhere and never expires them. trstctl attacks the problem
from every side: encrypt them properly at rest, prefer short-lived/dynamic secrets that
can't be hoarded, rotate the long-lived ones automatically, never let a secret value
touch a log or a disk it shouldn't, and put approvals and a tamper-evident audit trail
around access. Secret material is always held in wipeable `[]byte` buffers that are
zeroed after use, never a Go `string` (Go can copy strings freely, so a value placed in
one can linger in memory beyond your control).

## How it works

### How every secret is encrypted at rest

trstctl uses **[envelope encryption](../glossary.md)**, and all of it runs through the
single isolated cryptography path. Each secret is encrypted with a fresh per-secret data
key (DEK, AES-256-GCM), and that DEK is itself encrypted under a master key-encryption key
(KEK). The encryption is bound to the secret's tenant and path, so a sealed blob can't be
moved elsewhere. The KEK is loaded at startup from `TRSTCTL_SECRETS_KEK_FILE` (0600),
held only transiently, and zeroized. To rotate protection you re-wrap small DEKs, not all
your data.

### The native secret store (F63)

A versioned key-value store: every `Put` creates a new version (old versions stay
queryable), `Delete` writes a tombstone (history is retained), and the whole version list
can be **reconstructed from the event log** — every change is recorded as an immutable
event, and the store is a projection rebuilt from that history, never a primary write.
Writes are idempotent by key (a retry refreshes the same version instead of writing a
second), tenant-isolated with cross-tenant denial (one tenant can never read another's
secrets, enforced at the database layer), and the ready-to-mount `APIServer` enforces
per-secret RBAC.

The credential store the running control plane mounts is the **served seal path**: it
seals through a versioned binary container, and its key-encryption key is loaded into
locked, zeroizable memory at startup — never held as a raw byte slice on the heap.

An older store core is retained for **legacy event replay and compatibility**. It now also
holds its KEK behind the same locked-memory boundary and seals with the binary container,
and its reconstruction still replays both the current container and earlier
JSON-envelope history; new production writes go through the served seal path above, not
here.

### The developer secrets experience (F64)

Two pieces make secrets pleasant *and* safe for developers. A CLI **injector** runs your
program with secrets in its environment without ever writing them to disk (only the
variable *names* are audited, never values). An **SDK** caches secrets and auto-refreshes
them before expiry, and on a revocation it evicts the cache and fails safe rather than
serving a stale, revoked secret.

### Dynamic secrets (F65) and PKI-as-a-secrets-engine (F67)

Instead of a long-lived secret to steal, **dynamic secrets** are minted on demand,
scoped, and time-limited by a [lease](../glossary.md); when the lease expires trstctl
revokes the underlying credential automatically — even across a restart, because the
revocation intent is journaled first to a durable [outbox](../glossary.md) and delivered
at-least-once, so a crash can't silently drop it. Seven backends ship behind one
interface: PostgreSQL, MySQL, MongoDB, AWS STS, GCP IAM, Azure service principal, and
Redis/SSH; all pass a lifecycle conformance test. **PKI-as-a-secrets-engine** plugs the
same lease machinery into certificate issuance — a developer requests a short-lived
certificate exactly like a database password, and the leaf key is generated in wipeable
memory and zeroed immediately after use.

### Secret rotation (F37)

The rotation engine replaces a long-lived secret in **four rollback-safe phases**: stage
the new version, cut consumers over, verify they're healthy, retire the old one. If
cutover or verification fails, it **automatically rolls back** so the application is never
left broken. If backend rollback itself fails, the report sets `RollbackAttempted` and
`RollbackFailed`, leaves `RolledBack` false, and audits `rotation.rollback_failed` so
operators know the consumer may be on the new secret and needs intervention. Each phase is
audited and, in production, delivered via the outbox so a crash mid-rotation strands
nothing.

### Ephemeral API keys (F38)

For high-churn automation, trstctl issues short-lived credentials gated by
[attestation](workload-identity.md): prove what you are, get a sub-hour credential,
let it expire (no CRL needed). Every request takes an `Idempotency-Key` so a retry never
mints twice, and nothing is minted unless attestation verifies.

### Encryption-as-a-service & KMIP (F66)

The **transit** library encrypts, decrypts, HMACs, and signs data using named keys the
application *never sees* — ciphertexts are versioned (`trv:<version>:...`) so a key
rotation can re-wrap old data, and intermediate plaintext is held in wipeable memory and
zeroed after use. For legacy enterprise gear (databases, storage arrays), the **KMIP**
library has a bounded TTLV RequestMessage parser plus TLS client-cert-authenticated
operation model with key material zeroed on destroy. No served transit or KMIP API/CLI
surface exists yet; the console marks it library-only until a listener is mounted.

### Secret sync (F68)

trstctl can push secrets *outward* to the platforms that need them — Kubernetes, GitHub
Actions, GitLab CI, Terraform, Vercel, AWS Parameter Store, or a generic webhook — via the
durable outbox (journaled first, delivered at-least-once, no half-writes), and it
**detects drift** by comparing hashes when a target is changed out-of-band.

### The auth-method framework (F58)

Before a workload can read a secret, it has to authenticate *to* trstctl. The auth-method
framework is that login layer: a workload presents a credential (a token, an OIDC JWT, a
Kubernetes SA token, cloud IAM, etc.), trstctl verifies it through the single isolated
cryptography path (timing-safe), and issues a scoped, time-bounded **session**. Credential
bytes are never logged (held in wipeable memory, never a copyable string); every attempt
is recorded as an immutable event in the tamper-evident log.

### Secret scanning bridge (F39) and sharing & approvals (F60)

The **scanning bridge** ingests findings from gitleaks and trufflehog into the
[credential graph](graph-query-ai.md) and risk view — structurally excluding the secret
value (the parsers never read it) — and can auto-trigger the
[compromise workflow](incident-and-jit.md). **Secret sharing** creates one-time,
self-destructing links (viewed once, then deleted; expiry-bounded), and **change
approvals** put a dual-control [approval](incident-and-jit.md) gate on secret mutations.

## Use it

These run through their Go APIs today. The shapes:

```go
// Native store: versioned, envelope-encrypted put/get
store.Put(ctx, "db/password", []byte("s3cr3t"), "idem-key")   // -> version 1
val, _ := store.Get(ctx, "db/password")                        // latest live version

// Dynamic secret: a 1-hour Postgres credential, auto-revoked at lease end
lease, _ := dyn.Issue(ctx, "postgresql", "readonly", time.Hour, "req-1")

// Transit: encrypt without the app ever holding the key
ct, _ := keyring.Encrypt(ctx, "app-key", []byte("hello"), nil) // -> "trv:1:..."
```

The `secretstore.APIServer` exposes the store over HTTP (`PUT/GET /secrets/<path>`, with
`Idempotency-Key` and tenant headers) once mounted.

## Pitfalls & limits

- **Serving status:** the secret store, one-time sharing, the dynamic PKI secret, and
  machine login are **served** on the running control plane under `/api/v1/secrets/*`
  (enable with `secrets.enable_api`, off by default and fail-closed). **Secret sync** is
  **not yet wired** — it remains library code. Track the remaining tail in
  [Current limitations](../limitations.md).
- **Machine login tenant binding:** token credentials MAC-bind the tenant, the
  `machine-login` audience, principal, and expiry. `X-Tenant-ID` is a lookup hint on
  the public login route; a token for tenant A is rejected if presented with tenant B.
- **Protect the KEK.** Everything at rest is only as safe as `TRSTCTL_SECRETS_KEK_FILE`;
  in production back it with an [HSM/KMS](issuance-and-cas.md).
- **Dynamic beats static.** Prefer dynamic/ephemeral secrets over long-lived ones; if you
  must store a long-lived secret, put it on a rotation schedule.
- **Transit/KMIP serving status:** the KMIP TTLV parser is fuzzed and covered by an
  operation-level interop fixture, but no KMIP listener/API/CLI is mounted yet. Treat
  appliance profile validation as future served-endpoint work, not as a currently
  available network surface.
- **Sync is push + drift-detect**, not a two-way merge — trstctl is the source of truth.

## Reference

- **At rest:** envelope encryption (AES-256-GCM DEK wrapped by KEK); config
  `TRSTCTL_SECRETS_KEK_FILE`.
- **Store:** `Put/Get/GetVersion/Versions/Rollback/Delete/Purge`; `APIServer`
  (`PUT/GET /secrets/<path>`, `Idempotency-Key`).
- **Dynamic backends:** `postgresql`, `mysql`, `mongodb`, `aws-sts`, `gcp-iam`,
  `azure-sp`, `redis-ssh`, plus `pki`.
- **Transit:** `Encrypt/Decrypt/Rewrap/HMAC/Sign/Verify`, versioned `trv:<n>:` ciphertext.
- **Sync targets:** Kubernetes, GitHub Actions, GitLab CI, Terraform, Vercel, AWS
  Parameter Store, webhook.
- **Events:** `secret.version.written`, `rotation.*`, `rotation.rollback_failed`,
  `auth.session.issued`,
  `secretscan.finding`.

## See also

[Workload identity](workload-identity.md) (attestation behind ephemeral secrets) ·
[Issuance & certificate authorities](issuance-and-cas.md) (HSM-backed KEK; PKI engine) ·
[Incident response & JIT](incident-and-jit.md) (compromise + approvals) ·
[Discovery & inventory](discovery-and-inventory.md) (finding existing secrets) ·
[Current limitations](../limitations.md) ·
glossary: [secret](../glossary.md), [envelope encryption](../glossary.md),
[KEK/DEK](../glossary.md), [dynamic secret](../glossary.md), [lease](../glossary.md),
[transit](../glossary.md), [KMIP](../glossary.md)

**Covers:** F37, F38, F39, F63, F64, F65, F66, F67, F68, F58, F60
