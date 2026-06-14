# Secrets — store, issue, rotate, and encrypt the credentials machines use

## What it is

A [secret](../glossary.md) is any sensitive value software needs but shouldn't expose:
a database password, an API token, an encryption key. trustctl is a full secrets
platform alongside its certificate work — it stores secrets encrypted, hands out
short-lived ones on demand, rotates them safely, encrypts data on behalf of apps,
syncs secrets to other platforms, and governs who can read or change them.

The mental model: think of a bank. The **vault** stores valuables encrypted (the secret
store). The **safe-deposit clerk** issues a temporary key that self-destructs after an
hour (dynamic secrets). The **armored-car service** moves valuables to other branches
(secret sync). The **teller window** encrypts your deposit without you ever seeing the
master key (encryption-as-a-service). And every action needs ID and is logged
(auth + approvals + audit).

> **One honest note up front.** trustctl's *certificate* features include served APIs
> today; the *secrets* domain below is built as complete, tested library packages, with
> a ready-to-mount HTTP server (`secretstore.APIServer`) that is **not yet wired into
> the running control plane**. So everything here is real, tested code — but you drive
> it via its Go APIs today, not a live endpoint. See
> [Current limitations](../limitations.md). This page is honest about that throughout.

## Why it exists

Leaked secrets are one of the most common breach causes, because the traditional
approach — long-lived secrets copied into config files, environment variables, images,
and CI — spreads them everywhere and never expires them. trustctl attacks the problem
from every side: encrypt them properly at rest, prefer short-lived/dynamic secrets that
can't be hoarded, rotate the long-lived ones automatically, never let a secret value
touch a log or a disk it shouldn't, and put approvals and a tamper-evident audit trail
around access. Secret material is always held in `[]byte` and zeroized, never a Go
`string` (non-negotiable **AN-8**).

## How it works

### How every secret is encrypted at rest

trustctl uses **[envelope encryption](../glossary.md)** (non-negotiable **AN-3**, all in
`internal/crypto`). Each secret is encrypted with a fresh per-secret data key (DEK,
AES-256-GCM), and that DEK is itself encrypted under a master key-encryption key (KEK).
The encryption is bound to the secret's tenant and path, so a sealed blob can't be moved
elsewhere. The KEK is loaded at startup from `TRUSTCTL_SECRETS_KEK_FILE` (0600),
held only transiently, and zeroized. To rotate protection you re-wrap small DEKs, not all
your data. *Code:* `internal/crypto/envelope.go`.

### The native secret store (F63)

A versioned key-value store: every `Put` creates a new version (old versions stay
queryable), `Delete` writes a tombstone (history is retained), and the whole version list
can be **reconstructed from the event log** (**AN-2**) — the store is a projection, not a
primary write. Writes are idempotent by key (**AN-5**), tenant-isolated with cross-tenant
denial (**AN-1**), and the ready-to-mount `APIServer` enforces per-secret RBAC.

*Code:* `internal/secretstore` (`Store`, `Put/Get/Versions/Rollback/Delete`, `APIServer`).

### The developer secrets experience (F64)

Two pieces make secrets pleasant *and* safe for developers. A CLI **injector** runs your
program with secrets in its environment without ever writing them to disk (only the
variable *names* are audited, never values). An **SDK** caches secrets and auto-refreshes
them before expiry, and on a revocation it evicts the cache and fails safe rather than
serving a stale, revoked secret. *Code:* `internal/secretscli`, `internal/secretsdk`.

### Dynamic secrets (F65) and PKI-as-a-secrets-engine (F67)

Instead of a long-lived secret to steal, **dynamic secrets** are minted on demand,
scoped, and time-limited by a [lease](../glossary.md); when the lease expires trustctl
revokes the underlying credential automatically — even across a restart, because the
revocation intent is written to a durable [outbox](../glossary.md) (**AN-6**). Seven
backends ship behind one interface: PostgreSQL, MySQL, MongoDB, AWS STS, GCP IAM, Azure
service principal, and Redis/SSH; all pass a lifecycle conformance test. **PKI-as-a-
secrets-engine** plugs the same lease machinery into certificate issuance — a developer
requests a short-lived certificate exactly like a database password, and the leaf key is
generated locked and destroyed immediately (**AN-8**). *Code:* `internal/dynsecret`,
`internal/leaseworker`, `internal/pkisecret`.

### Secret rotation (F37)

The rotation engine replaces a long-lived secret in **four rollback-safe phases**: stage
the new version, cut consumers over, verify they're healthy, retire the old one. If
cutover or verification fails, it **automatically rolls back** so the application is never
left broken; each phase is audited and, in production, delivered via the outbox so a crash
mid-rotation strands nothing. *Code:* `internal/rotation` (`Engine.Rotate`).

### Ephemeral API keys (F38)

For high-churn automation, trustctl issues short-lived credentials gated by
[attestation](workload-identity.md): prove what you are, get a sub-hour credential,
let it expire (no CRL needed). Every request needs an idempotency key (**AN-5**) and
nothing is minted unless attestation verifies. *Code:* `internal/ephemeral`.

### Encryption-as-a-service & KMIP (F66)

The **transit** service encrypts, decrypts, HMACs, and signs data using named keys the
application *never sees* — ciphertexts are versioned (`trv:<version>:...`) so a key
rotation can re-wrap old data, and intermediate plaintext is zeroized (**AN-8**). For
legacy enterprise gear (databases, storage arrays) trustctl also answers **KMIP**, the
standard key-management protocol, with TLS client-cert auth and key material zeroized on
destroy. *Code:* `internal/transit`, `internal/kmip`.

### Secret sync (F68)

trustctl can push secrets *outward* to the platforms that need them — Kubernetes, GitHub
Actions, GitLab CI, Terraform, Vercel, AWS Parameter Store, or a generic webhook — via the
durable outbox (at-least-once, no half-writes, **AN-6**), and it **detects drift** by
comparing hashes when a target is changed out-of-band. *Code:* `internal/secretsync`.

### The auth-method framework (F58)

Before a workload can read a secret, it has to authenticate *to* trustctl. The auth-method
framework is that login layer: a workload presents a credential (a token, an OIDC JWT, a
Kubernetes SA token, cloud IAM, etc.), trustctl verifies it through `internal/crypto`
(timing-safe), and issues a scoped, time-bounded **session**. Credential bytes are never
logged (**AN-8**); every attempt is audited (**AN-2**). *Code:* `internal/authmethod`.

### Secret scanning bridge (F39) and sharing & approvals (F60)

The **scanning bridge** ingests findings from gitleaks and trufflehog into the
[credential graph](graph-query-ai.md) and risk view — structurally excluding the secret
value (the parsers never read it) — and can auto-trigger the
[compromise workflow](incident-and-jit.md). **Secret sharing** creates one-time,
self-destructing links (viewed once, then deleted; expiry-bounded), and **change
approvals** put a dual-control [approval](incident-and-jit.md) gate on secret mutations.
*Code:* `internal/secretscan`, `internal/secretshare`.

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

- **Serving status:** the secrets domain is built and tested as library packages with a
  ready-to-mount `APIServer`, but is **not yet wired** into the running control plane (no
  live REST/CLI surface). The certificate features are further along here. Track this in
  [Current limitations](../limitations.md).
- **Protect the KEK.** Everything at rest is only as safe as `TRUSTCTL_SECRETS_KEK_FILE`;
  in production back it with an [HSM/KMS](issuance-and-cas.md).
- **Dynamic beats static.** Prefer dynamic/ephemeral secrets over long-lived ones; if you
  must store a long-lived secret, put it on a rotation schedule.
- **KMIP/transit wire interop** is tested against reference clients but confirm your
  specific appliance's KMIP profile.
- **Sync is push + drift-detect**, not a two-way merge — trustctl is the source of truth.

## Reference

- **At rest:** envelope encryption (AES-256-GCM DEK wrapped by KEK); config
  `TRUSTCTL_SECRETS_KEK_FILE`.
- **Store:** `Put/Get/GetVersion/Versions/Rollback/Delete/Purge`; `APIServer`
  (`PUT/GET /secrets/<path>`, `Idempotency-Key`).
- **Dynamic backends:** `postgresql`, `mysql`, `mongodb`, `aws-sts`, `gcp-iam`,
  `azure-sp`, `redis-ssh`, plus `pki`.
- **Transit:** `Encrypt/Decrypt/Rewrap/HMAC/Sign/Verify`, versioned `trv:<n>:` ciphertext.
- **Sync targets:** Kubernetes, GitHub Actions, GitLab CI, Terraform, Vercel, AWS
  Parameter Store, webhook.
- **Events:** `secret.version.written`, `rotation.*`, `auth.session.issued`,
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
