# Lifecycle & PQC — keeping credentials fresh, and ready for quantum

## What it is

A [certificate](../glossary.md) is not a "set it and forget it" object. It has a life:
it's issued, it's used, it nears expiry and must be **renewed**, sometimes it must be
**rotated** (replaced early) or **revoked** (cancelled), and eventually it's retired.
Lifecycle automation is trstctl doing that work for you on a schedule. This page also
covers two forward-looking concerns: **crypto-agility** (being able to change algorithms
without rewriting the system) and **PQC migration** (moving your estate to
[post-quantum](../glossary.md) algorithms before quantum computers break today's keys).

The mental model: lifecycle is the building superintendent who notices a key is about to
wear out and cuts a new one *before* it fails; crypto-agility is having a master
key-cutting machine that can switch blank types instantly; PQC migration is the planned
project to re-cut every key in the building to a new, tamper-proof blank.

## Why it exists

Expiry is the number-one cause of certificate outages, and it's entirely preventable: a
machine that renews on a schedule never lets a certificate lapse. Rotation limits the
damage of a leak (a short-lived credential is only useful briefly). And the quantum
transition is a multi-year migration that you cannot start until your cryptography is
*agile* — able to add and swap algorithms in one place. trstctl was built crypto-agile
from the first commit precisely so this migration is a contained change, not a rewrite.

## How it works

### Lifecycle automation (F6)

The lifecycle manager watches the [inventory](discovery-and-inventory.md) and acts on
three signals, with each tenant's data isolated at the database layer:

- **Renew from ARI, with an expiry fallback.** For trstctl-issued X.509 identities,
  the scheduler evaluates the ACME Renewal Information (ARI) window from the recorded
  certificate validity. If the ARI window has started, it renews even when the
  certificate is still outside the fixed `renew_before` threshold. The configured
  threshold (`renew_before`, default `720h` = 30 days) remains a safety fallback for
  certificates that have no usable ARI span. Each renewal re-issues through the one
  [issuance path](issuance-and-cas.md) with an `Idempotency-Key`, so a retry never mints
  a duplicate. In a single transaction it links the new certificate to the old one and
  supersedes the old, then emits immutable lifecycle and rotation evidence. The fresh
  subject key is generated in a locked, zeroized buffer and destroyed the instant the CSR
  is built — secret material lives in wipeable memory and is zeroed after use.
- **Revoke with propagation.** `Revoke(certID, reason)` is idempotent (a retry never
  revokes twice), updates the inventory and — for reliable, journaled delivery — enqueues
  a `revocation.publish` to the [outbox](../glossary.md) in the same transaction so a
  crash can't drop it, and emits `certificate.revoked`.
- **Alert before expiry.** It finds certificates inside the `alert_before` window,
  enriches the alert with the certificate owner and active approver recipients,
  enqueues a notification to the outbox, stamps `alerted_at` so it doesn't nag,
  and emits `certificate.expiring`.

**Status:** the manager is served by the running binary. The leader-only background
loop scans tenant-scoped deployed X.509 identities, consumes ARI renewal windows first,
falls back to `lifecycle.renew_before`, and writes the normal `ca.renew` outbox intent
instead of signing inline. The same served sweep honors `lifecycle.alert_before`: it
enqueues `notification.expiry` work with `owner_id`, owner contact, approver
recipients, severity, and threshold-day metadata; the outbox worker dispatches it
through the operator-wired notification channels, and the notification inbox exposes
the same escalation fields. It is integration-tested against real PostgreSQL, NATS,
the signer process, tenant-member approvers, and a signed webhook sink;
`lifecycle.renew_before` and `lifecycle.alert_before` are parsed and validated at
startup.

`POST /api/v1/lifecycle/endpoint-bindings` is the served end-to-end path for
automated enrollment -> provision -> renewal -> endpoint-bind. It creates the
X.509 identity for an existing owner, provisions or references the connector target,
binds the route onto the identity, queues issue and deploy intents through the outbox,
and leaves renewal on the same scheduler-driven `ca.renew` path. The issuer creates the
credential-bearing deploy payload while the generated key is still in memory, so web
servers, keystores, and load balancers receive the certificate/key bundle through the
registered connector without returning PEM bytes from the API response. The response
contains only the identity, target, and queued intent names.

### Crypto-agility (F16)

Crypto-agility is an *architecture* property, and in trstctl it's non-negotiable: all
cryptography goes through a single isolated path, and no other part of the system performs
crypto directly (an automated build check fails the build if anything tries). An algorithm
is a typed identifier; a signer is an opaque handle that signs without revealing its key; a
backend (software, HSM, KMS) is one interface. Adding or swapping an algorithm — including
a post-quantum one — is therefore a *one-place change*, and every backend must pass a
conformance harness (`ConformBackend`) that signs a probe, verifies it, and confirms a
wrong message and tampered signature both fail.

What's available behind that boundary today: classical RSA and ECDSA/Ed25519, plus the
post-quantum **ML-DSA** (FIPS 204), **ML-KEM** (FIPS 203), **SLH-DSA** (FIPS 205), and a
**hybrid** Ed25519+ML-DSA signature. ML-KEM includes key generation, encapsulation, and
decapsulation with FIPS 203 known-answer tests for the 512, 768, and 1024 parameter sets,
so it is ready for hybrid key-establishment wiring. Every private key, classical or
post-quantum, lives in an mlock'd, zeroized buffer and is parsed only for the instant of
each operation — secret material is held in wipeable memory and zeroed after use. A
`Classify(algorithm)` helper tells the rest of the system whether an algorithm is
quantum-vulnerable, which is what drives migration.

Profile selection is served, not just a library promise. Operators can create profile
versions with `POST /api/v1/profiles` or `trstctl-cli profiles create -f profile.json`;
the guided console builder exposes RSA, ECDSA, Ed25519,
`Hybrid-ML-DSA-44-ECDSA-P256`, `ML-DSA-65`, and `SLH-DSA-SHA2-128s`. The profile API
validates every `allowed_key_algorithms` value through `internal/crypto` before a
`profile.created` event is emitted. Unknown labels fail closed, and ML-KEM is rejected
in certificate profiles because it is a key-encapsulation primitive rather than a
certificate signing algorithm.

The isolated signer path now carries the signature schemes, too: `trstctl-signer` can
generate signer-held **ML-DSA-44/65/87** and **SLH-DSA-SHA2-128s/128f/192s/256s** keys,
seal them in the signer key store, reload them after restart, and sign digests over the
same UDS or mTLS signer channel used for classical CA keys. ML-KEM remains a
key-encapsulation mechanism, not a signing algorithm, so it is exposed as a crypto
primitive for key exchange rather than through the signer `GenerateKey` path.

The served TLS path is now hybrid-ready: trstctl's HTTPS and mTLS listeners prefer
`X25519MLKEM768` when the peer supports it, then fall back to classical TLS 1.3 groups
for stock clients. The served CA can also mint a transition leaf that keeps the
standard ECDSA P-256 certificate shape for existing TLS clients and adds a signed
ML-DSA-44 + ECDSA-P256 composite binding inside the certificate. A PQ-aware verifier can
check that extension; older clients ignore it and still validate the normal CA-signed
leaf. The served ACME, EST, SCEP, and CMP paths all use the same profile-gated issuer,
so a CSR carrying that hybrid proof can be issued through those enrollment protocols
under a profile that allows `Hybrid-ML-DSA-44-ECDSA-P256`.

### PQC migration orchestration (F57)

Knowing *where* your weak crypto is (the [CBOM](observability-and-risk.md)) is half the
battle; the other half is *fixing* it without a giant manual project. The served PQC
migration orchestrator consumes the CBOM read model, finds quantum-vulnerable
certificate-key assets, and queues re-issuance through the outbox. RSA/ECDSA/EdDSA
findings point at **ML-DSA-65** (`FIPS 204`), TLS protocol/cipher findings point at
**ML-KEM-768** (`FIPS 203`), DSA findings point at **SLH-DSA-SHA2-128s** (`FIPS 205`),
and assets already using ML-DSA, ML-KEM, or SLH-DSA count as post-quantum-ready. `GET
/api/v1/cbom/assets` exposes the `migration_progress` percentage the orchestrator burns
down.

Start a served certificate-key migration with `POST /api/v1/pqc/migrations` or
`trstctl-cli pqc migrations start -f plan.json`. The request names CBOM `asset_ids`,
`target_algorithm: "ML-DSA-65"`, `protocol: "acme"`, and whether rollback should be
prepared. trstctl records `pqc.migration.started`, writes the re-issue intent to the
outbox in the tenant transaction, and the worker mints the replacement through the same
served ACME/protocol issuer used by normal enrollment. Today that replacement is the
deployable transition leaf `Hybrid-ML-DSA-44-ECDSA-P256`: stock TLS clients still see a
normal ECDSA P-256 certificate, while PQ-aware verifiers can validate the ML-DSA binding.

Rollback is a served path too: `POST /api/v1/pqc/migrations/{run_id}/rollback` or
`trstctl-cli pqc migrations rollback <run-id> -f rollback.json` queues an evented restore
of the original CBOM fact. Completion and rollback are immutable events
(`pqc.migration.asset_completed`, `pqc.migration.rollback_completed`) projected back into
`crypto_assets`, so posture dashboards and `migration_progress` are derived from the
event log rather than hand-edited read tables.

**Status:** served for CBOM certificate-key assets through ACME hybrid transition
re-issuance with rollback. The same planner/reissuer behavior is available through
operator-facing API and CLI entry points.

### In the console

In the web console the certificate inventory at `/certificates` is also a lifecycle
**command center**: expiry bands, a **47-day renewal-readiness simulator** (does each
certificate renew comfortably inside the shrinking CA/Browser-Forum maximum lifetime?),
deployment receipts from the connectors, and a per-certificate renewal-history timeline in
the detail drawer. The crypto-agility and PQC work surfaces at `/posture` as a **PQC
readiness gauge** — readiness percentage plus quantum-vulnerable, PQC-ready, and
out-of-policy counts derived from the served CBOM `migration_progress` — alongside the CBOM
scan trigger and the PQC migration-orchestration panel. See
[The web console](../web-console.md).

## Use it

Lifecycle thresholds are configuration today:

```json
{
  "lifecycle": {
    "renew_before": "720h",
    "alert_before": "168h"
  }
}
```

`renew_before` is the fallback window before expiry in which trstctl re-issues when no
earlier ARI window is due; `alert_before` is when it warns. See
[Configuration](../configuration.md) for the full set and
[Operations](../operations.md) for running behavior. The PQC posture you'd migrate from
is visible in the [CBOM](observability-and-risk.md) with `GET /api/v1/cbom/assets`; the
migration trigger accepts CBOM asset ids and currently re-issues certificate keys toward
`ML-DSA-65` through the served ACME hybrid transition path.

## Pitfalls & limits

- **ARI-driven renewal covers trstctl-issued deployed X.509 identities.** Inventory rows
  discovered from an outside CA are still visible for expiry/risk, but renewing them
  requires an issuer or connector path that can actually replace that external
  certificate.
- **PQC migration is served for certificate-key assets first.** TLS protocol/cipher
  migrations still require protocol and deployment-specific rollout work after CBOM
  identifies them.
- **What's *not* end-to-end on PQC** is pure ML-DSA subject certificates for every stock
  client, a multi-key SPIFFE Workload API response, and the fully automated fleet-wide
  rollout; the served TLS path already negotiates ML-KEM hybrid key exchange, the served
  ACME/EST/SCEP/CMP paths can issue hybrid transition leaves, and the signer can already
  hold and use ML-DSA and SLH-DSA keys. trstctl is crypto-agile by construction, so the
  remaining work is protocol-specific client compatibility and broader deployment
  automation, not a redesign.
- **SLH-DSA signatures are large.** They're the conservative choice for long-lived roots,
  not for high-volume leaf issuance — pick the algorithm per profile.

## Reference

- **Config:** `lifecycle.renew_before` (default `720h`), `lifecycle.alert_before`
  (Go duration strings); `TRSTCTL_LIFECYCLE_RENEW_BEFORE`.
- **Lifecycle ops:** `RenewExpiring`, `Rotate`, `Revoke`, `AlertExpiring`.
- **Events:** `certificate.renewed`, `certificate.revoked`, `certificate.expiring`;
  `pqc.migration.started`, `pqc.migration.asset_completed`,
  `pqc.migration.rollback_completed`, `protocol.issued`.
- **CBOM migration feed:** `POST /api/v1/cbom/scans` records `cbom.asset.observed`; `GET
  /api/v1/cbom/assets` returns FIPS 203/204/205 targets and `migration_progress`.
- **PQC migration API:** `POST /api/v1/pqc/migrations` queues ACME re-issuance for CBOM
  certificate-key assets; `POST /api/v1/pqc/migrations/{run_id}/rollback` queues rollback.
- **PQC algorithms:** ML-DSA (FIPS 204), ML-KEM (FIPS 203), SLH-DSA (FIPS 205),
  `HybridEd25519Dilithium3`. See the post-quantum section of
  [Current limitations](../limitations.md).

## See also

[Issuance & certificate authorities](issuance-and-cas.md) ·
[Observability & risk](observability-and-risk.md) (the CBOM you migrate from) ·
[Configuration](../configuration.md) · [Operations & resilience](../operations.md) ·
glossary: [rotation](../glossary.md), [revocation](../glossary.md),
[PQC](../glossary.md), [CBOM](../glossary.md)

**Covers:** F6, F16, F57
