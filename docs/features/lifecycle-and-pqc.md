# Lifecycle & PQC — keeping credentials fresh, and ready for quantum

## What it is

A [certificate](../glossary.md) is not a "set it and forget it" object. It has a life:
it's issued, it's used, it nears expiry and must be **renewed**, sometimes it must be
**rotated** (replaced early) or **revoked** (cancelled), and eventually it's retired.
Lifecycle automation is trustctl doing that work for you on a schedule. This page also
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
*agile* — able to add and swap algorithms in one place. trustctl was built crypto-agile
from the first commit precisely so this migration is a contained change, not a rewrite.

## How it works

### Lifecycle automation (F6)

The lifecycle manager watches the [inventory](discovery-and-inventory.md) and acts on
three signals, all tenant-scoped (**AN-1**):

- **Renew before expiry.** It lists certificates expiring within a configurable window
  (`renew_before`, default `720h` = 30 days) and re-issues each through the one
  [issuance path](issuance-and-cas.md) with an idempotency key (**AN-5**). In a single
  transaction it links the new certificate to the old one and supersedes the old, then
  emits `certificate.renewed` (**AN-2**). The fresh subject key is generated in a
  locked, zeroized buffer and destroyed the instant the CSR is built (**AN-8**).
- **Revoke with propagation.** `Revoke(certID, reason)` runs idempotently (**AN-5**),
  updates the inventory and enqueues a `revocation.publish` to the [outbox](../glossary.md)
  in the same transaction (**AN-6**), and emits `certificate.revoked`.
- **Alert before expiry.** It finds certificates inside the `alert_before` window,
  enqueues a notification to the outbox, stamps `alerted_at` so it doesn't nag, and
  emits `certificate.expiring`.

*Code:* `internal/lifecycle` (`Manager`, `RenewExpiring`, `Rotate`, `Revoke`,
`AlertExpiring`). **Status:** the manager is implemented and integration-tested against
real PostgreSQL and NATS, and its config (`lifecycle.renew_before`,
`lifecycle.alert_before`) is parsed and validated, but the running server does not yet
start it as a background loop — see [Pitfalls & limits](#pitfalls--limits).

### Crypto-agility (F16)

Crypto-agility is an *architecture* property, and in trustctl it's non-negotiable
**AN-3**: every cryptographic operation goes through the single boundary
`internal/crypto`, and nothing else in the codebase imports `crypto/*` (a CI linter
fails the build if it tries). An algorithm is a typed identifier; a signer is an opaque
handle that signs without revealing its key; a backend (software, HSM, KMS) is one
interface. Adding or swapping an algorithm — including a post-quantum one — is therefore a
*one-package change*, and every backend must pass a conformance harness (`ConformBackend`)
that signs a probe, verifies it, and confirms a wrong message and tampered signature both
fail.

What's available behind that boundary today: classical RSA and ECDSA/Ed25519, plus the
post-quantum **ML-DSA** (FIPS 204), **ML-KEM** (FIPS 203), **SLH-DSA** (FIPS 205), and a
**hybrid** Ed25519+ML-DSA signature. Every private key, classical or post-quantum, lives
in an mlock'd, zeroized buffer and is parsed only for the instant of each operation
(**AN-8**). A `Classify(algorithm)` helper tells the rest of the system whether an
algorithm is quantum-vulnerable, which is what drives migration.

*Code:* `internal/crypto` (`Algorithm`, `Signer`, `Backend`, `ConformBackend`,
`Classify`), `internal/crypto/pqc`, `internal/crypto/slhdsa.go`.

### PQC migration orchestration (F57)

Knowing *where* your weak crypto is (the [CBOM](observability-and-risk.md)) is half the
battle; the other half is *fixing* it without a giant manual project. The PQC migration
orchestrator walks the CBOM in the [credential graph](graph-query-ai.md), uses
`Classify` to find every quantum-vulnerable asset, and re-issues each one to a
post-quantum target — refusing outright if you hand it a *classical* target by mistake.

It's built to survive interruption: a progress store records each completed asset, so a
crashed run **resumes** without re-issuing anything (**AN-5**/**AN-6**), and an optional
policy gate can skip assets you're not ready to migrate. Each step is audited
(`pqc.migration.started`, `.skipped`, `.progress`, `.completed`, **AN-2**), and after a
successful re-issue it marks the CBOM node migrated so your posture dashboards reflect
reality.

*Code:* `internal/pqcmigration` (`Orchestrator`, `VulnerableAssets`, `Migrate`).
**Status:** library-complete and table-tested (detection, full migration, resume,
non-PQC-target rejection); no CLI/API trigger is wired yet.

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

`renew_before` is the window before expiry in which trustctl re-issues; `alert_before` is
when it warns. See [Configuration](../configuration.md) for the full set and
[Operations](../operations.md) for running behavior. The PQC posture you'd migrate from
is visible in the [CBOM](observability-and-risk.md); the migration itself targets a
post-quantum algorithm such as `SLH-DSA-SHA2-128f` or `ML-DSA-65`.

## Pitfalls & limits

- **Lifecycle automation is implemented but not yet scheduled** by the running binary;
  the config is wired and the logic is integration-tested. Track this in
  [Current limitations](../limitations.md). Until it's scheduled, renewal can be driven
  through the issuance path directly.
- **PQC migration has no CLI/API trigger yet** — the orchestrator is library-complete and
  tested; wiring an operator entry point is the follow-up.
- **What's *not* end-to-end on PQC** is issuance through every enrollment protocol and the
  fully automated fleet-wide rollout; the crypto primitives (ML-DSA, ML-KEM, SLH-DSA,
  hybrid) are in place. trustctl is crypto-agile by construction, so these are wiring
  steps, not redesigns.
- **SLH-DSA signatures are large.** They're the conservative choice for long-lived roots,
  not for high-volume leaf issuance — pick the algorithm per profile.

## Reference

- **Config:** `lifecycle.renew_before` (default `720h`), `lifecycle.alert_before`
  (Go duration strings); `TRUSTCTL_LIFECYCLE_RENEW_BEFORE`.
- **Lifecycle ops:** `RenewExpiring`, `Rotate`, `Revoke`, `AlertExpiring`.
- **Events:** `certificate.renewed`, `certificate.revoked`, `certificate.expiring`;
  `pqc.migration.{started,skipped,progress,completed}`.
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
