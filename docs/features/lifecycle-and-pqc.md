# Lifecycle & PQC — keeping credentials fresh, and ready for quantum

## What it is

A [certificate](../glossary.md) is not a "set it and forget it" object: it's issued,
used, nears expiry and must be renewed, sometimes rotated (replaced early) or revoked
(cancelled), and eventually retired. Lifecycle automation is trstctl doing that work on a
schedule. This page also covers two forward-looking concerns: crypto-agility (changing
algorithms without rewriting the system) and PQC migration (moving your estate to
[post-quantum](../glossary.md) algorithms before quantum computers break today's keys).

The mental model: lifecycle is the superintendent who cuts a new key before the old one
wears out; crypto-agility is a master key-cutting machine that can switch blank types
instantly; PQC migration is the project to re-cut every key in the building to a new,
tamper-proof blank.

## Why it exists

Expiry is the number-one cause of certificate outages, and it's entirely preventable: a
machine that renews on schedule never lets a certificate lapse. Rotation limits the
damage of a leak, since a short-lived credential is only useful briefly. The quantum
transition is a multi-year migration that can't start until your cryptography is *agile*
— able to add and swap algorithms in one place. trstctl was built crypto-agile from the
first commit, so this migration is a contained change, not a rewrite.

## How it works

### Lifecycle automation (F6)

The lifecycle manager watches the [inventory](discovery-and-inventory.md) and acts on
three signals, tenant-isolated at the database layer:

- **Renew from ARI, with an expiry fallback.** For trstctl-issued X.509 identities, the
  scheduler evaluates the ACME Renewal Information (ARI) window and renews early once it
  opens, even while the certificate is still outside the fixed `renew_before` threshold
  (default `720h` = 30 days), a safety fallback for certificates with no usable ARI span.
  Each renewal re-issues through the one [issuance path](issuance-and-cas.md) with an
  `Idempotency-Key`, supersedes the old certificate in a single transaction, and emits
  immutable lifecycle/rotation evidence. The fresh subject key is generated in a locked,
  zeroized buffer and destroyed the instant the CSR is built.
- **Revoke with propagation.** `Revoke(certID, reason)` is idempotent, updates the
  inventory, enqueues a `revocation.publish` to the [outbox](../glossary.md) in the same
  transaction so a crash can't drop it, and emits `certificate.revoked`.
- **Alert before expiry.** It finds certificates inside the `alert_before` window,
  enriches the alert with the owner and approver recipients, enqueues a notification,
  stamps `alerted_at` so it doesn't nag, and emits `certificate.expiring`.

**Status:** served by the running binary. A leader-only background loop scans
tenant-scoped deployed X.509 identities, honoring `lifecycle.renew_before` and
`lifecycle.alert_before` (both parsed and validated at startup), and writes the normal
`ca.renew` and `notification.expiry` outbox intents rather than acting inline. It's
integration-tested against real PostgreSQL, NATS, the signer process, and a signed
webhook sink.

`POST /api/v1/lifecycle/endpoint-bindings` is the served end-to-end path for automated
enrollment, provisioning, renewal, and endpoint binding: it creates the X.509 identity,
binds the route, queues issue/deploy intents through the outbox, and leaves renewal on
the same `ca.renew` path. The issuer builds the deploy payload while the key is still in
memory, so the connector delivers the certificate/key bundle without PEM bytes ever
returning from the API response.

### Crypto-agility (F16)

Crypto-agility is an architecture property, and in trstctl it's non-negotiable: all
cryptography goes through a single isolated path, or an automated build check fails.
An algorithm is a typed identifier; a signer is an opaque handle that signs without
revealing its key; a backend (software, HSM, KMS) is one interface. Adding or swapping an
algorithm is therefore a one-place change, and every backend must pass a conformance
harness (`ConformBackend`) that signs a probe, verifies it, and confirms a wrong message
and a tampered signature both fail.

In the MPL core, profile selection is served for classical RSA, ECDSA, and Ed25519.
Operators create profile versions with `POST /api/v1/profiles` or `trstctl-cli profiles
create -f profile.json`; the API validates every `allowed_key_algorithms` value through
`internal/crypto` before emitting a `profile.created` event, and unknown labels fail
closed.

All post-quantum algorithms and post-quantum issuance/signing paths are proprietary EE
features. That includes ML-DSA (FIPS 204), ML-KEM (FIPS 203), SLH-DSA (FIPS 205), hybrid
certificate/key types, and PQC signer-held keys. They plug into the same crypto and
signer interfaces from `ee/`, so the MPL core stays buildable without them and never
imports `ee/`. The core campaign tracker described next records work and evidence; it
does not contain an algorithm implementation or fleet executor.

### Core migration campaigns

CBOM sees the problem, so campaign ownership lives beside CBOM in core. A Community
operator can create a tenant-scoped campaign over existing quantum-vulnerable or
out-of-policy CBOM findings, assign an owner, deadline, wave, and readiness criteria,
then record work performed manually or by any external tool. No licence is required:
`POST /api/v1/pqc/campaigns` starts the campaign; the corresponding list/detail/update,
readiness, finding-disposition, close, and evidence routes serve the complete workflow.
The same operations are available under `trstctl-cli pqc campaigns` and on `/posture`.

Campaign mutations emit immutable `pqc.migration_campaign.*` events. PostgreSQL
projections carry `tenant_id` and forced row-level security. Closure is rejected until
the readiness gate passes and every selected finding is marked `remediated` or
`excepted` with a SHA-256 evidence digest. The closure artifact is signed by the
persistent audit key and binds the tenant, campaign, frozen finding digests,
dispositions, evidence digests, and timestamps; its included public JWKS permits
offline verification.

The edition boundary is explicit: the core response says automated fleet execution is
unavailable while keeping all tracking and proof actions live. The licensed engine may
execute a campaign across a fleet, but it is an optional executor—not a prerequisite
for a useful core campaign.

### PQC migration orchestration (F57)

Knowing *where* your weak crypto is (the [CBOM](observability-and-risk.md)) is half the
battle; the other half is *fixing* it without a manual project. PQC migration is served
when the Enterprise/PQC license attaches the proprietary EE package: the orchestrator
consumes the CBOM read model, finds quantum-vulnerable certificate-key assets, and queues
re-issuance through the outbox toward the licensed target.

The licensed EE API attaches `POST /api/v1/pqc/migrations` and
`POST /api/v1/pqc/migrations/{run_id}/rollback`. Those routes are not part of the MPL core OpenAPI
golden. There is no MPL-core CLI command for licensed fleet execution or rollback; the core
`pqc campaigns` commands record operator work and never call these licensed routes. Completion and rollback
project through the event log into `crypto_assets`, so posture dashboards and
`migration_progress` stay derived from replayable state, not hand-edited tables.

**Execution status:** served when the Enterprise/PQC license attaches `ee/pqcmigration`, for CBOM
certificate-key assets through ACME hybrid transition re-issuance with rollback. The MPL
core exposes CBOM posture, classical profile selection, and migration campaign
tracking/proof, but not PQC algorithms, issuance, or automated fleet execution.

### In the console

In the web console, the certificate inventory at `/certificates` is also a lifecycle
command center: expiry bands, a 47-day renewal-readiness simulator (does each certificate
renew inside the shrinking CA/Browser Forum maximum lifetime?), deployment receipts, and
a per-certificate renewal-history timeline. The crypto-agility work surfaces at
`/posture` as CBOM-backed algorithm posture, the complete core campaign/evidence
workflow, and the licensed executor when attached. See [The web console](../web-console.md).

## Use it

Lifecycle thresholds are configuration today:

```json
{
  "lifecycle": {
    "renew_before": "720h",
    "alert_before": "336h"
  }
}
```

Both are shipped defaults (30 / 14 days). `renew_before` is the fallback window before
expiry when trstctl re-issues absent an earlier ARI window; `alert_before` is when it
warns. See [Configuration](../configuration.md) and [Operations](../operations.md) for
the full set and running behavior. PQC posture is visible in the
[CBOM](observability-and-risk.md) via `GET /api/v1/cbom/assets`; core campaigns are
served under `/api/v1/pqc/campaigns`, while automated fleet execution attaches only
from proprietary EE.

## Pitfalls & limits

- **ARI-driven renewal** covers trstctl-issued deployed X.509 identities. Rows discovered
  from an outside CA stay visible for expiry/risk, but renewing them needs an issuer or
  connector path that can actually replace that external certificate.
- **PQC execution** is licensed EE scope. The MPL core exposes CBOM posture and the
  useful standalone `pqc campaigns` API/CLI/UI, but not PQC algorithms or automated
  fleet execution.
- **Former PQC end-to-end residuals** are served under the Enterprise/PQC attach.
  Stock OpenSSL 3.5 enrolls and verifies a pure ML-DSA-65 subject leaf over EST; the
  stock SPIFFE Workload API receives a two-entry classical + ML-DSA-65 response; and CBOM
  TLS findings roll out TLS 1.3 plus `X25519MLKEM768` through a posture-capable connector
  with receiver readback and exact rollback (the shipped proof uses Envoy) — a tested
  client/connector boundary, not a claim about every legacy client. Hybrid-to-pure
  replacement of an already deployed leaf stays gated by succession and evidence-based
  retirement; direct pure enrollment is served.
- **SLH-DSA** signatures are large — the conservative choice for long-lived roots, not
  high-volume leaf issuance; pick the algorithm per profile.

## Reference

- **Config:** `lifecycle.renew_before` (default `720h`), `lifecycle.alert_before`
  (default `336h`; Go duration strings); `TRSTCTL_LIFECYCLE_RENEW_BEFORE`,
  `TRSTCTL_LIFECYCLE_ALERT_BEFORE`.
- **Lifecycle ops:** `RenewExpiring`, `Rotate`, `Revoke`, `AlertExpiring`.
- **Events:** `certificate.renewed`, `certificate.revoked`, `certificate.expiring`;
  `pqc.migration_campaign.started`, `pqc.migration_campaign.updated`,
  `pqc.migration_campaign.finding_dispositioned`, `pqc.migration_campaign.closed`;
  `licensed_crypto.migration.started`, `licensed_crypto.migration.asset_completed`,
  `licensed_crypto.migration.rollback_completed`, `protocol.issued`.
- **CBOM migration feed:** `POST /api/v1/cbom/scans` records `cbom.asset.observed`; `GET
  /api/v1/cbom/assets` returns crypto posture, licensed migration targets, and
  `migration_progress`.
- **PQC migration API:** proprietary EE attaches `POST /api/v1/pqc/migrations` (CBOM
  certificate-key assets) and `POST /api/v1/pqc/migrations/{run_id}/rollback`.
- **Core PQC campaign API:** `/api/v1/pqc/campaigns` plus detail, update, readiness,
  finding disposition, close, and signed-evidence export routes.
- **PQC algorithms:** proprietary EE scope: ML-DSA (FIPS 204), ML-KEM (FIPS 203),
  SLH-DSA (FIPS 205), and hybrid algorithms. See the post-quantum section of
  [Current limitations](../limitations.md).

## See also

[Issuance & certificate authorities](issuance-and-cas.md) ·
[Observability & risk](observability-and-risk.md) (the CBOM source) ·
[Configuration](../configuration.md) · [Operations & resilience](../operations.md) ·
glossary: [rotation](../glossary.md), [revocation](../glossary.md),
[PQC](../glossary.md), [CBOM](../glossary.md)

**Covers:** F6, F16, F57
