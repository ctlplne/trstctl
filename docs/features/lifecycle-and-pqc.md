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
cryptography goes through a single isolated path, and no other part of the system
performs crypto directly (an automated build check fails the build if anything
tries). An algorithm is a typed identifier; a signer is an opaque handle that signs
without revealing its key; a backend (software, HSM, KMS) is one interface. Adding or
swapping an algorithm is therefore a *one-place change*, and every backend must pass
a conformance harness (`ConformBackend`) that signs a probe, verifies it, and
confirms a wrong message and tampered signature both fail.

In the MPL core, profile selection is served for classical RSA, ECDSA, and Ed25519.
Operators can create profile versions with `POST /api/v1/profiles` or
`trstctl-cli profiles create -f profile.json`; the API validates every
`allowed_key_algorithms` value through `internal/crypto` before a `profile.created`
event is emitted, and unknown labels fail closed.

All post-quantum algorithms and post-quantum issuance/signing paths are proprietary
EE features. That includes **ML-DSA** (FIPS 204), **ML-KEM** (FIPS 203),
**SLH-DSA** (FIPS 205), hybrid certificate/key types, PQC signer-held keys, PQC
APIs, PQC UI, and PQC tests. They plug into the same crypto and signer interfaces
from `ee/`, so the MPL core stays buildable without them and never imports `ee/`.

### PQC migration orchestration (F57)

Knowing *where* your weak crypto is (the [CBOM](observability-and-risk.md)) is half the
battle; the other half is *fixing* it without a giant manual project. PQC migration is
served when the Enterprise/PQC license attaches the proprietary EE package. The EE
orchestrator consumes the CBOM read model, finds quantum-vulnerable certificate-key
assets, and queues re-issuance through the outbox toward the licensed PQC target.

The licensed EE API attaches `POST /api/v1/pqc/migrations` and
`POST /api/v1/pqc/migrations/{run_id}/rollback`; those routes are not part of the MPL core OpenAPI
golden, and there is no MPL-core CLI command for PQC migration. Completion
and rollback are projected through the event log into `crypto_assets`, so posture
dashboards and `migration_progress` stay derived from replayable state rather than
hand-edited read tables.

**Status:** served when the Enterprise/PQC license attaches `ee/pqcmigration`, for
CBOM certificate-key assets through ACME hybrid transition re-issuance with rollback.
The MPL core exposes CBOM posture and classical profile selection, but not PQC
algorithms, PQC issuance, or the PQC migration trigger.

### In the console

In the web console the certificate inventory at `/certificates` is also a lifecycle
**command center**: expiry bands, a **47-day renewal-readiness simulator** (does each
certificate renew comfortably inside the shrinking CA/Browser-Forum maximum lifetime?),
deployment receipts from the connectors, and a per-certificate renewal-history timeline in
the detail drawer. The crypto-agility work surfaces at `/posture` as CBOM-backed
algorithm posture and remediation handoff; proprietary PQC controls are supplied from
the EE UI bundle when licensed. See [The web console](../web-console.md).

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
is visible in the [CBOM](observability-and-risk.md) with `GET /api/v1/cbom/assets`;
the PQC migration trigger attaches only from proprietary EE.

## Pitfalls & limits

- **ARI-driven renewal covers trstctl-issued deployed X.509 identities.** Inventory rows
  discovered from an outside CA are still visible for expiry/risk, but renewing them
  requires an issuer or connector path that can actually replace that external
  certificate.
- **PQC migration is licensed EE scope.** The MPL core exposes CBOM posture but does
  not expose PQC algorithms, the PQC migration API, or a PQC CLI command.
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
  `licensed_crypto.migration.started`, `licensed_crypto.migration.asset_completed`,
  `licensed_crypto.migration.rollback_completed`, `protocol.issued`.
- **CBOM migration feed:** `POST /api/v1/cbom/scans` records `cbom.asset.observed`; `GET
  /api/v1/cbom/assets` returns crypto posture, licensed migration targets, and
  `migration_progress`.
- **PQC migration API:** proprietary EE attaches `POST /api/v1/pqc/migrations` for CBOM
  certificate-key assets and `POST /api/v1/pqc/migrations/{run_id}/rollback` for rollback.
- **PQC algorithms:** proprietary EE scope: ML-DSA (FIPS 204), ML-KEM (FIPS 203),
  SLH-DSA (FIPS 205), and hybrid algorithms. See the post-quantum section of
  [Current limitations](../limitations.md).

## See also

[Issuance & certificate authorities](issuance-and-cas.md) ·
[Observability & risk](observability-and-risk.md) (the CBOM you migrate from) ·
[Configuration](../configuration.md) · [Operations & resilience](../operations.md) ·
glossary: [rotation](../glossary.md), [revocation](../glossary.md),
[PQC](../glossary.md), [CBOM](../glossary.md)

**Covers:** F6, F16, F57
