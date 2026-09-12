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
quantum-resistant blank.

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
  immutable lifecycle/rotation evidence. Requester-held issuance retains the original
  authorized CSR through renewal; the requester keeps the private key. The deprecated
  server-generated path records its separate custody and key-generation event.

  A fallback longer than the certificate's entire lifetime must not cause renewal on
  every sweep. New endpoint leaves issued by the platform or a selected private CA
  retain the actual signing constructor's validity timestamp. When `renew_before` is
  at least the interval from that timestamp to signed expiry, the scheduler waits for
  the ARI window. Thus a new 30-day leaf with a 30-day lead does not immediately renew.
  A 47-day leaf with a 30-day lead still becomes due around day 17; this repair does
  not shorten the configured lead or postpone that deadline. The automation plan uses
  the same decision as the scheduler.
- **Revoke with propagation.** `Revoke(certID, reason)` is idempotent, updates the
  inventory, enqueues a `revocation.publish` to the [outbox](../glossary.md) in the same
  transaction so a crash can't drop it, and emits `certificate.revoked`.
- **Alert before expiry.** It finds certificates inside the `alert_before` window,
  enriches the alert with the owner and approver recipients, enqueues a notification,
  stamps `alerted_at` so it doesn't nag, and emits `certificate.expiring`.
- **The CA calendar.** CA authorities run on their own clock. A leaf that expires is a
  page; a root that expires is an outage across every leaf beneath it, and the fix — get
  a new anchor into every relying party — takes quarters, not an afternoon. So the same
  sweep also walks `ca_authorities.not_after` against year-scale bands (36, 24, 12, 6
  and 3 months), alerting once per band an authority crosses into, with severity scaled
  to the runway: a planning signal beyond a year, a warning inside one, critical inside
  three months. It also flags the failure that hides — an authority with less life left
  than the validity its leaves are issued with, which silently truncates every new leaf
  while issuance keeps succeeding. Alerts carry the authority, the band, how many active
  certificates chain to it, and the date after which leaves stop getting full validity.

**The CA calendar's exact contract.** Bands are `36/24/12/6/3` months, evaluated against
an averaged Gregorian month; an authority sits in the tightest band it has crossed and
alerts only when it crosses into a tighter one, so a repeated sweep is silent and each
tightening re-fires. The band already notified is recorded on the authority and only ever
tightens, so a clock skew cannot re-fire an alert the operator already saw. Authorities
beyond 36 months, and authorities with no recorded `not_after`, raise nothing —
an unknown expiry is stated as unknown, not rendered as healthy. Alerts land on the
`notification.ca_horizon` outbox destination as `ca.horizon` or
`ca.validity_compression` and fan out through the same channels as expiry alerts. The
reference leaf validity is `lifecycle.leaf_validity`
(`TRSTCTL_LIFECYCLE_LEAF_VALIDITY`, default `2160h`/90 days); it is a yardstick for
horizon reporting and caps nothing. `GET /api/v1/ca/authorities` carries a `horizon`
object per authority (band, months remaining, severity, renew-by, whether truncation has
started, and the leaf validity assumed), and `GET /api/v1/certificates/health` now
resolves beyond 90 days into 180-day, 1-year, 2-year and 3-year bands — the flat
"later" bucket is exactly what hid multi-year hierarchy expiry.

**Status:** served by the running binary. A leader-only background loop scans
tenant-scoped deployed X.509 identities, honoring `lifecycle.renew_before` and
`lifecycle.alert_before` (both parsed and validated at startup), and writes the normal
`ca.renew` and `notification.expiry` outbox intents rather than acting inline. It's
integration-tested against real PostgreSQL, NATS, the signer process, and a signed
webhook sink.

`POST /api/v1/lifecycle/endpoint-bindings/preview` is the effect-free review path.
The operator must choose one exact built-in, private, or external CA; the response
names that CA, key custody, destination revision, planned records, queued effects,
recovery, verification, and the fingerprint that binds execution to the review.
`POST /api/v1/lifecycle/endpoint-bindings` accepts that fingerprint and is the served
end-to-end path for automated enrollment, provisioning, renewal, and endpoint
binding. It creates the X.509 identity, pins the issuer, binds the route, and queues
issue/deploy intents through the outbox. Initial issuance and renewal both use the
pinned authority; a missing or unavailable authority fails instead of falling back.
The issuer builds the deploy payload while the key is still in memory, so the
connector delivers the certificate/key bundle without PEM bytes ever returning from
the API response.

#### See and operate the live renewal plan

The **Machine identities → Lifecycle automation** panel answers the everyday operator
questions in one place:

- Is automatic renewal running, disabled, or waiting for a maintenance window?
- How many days before expiry does trstctl renew and alert?
- Which certificates are watched, due now, already in flight, or failed?
- Is lifecycle work waiting, processing, or failed in the durable outbox?
- Which actions are real, and where are the rotation, delivery, and rollback receipts?

The panel reads `GET /api/v1/lifecycle/automation-plan`; headless operators use the same
contract with `trstctl lifecycle automation-plan`. This is an effect-free preview: it
writes no row or event and contacts no CA, connector, or notification service. Its
tenant-scoped inventory includes public metadata only. Certificate bytes, private keys,
outbox payloads, and idempotency keys are not returned.

For a due or failed identity, **Review renewal now** or **Review retry** opens the normal
version-bound lifecycle transition preview before anything is queued. Execution then
appends the lifecycle event and the `ca.renew` outbox intent through the existing
idempotent mutation path. Verification comes from the resulting rotation run and
connector receipt, not from a green button state.

A failed agent attempt can leave the identity in `renewal_failed` while its
existing renewal job retries. Scheduled sweeps do not start another renewal while
that identity has pending or processing `ca.renew` or `endpoint.renew` work.
Manual renewal previews and execution return HTTP 409 with guidance to follow the
existing job. Once that work is terminal, a still-due identity can be renewed again.
Revocation remains available during recovery.

The control limits are intentional and visible:

- **Pause** is a maintenance-window configuration action. The current web request does
  not silently rewrite operator configuration.
- **Resume** is automatic when the next configured maintenance window opens.
- **Cancel after enqueue** is not offered. A worker may already have leased the command,
  so claiming it was cancelled could allow an unseen issuance or deployment to finish.
- **Rollback** is available through Connectors only when a deployed predecessor and a
  connector-backed rollback procedure exist. The rotation run keeps the public rollback
  reference used to verify that recovery.

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

The preferred UI/API entry point is the graph-bound action route,
`POST /api/v1/graph/crypto-readiness/actions`. It refuses a missing, foreign,
unlocated, or unattributed row, and stores the exact current readiness-row digest in
the immutable campaign-start event. Existing `/api/v1/pqc/campaigns` remains the
manual campaign API; those legacy/manual campaigns do not claim a graph binding.
Graph-bound campaigns refuse further mutation with `409 Conflict` when a dependent
edge or attributed owner changes. This prevents old coordination evidence from being
applied to a newly different blast radius.

Campaign mutations emit immutable `pqc.migration_campaign.*` events. PostgreSQL
projections carry `tenant_id` and forced row-level security. Closure is rejected until
the readiness gate passes and every selected finding is marked `remediated` or
`excepted` with a SHA-256 evidence digest. The closure artifact is signed by the
persistent audit key and binds the tenant, campaign, frozen finding digests,
dispositions, evidence digests, and timestamps; its included public JWKS permits
offline verification.

The canonical read and evidence routes are `GET /api/v1/graph/crypto-readiness` and
`GET /api/v1/graph/crypto-readiness/export`. The latter packages the same ordered
rows, owners, actions, evidence references, recommendations, and coverage limitation
as CSV and NDJSON, with an audit-key JWS and public JWKS for offline verification.

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

### Offline operator rehearsal

Run the licensed rehearsal from the repository root after the pinned Go modules,
container images, OpenSSL interop image, and bundled PostgreSQL artifact have been
supplied locally:

```sh
make pqc-operator-lab
```

The command runs the three exact shipped-binary definition-of-done proofs: pure
ML-DSA EST enrollment with stock OpenSSL, the classical/PQ SPIFFE SVID pair, and
CBOM migration plus rollback. It sets the Go module resolver offline and the
pinned interop runner uses `--pull=never`. The result is
`dist/pqc-operator-lab-licensed.tar.gz`.

Community operators use the same workflow with an edition selector:

```sh
make core-only pqc-operator-lab
```

That command builds and starts isolated `trstctl_core` control-plane and signer
binaries against private bundled PostgreSQL and embedded NATS data directories.
It proves that CBOM reading remains served and that `/v1/editions` reports PQC
execution as unavailable. It exits successfully without advertising or calling
the proprietary migration mutation.

Both archives contain a versioned manifest, one machine report and one public
transcript per stage, and `SHA256SUMS`. Archive construction rejects private-key
PEM, bearer credentials, trstctl API tokens, and non-empty password/secret/token
JSON fields. The command deletes only its own private runtime directory; the
receipt archive is the only retained output.

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
- **Unknown issuance time remains unknown.** Older records, external CA responses and
  protocol issuance paths that do not retain the constructor timestamp still use the
  existing fixed fallback alongside ARI. Discovery time and the backdated X.509
  `notBefore` are not substituted for issuance time. An older local leaf can therefore
  renew once before its new endpoint successor gains this protection; external
  successors without the timestamp can still repeat. This change covers the served
  identity scheduler and its plan, not the separate fixed-threshold
  `lifecycle.Manager.RenewExpiring` library method.
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
