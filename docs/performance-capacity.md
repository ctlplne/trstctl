# Performance Capacity And Cost Model

This capacity model translates the committed performance SLOs into right-sizing
guidance. It is tied to the measured smoke artifact at
`scripts/perf/artifacts/smoke-baseline.json` and the served live-load artifact at
`scripts/perf/artifacts/live-load-baseline.json`. Storage, resource, and cost rows
are recalculated from the capacity calibration artifact at
`scripts/perf/artifacts/capacity-measurement-baseline.json`. Event-spine burst and
drain behavior is pinned by
`scripts/perf/artifacts/spine-burst-cap-small.json`; operators should replace the
cost column with their infrastructure pricing, but should not remove the measured
unit rows.

## Capacity Tiers

| Tier | Deployment shape | Tenants | Managed credentials | Events/day | PostgreSQL 30d | JetStream 30d | Control plane | Signer | Est. monthly cost | Est. cost/credential |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | ---: |
| CAP-SMALL | single-node regulated evaluation | 5 | 25,000 | 250,000 | 8.1 GiB | 18 GiB | 2 vCPU / 4 GiB | 1 vCPU / 1 GiB | $420 | $0.0168 |
| CAP-MEDIUM | external datastore production | 50 | 250,000 | 2,500,000 | 73 GiB | 173 GiB | 6 vCPU / 12 GiB | 2 vCPU / 2 GiB | $1,880 | $0.0075 |
| CAP-LARGE | multi-replica enterprise | 250 | 1,000,000 | 10,000,000 | 282 GiB | 690 GiB | 16 vCPU / 32 GiB | 6 vCPU / 8 GiB | $5,590 | $0.0056 |

## Measured Units

`scripts/perf/run-capacity-calibration.sh` starts embedded PostgreSQL, applies the
real migrations, inserts representative tenant rows, reads
`pg_total_relation_size`, appends representative events to embedded JetStream with
`SyncAlways`, and reads the committed served live-load resource counters. The live
artifact is valid only when it carries component counters for the control plane,
signer, PostgreSQL, and JetStream. The capacity rows above use these measured units
with 30 days of event retention and a 1.35x headroom multiplier.

| Artifact ID | Unit | Measured value | Measurement source | Why it matters |
| --- | --- | ---: | --- | --- |
| `postgres_certificate_row` | Certificate read-model row with indexes | 738 bytes/row | `pg_total_relation_size('certificates')` over 1,000 inserted rows | Drives PostgreSQL growth for inventory-heavy tenants. |
| `postgres_credential_row` | Sealed credential row with unique tenant index | 779 bytes/row | `pg_total_relation_size('credentials')` over 1,000 inserted rows | Drives PostgreSQL growth for connector, issuer, and secret-adjacent credential rows. |
| `postgres_managed_credential` | Managed credential PostgreSQL unit | 1,517 bytes/credential | Certificate row plus sealed credential row | Drives CAP PostgreSQL tier math before base/headroom assumptions. |
| `jetstream_event` | Event envelope in embedded JetStream file store | 979 bytes/event | File-store byte delta after 1,000 representative tenant lifecycle events | Drives source-of-truth event-log growth and backup size. |
| `audit_record_json` | Tenant-facing audit record JSON | 754 bytes/record | `json.Marshal(audit.Record)` for an actor-attributed mutation | Keeps audit export size tied to the event-log projection model. |
| `live_peak_memory` | Served live profile peak memory | 83,745,048 bytes | `scripts/perf/artifacts/live-load-baseline.json` | Bounds control-plane memory rows before customer workload headroom. |
| `component_resource_metrics` | Full-product process/container counters | `control_plane`, `signer`, `postgresql`, and `jetstream` | `component_resource_metrics` in the live-load and capacity artifacts | Prevents capacity signoff from inheriting only the control-plane aggregate. |
| `signer_rpc_peak_throughput` | Signer RPC peak live throughput | 7,688.7655 requests/sec | `signer.rpc` peak phase in the live-load artifact | Confirms the capacity signer row is backed by the child signer process footprint. |
| `projection_replay_peak_throughput` | Projection replay live throughput | 8,952.6667 events/sec | `spine.projection_replay` peak phase in the live-load artifact | Confirms replay can exceed the 500 events/sec floor in the served profile. |
| `postgres_calibration_connections` | PostgreSQL calibration connections | 2 connections | Calibration run `pg_stat_activity` count | Keeps the capacity artifact aware of connection footprint instead of omitting it. |

## Event-Spine Burst Receipt

`scripts/perf/run-spine-burst.sh` runs the same embedded-PostgreSQL/JetStream
replay-and-outbox-drain mechanism as [performance.md](performance.md)'s spine-burst
gate, scaled per capacity tier — see there for how it works.

The committed cap-small receipt captures:

- 5 tenants and 50 seeded agents.
- 1,000 event-log appends and 250 outbox intents.
- Projection lag, outbox backlog, queue rejects, DB-pool utilization, p95/p99
  latency, heap/RSS, goroutines, file descriptors, and storage growth.
- A slow upstream destination whose backlog must stay bounded instead of growing
  without limit.

The same harness has PERF/RUNOPS external profiles for the larger capacity rows:

| Profile | Capacity tier | Datastore requirement | Default burst workload | Artifact |
| --- | --- | --- | --- | --- |
| `cap-medium` | CAP-MEDIUM | `TRSTCTL_POSTGRES_DSN` plus `TRSTCTL_NATS_URL`, default `TRSTCTL_NATS_REPLICAS=3` | 50 tenants, 500 seeded agents, 10,000 events, 2,500 outbox intents | `scripts/perf/artifacts/spine-burst-cap-medium.json` |
| `cap-large` | CAP-LARGE | `TRSTCTL_POSTGRES_DSN` plus `TRSTCTL_NATS_URL`, default `TRSTCTL_NATS_REPLICAS=3` | 250 tenants, 2,000 seeded agents, 40,000 events, 10,000 outbox intents | `scripts/perf/artifacts/spine-burst-cap-large.json` |

Run them with `SPINE_BURST_PROFILE=cap-medium make spine-burst` or
`SPINE_BURST_PROFILE=cap-large make spine-burst` against a dedicated
PostgreSQL/JetStream cluster; these fail closed without a real external
datastore, and a single-replica run still needs
`TRSTCTL_NATS_ALLOW_SINGLE_REPLICA=true`.

The cost model uses visible monthly unit inputs: PostgreSQL storage at
`$0.16/GiB`, JetStream storage at `$0.10/GiB`, control-plane compute at `$55/vCPU`
and `$8/GiB`, signer compute at `$75/vCPU` and `$10/GiB`, plus each tier's explicit
base operating cost. These are product-calibration defaults, not a customer quote.

## Scale Triggers

Move from `CAP-SMALL` to `CAP-MEDIUM` when any of these becomes true:

- More than 5 tenants or 25,000 managed credentials.
- More than 250,000 events/day.
- Projection lag exceeds 25 events during the smoke profile.
- The served live-load `realistic` phase misses any p95 or throughput SLO.
- API, protocol, or signing queue saturation exceeds 80% in normal operation.

Move from `CAP-MEDIUM` to `CAP-LARGE` when any of these becomes true:

- More than 50 tenants or 250,000 managed credentials.
- More than 2,500,000 events/day.
- Replay/rebuild windows exceed the recovery-time objective in
  `docs/disaster-recovery.md`.
- The served live-load `peak` phase misses any p99, max-latency, or throughput SLO.
- Signer CPU is the limiting resource while control-plane API workers still have
  headroom. The signer scales separately by design.

## Artifact Contract

Release CI and review publish three JSON artifacts as release-gating evidence,
each requiring `summary.ok: true`:

- The **perf smoke artifact** (`scripts/perf/artifacts/smoke-baseline.json`) needs
  one `met: true` result per `PERF-SLO-*` row in [performance.md](performance.md)
  and must name the capacity tiers above.
- The **served live-load artifact**
  (`scripts/perf/artifacts/live-load-baseline.json`) needs `served_stack: true`
  and its stack profile, an `event_spine_burst` reference to the CAP-SMALL
  spine-burst receipt plus the capture-and-soak command,
  `component_resource_metrics` for the control plane, signer, PostgreSQL, and
  JetStream, and one `realistic` plus one `peak` result (p50/p95/p99/max latency,
  throughput, error count, queue saturation, projection lag, resource metrics,
  `met: true`) per row.
- The **capacity calibration artifact**
  (`scripts/perf/artifacts/capacity-measurement-baseline.json`, produced by
  `scripts/perf/run-capacity-calibration.sh`) needs measured PostgreSQL row
  deltas, JetStream file-store deltas, live resource counters, connection count,
  signer footprint, and `component_resource_metrics`; its `derived_capacity_tiers`
  must match the served CAP-SMALL/CAP-MEDIUM/CAP-LARGE rows, and its referenced
  live artifact must be the served-route stack with `realistic`/`peak` results,
  not synthetic self-test counters.

The scheduled soak, spine-burst, and external CAP-MEDIUM/CAP-LARGE receipts follow
the same pass/fail contract as [performance.md](performance.md): each input series
must come from the real capture/burst scripts, not a synthetic self-test series,
`scripts/perf/soak.sh --in` must produce a trend report with `summary.ok: true`
carrying `input_evidence`, and the induced-leak self-test must still fail as
expected. The spine-burst variant additionally records embedded PostgreSQL,
embedded JetStream, seeded tenants/agents, event-log replay, outbox drain,
slow-upstream backlog, projection lag, queue rejects, and DB-pool utilization; the
external CAP-MEDIUM/CAP-LARGE receipts are PERF/RUNOPS release-review evidence
whose series source records `external-postgresql+external-jetstream` (the default
scheduled CI gate stays CAP-SMALL so CI never depends on an operator-managed
external cluster).

The same capacity denominator is served through
`GET /api/v1/scale/orchestration` and `trstctl-cli scale orchestration`:
CAP-SCALE-01 posture chooses the 1M-credit `CAP-LARGE` tier, names the
100k/250k/1M credential bands, and exposes the execution lanes, sharding plan,
release gates, and operator residuals without claiming a specific customer
infrastructure SKU — naming all three base measurement artifacts plus the
spine-burst receipt at `scripts/perf/artifacts/spine-burst-cap-small.json`.
