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
`SyncAlways`, and reads the committed served live-load resource counters. The
capacity rows above use these measured units with 30 days of event retention and a
1.35x headroom multiplier.

| Artifact ID | Unit | Measured value | Measurement source | Why it matters |
| --- | --- | ---: | --- | --- |
| `postgres_certificate_row` | Certificate read-model row with indexes | 738 bytes/row | `pg_total_relation_size('certificates')` over 1,000 inserted rows | Drives PostgreSQL growth for inventory-heavy tenants. |
| `postgres_credential_row` | Sealed credential row with unique tenant index | 779 bytes/row | `pg_total_relation_size('credentials')` over 1,000 inserted rows | Drives PostgreSQL growth for connector, issuer, and secret-adjacent credential rows. |
| `postgres_managed_credential` | Managed credential PostgreSQL unit | 1,517 bytes/credential | Certificate row plus sealed credential row | Drives CAP PostgreSQL tier math before base/headroom assumptions. |
| `jetstream_event` | Event envelope in embedded JetStream file store | 979 bytes/event | File-store byte delta after 1,000 representative tenant lifecycle events | Drives source-of-truth event-log growth and backup size. |
| `audit_record_json` | Tenant-facing audit record JSON | 754 bytes/record | `json.Marshal(audit.Record)` for an actor-attributed mutation | Keeps audit export size tied to the event-log projection model. |
| `live_peak_memory` | Served live profile peak memory | 20,220,168 bytes | `scripts/perf/artifacts/live-load-baseline.json` | Bounds control-plane memory rows before customer workload headroom. |
| `signer_rpc_peak_throughput` | Signer RPC peak live throughput | 12,681.3231 requests/sec | `signer.rpc` peak phase in the live-load artifact | Confirms the capacity signer row is not just a planning-only placeholder. |
| `projection_replay_peak_throughput` | Projection replay live throughput | 186,974.8636 events/sec | `spine.projection_replay` peak phase in the live-load artifact | Confirms replay can exceed the 500 events/sec floor in the served profile. |
| `postgres_calibration_connections` | PostgreSQL calibration connections | 1 connection | Calibration run `pg_stat_activity` count | Keeps the capacity artifact aware of connection footprint instead of omitting it. |

## Event-Spine Burst Receipt

`scripts/perf/run-spine-burst.sh --profile cap-small --out
scripts/perf/artifacts/spine-burst-cap-small.json` starts embedded PostgreSQL,
applies the production migrations, seeds tenants and agents, starts embedded
JetStream, appends a cap-small event burst, replay/decode-applies the event log,
and pushes a bounded slow-upstream backlog through the outbox. The same
`scripts/perf/soak.sh --in` analyzer used by the endurance gate turns that series
into a pass/fail trend report.

The committed cap-small receipt captures:

- 5 tenants and 50 seeded agents.
- 1,000 event-log appends and 250 outbox intents.
- Projection lag, outbox backlog, queue rejects, DB-pool utilization, p95/p99
  latency, heap/RSS, goroutines, file descriptors, and storage growth.
- A slow upstream destination whose backlog must stay bounded instead of growing
  without limit.

The cost model in the artifact uses visible monthly unit inputs: PostgreSQL
storage at `$0.16/GiB`, JetStream storage at `$0.10/GiB`, control-plane compute
at `$55/vCPU` and `$8/GiB`, signer compute at `$75/vCPU` and `$10/GiB`, plus each
tier's explicit base operating cost. These are product-calibration defaults, not
a customer quote.

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

Release CI must publish the perf smoke JSON artifact. The artifact is valid only
when:

- It has one result for every `PERF-SLO-*` row in `docs/performance.md`.
- Every result has `met: true`.
- The artifact names the capacity tiers above.
- `summary.ok` is true.

Release review must also publish the served live-load JSON artifact. The live
artifact is valid only when:

- It has `served_stack: true` and names the stack profile used for the run.
- It has one `realistic` and one `peak` result for every `PERF-SLO-*` row.
- Every result carries p50, p95, p99, max latency, throughput, error count, queue
  saturation, projection lag, and resource metrics.
- Every result has `met: true` and `summary.ok` is true.

Release CI must publish the capacity calibration JSON artifact. The capacity
artifact is valid only when:

- It names `scripts/perf/artifacts/capacity-measurement-baseline.json`.
- It was produced by `scripts/perf/run-capacity-calibration.sh`.
- It carries measured PostgreSQL row deltas, JetStream file-store deltas, live
  resource counters, connection count, and signer footprint.
- The referenced live artifact is rejected unless it is the served-route stack
  profile with `realistic` and `peak` results for every hot path; synthetic
  self-test counters are not valid capacity signoff inputs.
- `derived_capacity_tiers` matches the CAP-SMALL, CAP-MEDIUM, and CAP-LARGE rows
  served by `GET /api/v1/scale/orchestration`.
- `summary.ok` is true.

The scheduled captured-soak artifact is valid only when:

- The input series came from `scripts/perf/capture-soak-series.sh` over the local
  eval-stack hot paths, not from a synthetic self-test series.
- `scripts/perf/soak.sh --in <series.json>` produced the trend report artifact.
- The induced leak substitute step used `scripts/perf/soak.sh --selftest-fail` and
  failed as expected.
- The trend report has `summary.ok: true`.

The scheduled spine-burst artifact is valid only when:

- The input series came from `scripts/perf/run-spine-burst.sh --profile cap-small`,
  not from a synthetic self-test series.
- The artifact names `scripts/perf/artifacts/spine-burst-cap-small.json`.
- The artifact records embedded PostgreSQL, embedded JetStream, seeded tenants and
  agents, event-log replay, outbox drain, slow-upstream backlog, projection lag,
  queue rejects, and DB-pool utilization.
- `scripts/perf/soak.sh --in <spine-burst.json>` exits successfully and the trend
  report has `summary.ok: true`.

The same capacity denominator is served through
`GET /api/v1/scale/orchestration` and `trstctl-cli scale orchestration`. That
CAP-SCALE-01 posture chooses the 1M-credit `CAP-LARGE` tier, names the 100k/250k/1M
credential bands, and exposes the execution lanes, sharding plan, release gates, and
operator residuals without claiming a specific customer infrastructure SKU. The
served plan names all three base measurement artifacts, including
`scripts/perf/artifacts/capacity-measurement-baseline.json`, plus the spine-burst
receipt at `scripts/perf/artifacts/spine-burst-cap-small.json`.
