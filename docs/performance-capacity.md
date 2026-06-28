# Performance Capacity And Cost Model

This capacity model translates the committed performance SLOs into right-sizing
guidance. It is tied to the measured smoke artifact at
`scripts/perf/artifacts/smoke-baseline.json` and the served live-load artifact at
`scripts/perf/artifacts/live-load-baseline.json`; operators should replace the
cost column with their infrastructure pricing, but should not remove the unit rows.

## Capacity Tiers

| Tier | Deployment shape | Tenants | Managed credentials | Events/day | PostgreSQL 30d | JetStream 30d | Control plane | Signer | Est. monthly cost | Est. cost/credential |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | ---: |
| CAP-SMALL | single-node regulated evaluation | 5 | 25,000 | 250,000 | 20 GiB | 35 GiB | 2 vCPU / 4 GiB | 1 vCPU / 1 GiB | $450 | $0.0180 |
| CAP-MEDIUM | external datastore production | 50 | 250,000 | 2,500,000 | 180 GiB | 320 GiB | 6 vCPU / 12 GiB | 2 vCPU / 2 GiB | $4,200 | $0.0168 |
| CAP-LARGE | multi-replica enterprise | 250 | 1,000,000 | 10,000,000 | 700 GiB | 1,200 GiB | 16 vCPU / 32 GiB | 6 vCPU / 8 GiB | $14,500 | $0.0145 |

## Storage Units

The planning constants are deliberately conservative until a customer-specific
load run replaces them:

| Unit | Planning value | Why it matters |
| --- | ---: | --- |
| Event envelope, compressed JetStream segment | 2.5 KiB/event | Drives source-of-truth log growth and backup size. |
| Certificate read-model row with indexes | 3.0 KiB/certificate | Drives PostgreSQL table and index growth for inventory-heavy tenants. |
| Secret version metadata plus sealed payload pointer | 4.0 KiB/version | Drives secret-store projection growth; secret bytes stay encrypted. |
| CRL publication event with DER payload | 16 KiB/publication | Drives revocation freshness storage for high-churn CAs. |
| Projection replay smoke floor | 500 events/sec | Minimum acceptable rebuild/replay throughput for the committed smoke profile. |
| Signer RPC smoke floor | 100 requests/sec | Minimum request framing throughput before isolated signer crypto cost is included. |

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

The scheduled captured-soak artifact is valid only when:

- The input series came from `scripts/perf/capture-soak-series.sh` over the local
  eval-stack hot paths, not from a synthetic self-test series.
- `scripts/perf/soak.sh --in <series.json>` produced the trend report artifact.
- The induced leak substitute step used `scripts/perf/soak.sh --selftest-fail` and
  failed as expected.
- The trend report has `summary.ok: true`.
