# Performance SLOs

This page is the committed performance contract for the served trstctl hot paths.
It is intentionally concrete: every row has a `PERF-SLO-*` identifier, an owner,
latency targets, a minimum smoke-throughput target, queue/projection limits, and a
benchmark name. The local smoke gate writes the current measurement receipt:

```sh
scripts/perf/run-local.sh --profile smoke --out /tmp/trstctl-perf-smoke.json
```

The committed baseline receipt is `scripts/perf/artifacts/smoke-baseline.json`.
The smoke profile is a fast CI guard over representative product code paths. It is
not a substitute for the served live-load receipt, a multi-hour soak, or a
customer-specific load test, but it turns the hot-path denominator into executable
release evidence.

## Served live-load gate

The served live-load profile boots the local eval perf stack, drives every
`PERF-SLO-*` hot path through an HTTP handler, and exercises the signer path through
the generated signer gRPC service over an in-memory `bufconn` transport. That keeps
the committed receipt runnable in restricted CI while still measuring the served
RPC request path rather than a protobuf-only library shortcut. Customer load runs
should swap the signer transport to their production UDS or mTLS placement.

```sh
make perf-live
scripts/perf/run-local.sh --profile live --out /tmp/trstctl-perf-live.json
```

The committed live receipt is
`scripts/perf/artifacts/live-load-baseline.json`. Each SLO row must have both
`realistic` and `peak` phase measurements with p50, p95, p99, max latency,
throughput, error count, queue saturation, projection lag, and resource metrics.
The live profile is still a local eval-stack receipt, not a promise that one vendor
SKU will satisfy every production tenant shape; customer capacity reviews should run
the same profile against their chosen datastore, signer placement, and connector mix.

The shipped Prometheus alert pack mirrors this table. The
`trstctl-slo-hot-paths` rule group in `deploy/observability/alerts.yml` records p99
latency and 5m/1h error ratios for every `PERF-SLO-*` row, then fires a latency
threshold alert and a 14.4x/6x multi-window burn-rate alert against the committed
0.10% error budget. `internal/observ` tests enumerate `internal/perf.HotPaths()`
and fail if a new SLO row lacks matching PromQL coverage. `PERF-SLO-007` and
`PERF-SLO-008` currently use served route-family alert denominators plus the direct
signer/projection health alerts; first-class signer RPC and projection replay
histograms remain the next precision upgrade.

## Endurance / soak gate

Sustained-load behavior — memory/heap/goroutine/FD leak slopes, DB-pool saturation,
projection/outbox lag, queue rejects, signer restarts, and storage growth — is held
to a pass/fail threshold contract by an executable **soak gate**:

```sh
make soak                      # self-test: an induced leak series MUST fail, a healthy series MUST pass
scripts/perf/soak.sh --in <series.json> --out <report.json>   # analyze a captured sustained-load series
make soak-capture              # capture local eval-stack samples, then analyze them with --in
make spine-burst               # capture embedded Postgres/JetStream replay + outbox burst, then analyze it with --in
```

The threshold contract and the trend analyzer are shared by this gate, `make soak`,
and these docs so they consume one denominator — the same pattern as the smoke gate.
The gate exits non-zero on a leak slope or an SLO breach and emits a JSON trend
report. The scheduled CI soak job captures a real local eval-stack series with
`scripts/perf/capture-soak-series.sh`, feeds that series into
`scripts/perf/soak.sh --in`, uploads the trend report, and separately proves an
induced leak substitute fails the gate.

The spine-burst gate is the focused event-spine capacity receipt for SPINE-002:

```sh
scripts/perf/run-spine-burst.sh --profile cap-small --out scripts/perf/artifacts/spine-burst-cap-small.json
scripts/perf/soak.sh --in scripts/perf/artifacts/spine-burst-cap-small.json
```

It starts embedded PostgreSQL, applies migrations, seeds tenants and agents, starts
embedded JetStream, appends the cap-small event workload, replay/decode-applies the
event log with a bounded projection-lag target, injects a slow upstream destination
through the outbox, and records projection lag, outbox backlog, queue rejects, DB
pool utilization, p95/p99 latency, and resource counters. The committed receipt is
`scripts/perf/artifacts/spine-burst-cap-small.json`.

| SLO | Hot path | Served surface | Owner | Benchmark | p50 / p95 / p99 target | Min throughput | Error budget | Queue / lag ceiling | Capacity ref |
| --- | --- | --- | --- | --- | --- | ---: | ---: | --- | --- |
| PERF-SLO-001 | `api.issuance` | `POST /api/v1/identities` plus served signer issuance | CORRECT/API | `BenchmarkIssuance` | 50 / 150 / 300 ms | 25/sec | 0.10% | queue <= 80%, lag <= 25 events | CAP-SMALL |
| PERF-SLO-002 | `api.inventory` | `GET /api/v1/certificates` and inventory pagination | API/STORE | `BenchmarkInventory` | 25 / 75 / 150 ms | 100/sec | 0.10% | queue <= 80%, lag <= 25 events | CAP-SMALL |
| PERF-SLO-003 | `api.graph_risk` | `/api/v1/graph/*` and `/api/v1/risk/*` | GRAPH/RISK | `BenchmarkGraphRiskQuery` | 75 / 250 / 500 ms | 20/sec | 0.10% | queue <= 80%, lag <= 25 events | CAP-MEDIUM |
| PERF-SLO-004 | `api.secrets` | `GET/PUT /api/v1/secrets/*` | SECRETS/CRYPTO | `BenchmarkSecrets` | 50 / 150 / 300 ms | 50/sec | 0.10% | queue <= 80%, lag <= 25 events | CAP-SMALL |
| PERF-SLO-005 | `protocol.enrollment` | ACME, EST, SCEP, CMP, SPIFFE, and SSH enrollment parsers | PROTOCOLS | `BenchmarkProtocolEnrollment` | 50 / 150 / 300 ms | 40/sec | 0.10% | queue <= 80%, lag <= 25 events | CAP-MEDIUM |
| PERF-SLO-006 | `revocation.ocsp_crl` | `POST /ocsp/{tenant}` and `GET /crl/{tenant}` | REVOCATION | `BenchmarkOCSPCRL` | 25 / 75 / 150 ms | 100/sec | 0.10% | queue <= 80%, lag <= 25 events | CAP-SMALL |
| PERF-SLO-007 | `signer.rpc` | `trustctl-signer` gRPC Sign/GenerateKey request path | SIGNING | `BenchmarkSignerRPC` | 25 / 75 / 150 ms | 100/sec | 0.10% | queue <= 70%, lag = 0 events | CAP-SMALL |
| PERF-SLO-008 | `spine.projection_replay` | event replay and projection decode/apply loop | SPINE/PROJECTIONS | `BenchmarkProjectionReplay` | 100 / 300 / 750 ms | 500 events/sec | 0.10% | queue <= 80%, lag <= 50 events | CAP-LARGE |

## Gates

The fast local gate:

```sh
scripts/perf/run-local.sh --profile smoke
```

The served local live-load gate:

```sh
make perf-live
scripts/perf/run-local.sh --profile live
```

The event-spine burst gate:

```sh
make spine-burst
```

The Go benchmark denominator (the `Benchmark*` targets named in the SLO table
above), and the broader benchmark discovery command used for release review:

```sh
go test -run '^$' -bench=. ./...
```

CI runs the smoke profile and uploads the JSON receipt as a workflow artifact.
Release review compares the smoke receipt, the served live-load receipt, the
capacity calibration receipt at
`scripts/perf/artifacts/capacity-measurement-baseline.json`, the spine-burst
receipt at `scripts/perf/artifacts/spine-burst-cap-small.json`, and the capacity
model in `docs/performance-capacity.md`.

CAP-SCALE-01 is also served as operator-facing posture: `GET
/api/v1/scale/orchestration` and `trstctl-cli scale orchestration` return the 100k,
250k, and 1M credential bands, execution lanes, bulkhead/backpressure controls,
release gates, and residuals tied to this performance contract.

CAP-SCALE-02 is served as regional HA issuance posture: `GET
/api/v1/scale/ha-issuance` and `trstctl-cli scale ha-issuance` return active regional
ingress lanes, tenant write fences, failover gates, and 5s/30s RPO/RTO targets. The
numbers assume a healthy shared or promoted PostgreSQL writer endpoint, replicated
JetStream event log, isolated signer placement, and green regional smoke. They do not
turn independent split-brain writers into a supported topology.
