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
not a substitute for a multi-hour soak or a customer-specific load test, but it
turns the hot-path denominator into executable release evidence.

## Endurance / soak gate (PERF-004)

Sustained-load behavior — memory/heap/goroutine/FD leak slopes, DB-pool saturation,
projection/outbox lag, queue rejects, signer restarts, and storage growth — is held
to a pass/fail threshold contract by an executable **soak gate**:

```sh
make soak                      # self-test: an induced leak series MUST fail, a healthy series MUST pass
scripts/perf/soak.sh --in <series.json> --out <report.json>   # analyze a captured sustained-load series
```

The threshold contract and the trend analyzer live in `internal/perf`
(`DefaultSoakThresholds`, `AnalyzeSoak`) so this gate, `make soak`, and these docs
consume one denominator — the same pattern as the smoke gate. The gate exits
non-zero on a leak slope or an SLO breach and emits a JSON trend report.

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

The Go benchmark denominator:

```sh
go test -run '^$' -bench=. ./internal/perf
```

The broader benchmark discovery command used for release review:

```sh
go test -run '^$' -bench=. ./internal/...
```

CI runs the smoke profile and uploads the JSON receipt as a workflow artifact.
Release review compares that artifact with the capacity model in
`docs/performance-capacity.md`.
