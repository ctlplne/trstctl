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

The served live-load profile boots the local eval perf stack, drives each
HTTP-addressable `PERF-SLO-*` hot path through its production route family, and
exercises the signer path through the generated signer gRPC service in a separate
child process over a real Unix-domain socket. The stack uses an actual loopback HTTP
listener, bundled PostgreSQL, and embedded file-backed JetStream. The projection
row drives the event replay/apply loop directly because it is a worker surface, not
an HTTP endpoint. In plain terms: the harness enters through the same doors and
crosses the same process and storage boundaries as the product; it rejects test-only
HTTP routes, `httptest`, `bufconn`, and in-process signer shortcuts. Customer load
runs should repeat the profile with their production PostgreSQL, JetStream, and UDS
or mTLS signer placement.

```sh
make perf-live
scripts/perf/run-local.sh --profile live --out /tmp/trstctl-perf-live.json
```

The committed live receipt is
`scripts/perf/artifacts/live-load-baseline.json`. Each SLO row must have both
`realistic` and `peak` phase measurements with p50, p95, p99, max latency,
throughput, error count, queue saturation, projection lag, and resource metrics.
The receipt also carries an `event_spine_burst` reference to the CAP-SMALL
PostgreSQL/JetStream replay and bounded-outbox gate so live review does not lose
the heavier spine evidence.
It also carries `issuance_breakdown`, where `api.issuance` spends its time in each
phase, measured from timestamps only (no profiler runs during the gate, and no
threshold reads it): for every measured issuance, the wait for a pooled PostgreSQL
connection, PostgreSQL round trips (a pipelined batch is one), commits, the
idempotency claim and completion statements, event appends to JetStream, signer RPCs
(the signer's journal fsyncs are inside them) and the rest (HTTP, JSON and handler
work), reported as each field's median and the five slowest requests whole; the
PostgreSQL wait events sampled while the phase's issuances ran; and one timed 8 KiB
write+fsync on the work disk.
The live profile is still a local eval-stack receipt, not a promise that one vendor
SKU will satisfy every production tenant shape; customer capacity reviews should run
the same profile against their chosen datastore, signer placement, and connector mix.

`make test` builds the isolated signer before timed live work. The serial live
packages keep race detection and whole-repository atomic coverage for correctness;
both the live-load and soak-capture stack startups use the explicit four-minute
instrumented harness allowance. The exact
live mutation SLO test then runs once without race or coverage instrumentation,
with its original 90-second startup deadline and unchanged latency, throughput,
error, queue, and lag limits. `make test` prints every measurement and reports
SLO misses without failing the functional target; operation errors and stack
failures still fail it. Direct execution of the test still enforces the SLO.
Instrumented timings are never release performance evidence. Run the uncached
`make perf-live-wall` release gate alone on a quiet
machine against a stored baseline from that same machine and configuration:

```sh
PERF_LIVE_OUT=/path/on/this/host/live-baseline.json make perf-live
PERF_LIVE_BASELINE=/path/on/this/host/live-baseline.json \
  PERF_LIVE_OUT=/path/on/this/host/live-candidate.json make perf-live-wall
```

The first command saves the baseline only if the existing absolute SLOs pass.
Both receipts carry a hashed machine fingerprint. The second command fails on a
different host, incompatible phase/sample set, or an absolute SLO failure, and
prints p99 and throughput side by side; it adds no new relative SLO budget. Record
the two receipts and the host configuration with the release decision. CI's
scheduled `make perf-live` receipt is supplemental when its runner differs from
the baseline host.

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
`scripts/perf/artifacts/spine-burst-cap-small.json`. When that receipt is analyzed
with `scripts/perf/soak.sh --in`, the trend report includes `input_evidence` with
the source, workload, slow-upstream, appended/replayed event counts, and outbox
backlog summary from the burst.

PERF/RUNOPS can run the same harness against external capacity profiles:

```sh
export TRSTCTL_POSTGRES_DSN='postgres://trstctl:...@perf-db:5432/trstctl?sslmode=require'
export TRSTCTL_NATS_URL='nats://perf-nats:4222'
export TRSTCTL_NATS_REPLICAS=3
SPINE_BURST_PROFILE=cap-medium make spine-burst
SPINE_BURST_PROFILE=cap-large make spine-burst
```

`cap-medium` and `cap-large` fail closed without external PostgreSQL and external
JetStream, and write `spine-burst-cap-medium.json` or `spine-burst-cap-large.json`
unless `SPINE_BURST_OUT` overrides the path.

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

## Enterprise-scale harness

The enterprise-scale harness (A266) measures trstctl at estate size through its own API, on the same local eval stack
the live-load gate boots (embedded PostgreSQL, embedded JetStream, the signer as a child process):

```sh
make perf-scale
scripts/perf/run-scale.sh --inventory 100000 --renewals 2000 --clients 16 --out dist/scale/receipt.json
```

One run has three phases:

1. **Inventory.** `--inventory` certificates, described the way another product's export describes them and generated
   from `--seed` so a rerun imports the same rows, go through the switching kit: each export of at most `--chunk` rows
   (default 25,000) is previewed, applied against the preview's digest, and applied by the leader's bounded batches,
   each row becoming a certificate with its owner and application group.
2. **Fleet.** `--renewals` managed identities under a certificate profile with a short validity ceiling, each bound to
   its own AWS Certificate Manager target (an in-process ACM double that checks every request's SigV4 signature), are
   requested by `--clients` concurrent API clients, issued by the built-in CA and deployed to their targets.
3. **Renewal storm.** Once the last fleet certificate enters its renewal window, the last third of its life, the
   lifecycle scheduler's sweep finds the whole fleet due at once on the real clock, and the runtime's outbox dispatcher
   issues and deploys every successor while readers page the inventory. The wait before the storm, and the time the storm has before the
   first successor's own window opens, are both the storm budget: 200 ms a renewal, at least three minutes
   (`--fleet-lifetime` sets the fleet's full signed lifetime instead).

The JSON receipt records each phase's throughput and request latency, the storm's drain time, peak outbox depth and
read latency, the control plane's, signer's, PostgreSQL's and JetStream's resources, and every correctness gap; the run
exits non-zero on any of them: an import not completed with every row applied, a fleet identity not issued, deployed
and delivered exactly once, a fleet identity not renewed or renewed twice, a successor its target does not hold, or a
dead letter. CI runs the harness at CI scale on every push (`a266 scale smoke`, 3,000 certificates and a 40-renewal
storm) and keeps the receipt as a workflow artifact.

The committed receipt is `scripts/perf/artifacts/scale-local-baseline.json`: one Mac (arm64, 10 CPUs, embedded
datastores), 100,000 certificates and a 2,000-renewal storm with 16 clients. The four 25,000-row exports were previewed
and applied in 6.0 s and the leader recorded them at 164.5 certificates a second (608 s). The fleet's 2,000 identities
were requested in 6.2 s (p95 69 ms) and issued and delivered to their ACM targets in 161 s (12.4 a second). The storm
renewed and delivered all 2,000 in 393 s (5.1 a second), none twice and with no dead letter, while eight readers paged
the inventory 166,706 times at p95 27 ms. The control plane peaked at 404 MiB and the database at 220 MiB.

A tenant's renewals are delivered one at a time: issuance and renewal share one outbox lane per tenant, and the outbox
runs at most one entry per lane and two per tenant, so a storm's rate is one over a renewal's time (about 0.2 s here).
What comes next is a lane per identity with configurable caps, so a tenant's storm can use the workers it is given, and
the published million-certificate run across several hosts on external PostgreSQL and JetStream.

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

The enterprise-scale harness:

```sh
make perf-scale
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
receipt at `scripts/perf/artifacts/spine-burst-cap-small.json`, the enterprise-scale
receipt at `scripts/perf/artifacts/scale-local-baseline.json`, and the capacity
model in `docs/performance-capacity.md`.

CAP-SCALE-01 is also served as operator-facing posture: `GET
/api/v1/scale/orchestration` and `trstctl-cli scale orchestration` return the 100k,
250k, and 1M credential bands, execution lanes, bulkhead/backpressure controls,
release gates, and residuals tied to this performance contract.

CAP-SCALE-02 is a regional HA issuance **reference architecture**: `GET
/api/v1/scale/ha-issuance` and `trstctl-cli scale ha-issuance` return example regional
ingress lanes, tenant write fences, failover gates, and 5s/30s RPO/RTO **targets**.
`served: true` means the contract route is available; `evidence_scope:
reference_architecture` makes clear that this response does not discover deployed
regions or measure recovery. Qualify each installation with regional issue/renew/revoke
smoke and a multi-host failover drill before claiming HA or those objectives. The
targets assume a healthy shared or promoted PostgreSQL writer endpoint, replicated
JetStream event log, isolated signer placement, and green regional smoke. Independent
split-brain writers remain unsupported.
