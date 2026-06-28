# Observability

trstctl's serving control plane is instrumented so an operator can answer "is it
healthy, and if not, where does it hurt" from telemetry alone (B6). Every request
is traced, counted, and access-logged, and the real dependencies are health- and
readiness-probed.

## Endpoints

| Path | Purpose | Auth |
| --- | --- | --- |
| `/healthz` | **Liveness** — the process is up and the signer (if configured) is reachable. | none |
| `/readyz` | **Readiness** — probes the real dependencies (PostgreSQL, NATS JetStream, the signer). Returns 200 when all are up, **503** with a per-dependency body when any is down. | none |
| `/metrics` | **Prometheus** metrics in the text exposition format. | none |

`/readyz` is what a Kubernetes readiness probe should target: when a dependency
drops, readiness flips to 503 and the pod is removed from rotation, while
`/healthz` (liveness) stays green so the pod is not killed for a transient
dependency blip.
For external NATS, readiness also verifies the event stream's durability contract:
if JetStream reports fewer replicas than `TRSTCTL_NATS_REPLICAS`, `/readyz`
returns degraded instead of serving with a weaker RPO than configured.

```bash
curl -fksS https://localhost:8443/readyz   # {"status":"ok","checks":{"db":"ok","nats":"ok","signer":"ok"}}
curl -fksS https://localhost:8443/metrics  # # TYPE trstctl_http_requests_total counter ...
```

## Metrics

The control plane emits, at minimum:

- **`trstctl_http_requests_total{method,route,code}`** — a counter of HTTP
  requests by method, normalized route, and status code.
- **`trstctl_http_request_duration_seconds{method,route}`** — a latency histogram
  (with `_bucket`, `_sum`, `_count`).
- **`trstctl_signer_up`** — `1` when the out-of-process signer is healthy, else `0`.
- **`trstctl_signer_restarts_total`** — cumulative relaunches of the signer child
  by the supervisor.
- **`trstctl_event_log_replicas_desired`** and
  **`trstctl_event_log_replicas_actual`** — configured vs observed JetStream
  replicas for the source-of-truth event stream; actual below desired is a
  durability incident and has a shipped alert rule.
- **`trstctl_projection_lag_events`** — how many source-of-truth events the read
  model is behind. This is the "API/UI might be old" gauge.
- **`trstctl_outbox_reconciliation_lag_events`** — how far boot reconciliation is
  behind the event-log head.
- **`trstctl_outbox_delivery_timeouts_total{tenant_id,destination}`** — outbox
  deliveries that exceeded their per-message execution timeout.
- **`trstctl_read_model_snapshots_written_total`**,
  **`trstctl_read_model_snapshot_last_success_timestamp_seconds`**, and
  **`trstctl_read_model_snapshot_failures_total`** — snapshot worker throughput,
  last successful write time, and failures.
- **`trstctl_crl_regenerated_total`**,
  **`trstctl_crl_last_regenerated_timestamp_seconds`**, and
  **`trstctl_crl_regeneration_failures_total`** — served CRL freshness work.
- **`trstctl_audit_retention_runs_total`**,
  **`trstctl_audit_retention_failures_total`**, and
  **`trstctl_audit_retention_last_success_timestamp_seconds`** — audit archive
  and retention worker health.
- **`trstctl_agent_enrollments_total{result}`** — bootstrap enrollment outcomes
  (`success` / `failed`).
- **`trstctl_agent_heartbeats_total{result}`** — served agent-channel heartbeat
  RPC outcomes (`success` / `failed`).
- **`trstctl_agent_bulkhead_rejections_total{method}`** — heartbeat or renewal
  RPCs shed by the agent-channel bulkhead.
- **`trstctl_agents_total`** and **`trstctl_agents_stale_total`** — fleet-wide
  aggregate counts; stale means the agent missed two configured heartbeat
  intervals. These are counts only, with no per-agent labels.

The signer is a separate, HTTP-less process, so it cannot expose its own
`/metrics`; the control plane samples its health and restart count on a fixed
cadence and publishes them on the same registry as everything else. The sampler is
a background worker that stops cleanly on shutdown.

Routes are **normalized** — opaque path segments (UUIDs, long hex ids, numeric
ids) are collapsed to `:id` — so per-id paths do not explode label cardinality and
no identifier leaks into a label.

Scrape it with the example config in
[`deploy/observability/prometheus.example.yml`](https://github.com/ctlplne/trstctl/blob/main/deploy/observability/prometheus.example.yml).

## Endurance / soak gate

Metrics existing is not the same as a metric being _gated_. The **soak gate** ties a
sustained-load profile to pass/fail thresholds so a slow leak or creeping saturation
fails CI instead of surfacing in production. It tracks, over a time-ordered series:
p95/p99 latency, RSS and heap, goroutines, open file descriptors, DB pool
utilization, queue rejections, signer restarts, projection lag, outbox lag, and
storage growth. The gate **fails** on either an SLO breach (a metric exceeds its
ceiling) or a **leak slope** (a gauge trends upward faster than its allowed
per-minute drift, even if no single sample breached a ceiling), and it emits a JSON
**trend report** so a regression is diagnosable.

The threshold contract and the trend analyzer are a single code-owned definition, so
the docs, the local gate, and CI share one denominator — the same pattern as the
hot-path smoke and served live-load gates. Run it via:

```sh
make soak                          # self-test: induced leak must fail, healthy must pass
make soak-capture                  # capture local eval-stack samples, then analyze with --in
scripts/perf/soak.sh --selftest-fail   # induced leak/saturation  -> exit non-zero
scripts/perf/soak.sh --selftest-ok     # healthy steady state     -> exit zero
scripts/perf/capture-soak-series.sh --out series.json
scripts/perf/soak.sh --in series.json --out trend.json   # analyze a captured run
```

The self-test modes make the gate provably correct, and the scheduled CI soak job
adds the heavyweight evidence: it captures a real local eval-stack series, feeds it
through `scripts/perf/soak.sh --in`, uploads the trend report, and verifies an
induced leak substitute fails.

## Tracing

Every request is part of a distributed trace using the **W3C Trace Context**
standard, so it interoperates with OpenTelemetry/Jaeger collectors on the wire:

- An inbound `traceparent` header is **continued**; otherwise a new trace starts.
- The trace id is returned on the response `traceparent` header and included in the
  structured access log, so a request is correlatable end to end.
- The trace **spans subsystems**: the readiness probes for PostgreSQL, NATS, and
  the signer run as child spans of the request, so one trace shows where time goes
  across dependencies.

## OTLP export

trstctl can stream served HTTP traces and event-sourced audit records to an
operator-owned OpenTelemetry collector over **OTLP/HTTP protobuf**. This is not
product telemetry and it does not phone home: it is disabled until you set your
own collector endpoint.

```bash
export TRSTCTL_OTLP_ENABLED=true
export TRSTCTL_OTLP_ENDPOINT=https://otel-collector.example.internal:4318
export TRSTCTL_OTLP_BEARER_TOKEN_FILE=/run/secrets/trstctl-otlp-token
```

For local collectors that listen on plaintext HTTP, make the downgrade explicit:

```bash
export TRSTCTL_OTLP_ENABLED=true
export TRSTCTL_OTLP_ENDPOINT=http://otel-collector:4318
export TRSTCTL_OTLP_INSECURE=true
```

The exporter posts spans to `/v1/traces` and audit records to `/v1/logs`, deriving
those signal paths from the endpoint you set. Trace spans include non-secret
request attributes such as `http.route` and `http.status_code`. Audit log records
include event metadata only: `trstctl.audit.type`, `trstctl.audit.id`,
`trstctl.audit.sequence`, `trstctl.audit.schema_version`, `trstctl.tenant.id`,
actor subject/roles when present, and payload byte count. The event payload itself
is not sent to the collector.

Trace export uses a bounded in-process queue. If the collector is slow or down,
served API requests keep their own backpressure behavior and telemetry is dropped
instead of blocking credential operations. Audit export runs as a leader-only
background worker and carries the event-stream sequence so Splunk, Datadog, or an
OpenTelemetry Collector pipeline can dedupe replayed records and alert on gaps.

## Structured logs

The control plane logs in **structured JSON** (or text — set `TRSTCTL_LOG_FORMAT`)
via `log/slog`, wired into the serving path. Each request emits one access-log
record carrying the **`trace_id`** correlation field plus the method, normalized
route, status, response size, and duration.

Logs contain **zero secret material**: the access log never records the
`Authorization` header, the request body, or the query string — only the method,
the normalized route, and the status. This is asserted by a test.

## Dashboards & alerts

Baseline operator assets ship under
[`deploy/observability/`](https://github.com/ctlplne/trstctl/tree/main/deploy/observability):

- **`alerts.yml`** — Prometheus alerting rules: control plane down, 5xx error rate
  above 5%, p99 latency above 1s, **signer down**, **signer restarting
  repeatedly**, event-log under-replication, async-spine lag, outbox delivery
  timeouts, snapshot staleness/failures, CRL staleness/failures, audit-retention
  failures, agent enrollment failures, heartbeat failure ratio, agent-channel
  bulkhead saturation, and stale-agent ratio. Every metric the rules reference is
  one the control plane actually emits (asserted by a test, so a rule can't
  reference a metric that does not exist). A reverse test also requires every
  ops-critical async/fleet metric to have alert coverage.
- **`dashboard.json`** — a Grafana dashboard: request rate, error ratio, latency
  percentiles, throughput by status code, and **signer up / restarts**.
- **`prometheus.example.yml`** — a ready-to-use scrape + rules config.

## Ops-critical signal matrix

| Failure mode | Primary metric | Alert |
| --- | --- | --- |
| Read model is old even though `/readyz` is green | `trstctl_projection_lag_events` | `TrstctlProjectionLagHigh` |
| Outbox boot reconciliation falls behind the event stream | `trstctl_outbox_reconciliation_lag_events` | `TrstctlOutboxReconciliationLagHigh` |
| External delivery hangs inside a connector/webhook | `trstctl_outbox_delivery_timeouts_total` | `TrstctlOutboxDeliveryTimeouts` |
| Snapshot worker fails or stops producing fresh boot accelerators | `trstctl_read_model_snapshot_failures_total`, `trstctl_read_model_snapshot_last_success_timestamp_seconds` | `TrstctlReadModelSnapshotFailures`, `TrstctlReadModelSnapshotStale` |
| CRL freshness fails and revocation data can go stale | `trstctl_crl_regeneration_failures_total`, `trstctl_crl_last_regenerated_timestamp_seconds` | `TrstctlCRLRegenerationFailures`, `TrstctlCRLFreshnessStale` |
| Audit archive/retention stops | `trstctl_audit_retention_failures_total`, `trstctl_audit_retention_last_success_timestamp_seconds` | `TrstctlAuditRetentionFailing`, `TrstctlAuditRetentionStale` |
| Agents cannot bootstrap | `trstctl_agent_enrollments_total{result="failed"}` | `TrstctlAgentEnrollmentFailures` |
| Agents reach the channel but heartbeat fails | `trstctl_agent_heartbeats_total{result="failed"}` | `TrstctlAgentHeartbeatFailures` |
| Fleet wave is too large for the agent bulkhead | `trstctl_agent_bulkhead_rejections_total` | `TrstctlAgentBulkheadSaturated` |
| Agents stop reporting after rollout or upgrade | `trstctl_agents_total`, `trstctl_agents_stale_total` | `TrstctlAgentFleetStale` |

## Plugging a new component in

Observability is a default of the platform, not an afterthought: a new serving
surface or background worker registers its metrics, structured logs,
health/readiness, and tracing through one shared observability library — the same
registry, request middleware, readiness checks, tracer, and signer-metrics helpers
— rather than rolling its own. Background workers stop cleanly on cancellation so
shutdown stays graceful. New `trstctl_` alert metrics are held to the same reality
test, so a dashboard or alert can never reference a metric the code does not emit.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `TRSTCTL_LOG_FORMAT` | `json` | `json` or `text`. |

`/metrics` and `/readyz` are always served and unauthenticated; restrict them at
your ingress / network policy if you do not want them publicly reachable.
