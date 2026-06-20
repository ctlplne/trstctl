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

The signer is a separate, HTTP-less process (AN-4), so it cannot expose its own
`/metrics`; the control plane samples its health and restart count on a fixed
cadence and publishes them on the same registry as everything else. The sampler is
a background worker that stops cleanly on shutdown.

Routes are **normalized** — opaque path segments (UUIDs, long hex ids, numeric
ids) are collapsed to `:id` — so per-id paths do not explode label cardinality and
no identifier leaks into a label.

Scrape it with the example config in
[`deploy/observability/prometheus.example.yml`](https://github.com/imfeelingtheagi/trstctl/blob/main/deploy/observability/prometheus.example.yml).

## Tracing

Every request is part of a distributed trace using the **W3C Trace Context**
standard, so it interoperates with OpenTelemetry/Jaeger collectors on the wire:

- An inbound `traceparent` header is **continued**; otherwise a new trace starts.
- The trace id is returned on the response `traceparent` header and included in the
  structured access log, so a request is correlatable end to end.
- The trace **spans subsystems**: the readiness probes for PostgreSQL, NATS, and
  the signer run as child spans of the request, so one trace shows where time goes
  across dependencies.

!!! note "OTLP export is a follow-up"
    The trace model is OpenTelemetry-shaped and W3C-`traceparent`-compatible on
    the wire today. Exporting spans over **OTLP** to a collector is wired behind a
    pluggable exporter seam (`observ.Exporter`) and is a tracked follow-up; the
    control plane does not bundle the OTel SDK yet.

## Structured logs

The control plane logs in **structured JSON** (or text — set `TRSTCTL_LOG_FORMAT`)
via `log/slog`, wired into the serving path. Each request emits one access-log
record carrying the **`trace_id`** correlation field plus the method, normalized
route, status, response size, and duration.

Logs contain **zero secret material** (AN-8): the access log never records the
`Authorization` header, the request body, or the query string — only the method,
the normalized route, and the status. This is asserted by a test.

## Dashboards & alerts

Baseline operator assets ship under
[`deploy/observability/`](https://github.com/imfeelingtheagi/trstctl/tree/main/deploy/observability):

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

Observability is a default of the codebase, not a per-sprint afterthought: a new
serving surface or background worker registers its metrics, structured logs,
health/readiness, and tracing through the shared `internal/observ` library (the
same `Registry`, `Middleware`, `Readiness`, `Tracer`, and the `SignerMetrics`-style
helpers) rather than rolling its own. Background workers take a context and stop on
cancellation so shutdown stays graceful. New `trstctl_` alert metrics are held to
the same reality test, so a dashboard or alert can never reference a metric the code
does not emit.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `TRSTCTL_LOG_FORMAT` | `json` | `json` or `text`. |

`/metrics` and `/readyz` are always served and unauthenticated; restrict them at
your ingress / network policy if you do not want them publicly reachable.
