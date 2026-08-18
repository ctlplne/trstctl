# Observability

trstctl's control plane is instrumented so an operator can answer "is it healthy,
and if not, where does it hurt" from telemetry alone (B6): every request is
traced, counted, and access-logged, and the real dependencies are health- and
readiness-probed.

## Endpoints

| Path | Purpose | Auth |
| --- | --- | --- |
| `/healthz` | **Liveness** — the process is up and the signer (if configured) is reachable. | none |
| `/readyz` | **Readiness** — probes PostgreSQL, NATS JetStream, the durable projection tail, and the signer; returns `200` when all are trustworthy, `503` with a per-dependency body otherwise. | none |
| `/metrics` | **Prometheus** metrics in the text exposition format. | none |

`/readyz` is the Kubernetes readiness-probe target: a dropped dependency flips it
to 503 and removes the pod from rotation, while `/healthz` (liveness) stays green
so a transient blip does not get the pod killed. For external NATS, readiness also
checks the event stream's durability: fewer JetStream replicas than
`TRSTCTL_NATS_REPLICAS` degrades `/readyz` rather than serve with a weaker RPO than
configured. Projection readiness reads the persisted projection checkpoint. If
the tail cannot apply a sequence, it records that failed sequence before it
retries and `/readyz` returns 503. A normal short-lived positive lag does not flap
readiness; only a recorded failure that still lies ahead of the applied
checkpoint degrades it. The response contains safe sequence and lag numbers, not
the stored database error or event payload. Set `TRSTCTL_CA_FILE` to the inspected
public evaluation CA or the operator-managed production CA before probing HTTPS;
do not train monitors to disable certificate verification.

```bash
curl -fsS --cacert "$TRSTCTL_CA_FILE" https://localhost:8443/readyz # {"status":"ok","checks":{"db":"ok","nats":"ok","projection":"ok","signer":"ok"}}
curl -fsS --cacert "$TRSTCTL_CA_FILE" https://localhost:8443/metrics
```

The leader retries a failed projection tail. Once it applies the failed sequence,
the same checkpoint update advances the cursor and clears the durable failure
marker atomically, so readiness recovers without restarting the control plane.
The event projection itself commits before that checkpoint update. Do not edit
the checkpoint by hand: preserve PostgreSQL and JetStream, inspect the named
sequence in the logs, and fix the database, schema, or producer fault that made
the immutable event fail.

Metadata sampling, backup-restore fencing, replay, and the durable tail may read
the same JetStream generation at the same time. trstctl pins the durable generation
name under the history barrier but resolves a private NATS client handle for each
operation. This matters because the NATS `Stream` object contains a mutable metadata
cache: sharing that object between `Info` and message reads is not concurrency-safe.
The private handles isolate only client memory; they do not create another event
stream, weaken the generation fence, or serialize unrelated readers.

## Metrics

The control plane emits, at minimum:

- `trstctl_http_requests_total{method,route,code}` — HTTP request counts by
  method, normalized route, and status code.
- `trstctl_http_request_duration_seconds{method,route}` — a latency histogram
  (with `_bucket`, `_sum`, `_count`).
- `trstctl_signer_up` — `1` when the out-of-process signer is healthy, else `0`.
- `trstctl_signer_restarts_total` — cumulative signer-child relaunches by the
  supervisor.
- `trstctl_event_log_replicas_desired` and `trstctl_event_log_replicas_actual` —
  configured vs. observed JetStream replicas; actual below desired is a
  durability incident with a shipped alert.
- `trstctl_projection_lag_events` — how many events the read model is behind (the
  "API/UI might be old" gauge).
- `trstctl_outbox_reconciliation_lag_events` — how far boot reconciliation is
  behind the event-log head.
- `trstctl_outbox_delivery_timeouts_total{tenant_id,destination}` — outbox
  deliveries that exceeded their per-message execution timeout.
- `trstctl_read_model_snapshots_written_total`,
  `trstctl_read_model_snapshot_last_success_timestamp_seconds`, and
  `trstctl_read_model_snapshot_failures_total` — snapshot worker throughput, last
  successful write time, and failures.
- `trstctl_crl_regenerated_total`, `trstctl_crl_last_regenerated_timestamp_seconds`,
  and `trstctl_crl_regeneration_failures_total` — served CRL freshness work.
- `trstctl_audit_retention_runs_total`, `trstctl_audit_retention_failures_total`,
  and `trstctl_audit_retention_last_success_timestamp_seconds` — audit archive and
  retention worker health.
- `trstctl_agent_enrollments_total{result}` and `trstctl_agent_heartbeats_total{result}`
  — bootstrap enrollment and served agent-channel heartbeat RPC outcomes (`success`
  / `failed`).
- `trstctl_agent_bulkhead_rejections_total{method}` — heartbeat or renewal RPCs
  shed by the agent-channel bulkhead.
- `trstctl_agents_total` and `trstctl_agents_stale_total` — fleet-wide aggregate
  counts; stale means two missed configured heartbeat intervals (counts only, no
  per-agent labels).

The signer is a separate, HTTP-less process with no `/metrics` of its own; the
control plane samples its health and restart count on a fixed cadence onto the same
registry via a background worker that stops cleanly on shutdown.

Routes are normalized — opaque path segments (UUIDs, long hex ids, numeric ids)
collapse to `:id` — so per-id paths do not explode label cardinality, and no
identifier leaks into a label.

Scrape it with the example config in
[`deploy/observability/prometheus.example.yml`](https://github.com/ctlplne/trstctl/blob/main/deploy/observability/prometheus.example.yml).

## Endurance / soak gate

Metrics existing is not the same as being _gated_: the soak gate binds a
sustained-load profile to pass/fail thresholds so a slow leak or creeping
saturation fails CI instead of surfacing in production. The gate, its self-test
modes, and the scheduled CI soak job are the same mechanism documented in
[performance.md](performance.md); run `make soak` (self-test) or `make
soak-capture` (capture local eval-stack samples, then analyze with
`scripts/perf/soak.sh --in`) against this page's own metrics.

## Tracing

Every request is part of a distributed trace using the W3C Trace Context standard,
so it interoperates with OpenTelemetry/Jaeger collectors on the wire:

- An inbound `traceparent` header is continued; otherwise a new trace starts.
- The trace id also returns on the response `traceparent` header and lands in the
  structured access log, so a request is correlatable end to end.
- The trace spans subsystems: the readiness probes for PostgreSQL, NATS, and the
  signer run as child spans of the request, so one trace shows where time goes.

## OTLP export

trstctl can stream served HTTP traces and event-sourced audit records to an
operator-owned OpenTelemetry collector over OTLP/HTTP protobuf. It is not product
telemetry and does not phone home — disabled until you set your own collector
endpoint, and a local plaintext collector also needs `TRSTCTL_OTLP_INSECURE=true`.

```bash
export TRSTCTL_OTLP_ENABLED=true
export TRSTCTL_OTLP_ENDPOINT=https://otel-collector.example.internal:4318
export TRSTCTL_OTLP_BEARER_TOKEN_FILE=/run/secrets/trstctl-otlp-token
```

The exporter posts spans to `/v1/traces` and audit records to `/v1/logs`, derived
from the endpoint you set. Trace spans include non-secret request attributes such
as `http.route` and `http.status_code`. Audit log records include event metadata
only — `trstctl.audit.type`, `trstctl.audit.id`, `trstctl.audit.sequence`,
`trstctl.audit.schema_version`, `trstctl.tenant.id`, actor subject/roles when
present, and payload byte count — never the event payload itself.

Trace export uses a bounded in-process queue: telemetry drops instead of blocking
credential operations if the collector is slow or down. Audit export runs as a
leader-only background worker carrying the event-stream sequence, so a downstream
SIEM or OpenTelemetry Collector pipeline can dedupe replayed records and alert on
gaps.

### Native Splunk HEC and Microsoft Sentinel audit delivery

OTLP is the metadata-only observability stream. Native audit feeds are the
tenant-governed evidence stream: they deliver the production Splunk HEC or Sentinel
mapping, including each audit record and a final chain trailer, in bounded batches.
Configure them from the Audit console or `PUT /api/v1/audit/feeds/{id}` and inspect
them with `GET /api/v1/audit/feeds` or `trstctl-cli audit feeds list`.

The status response is the durable operator signal. `last_delivered_sequence` is
the highest accepted record, `lag_records` is the exact queued batch size still
owed to the collector, `attempts` and `next_attempt_at` explain retries, and
`last_error_code` plus `collector_request_id` correlate a terminal failure or
vendor receipt. Credentials are represented only by an allowlisted `env:NAME`
reference. Remote response bodies are deliberately not retained because a
collector can echo a credential or customer payload in an error page.

Delivery is outbox-backed and owns the `audit.feed.*` bulkhead family. A transient
failure retries the byte-identical batch and deterministic batch ID. Startup
reconciliation recreates a missing outbox row only after the event history still
matches the recorded range, IDs, seed, and head. A changed range fails closed; it
is never silently replaced by whichever records happen to be current.

## Structured logs

The control plane logs structured JSON (or text — set `TRSTCTL_LOG_FORMAT`) via
`log/slog`. Each request emits one access-log record carrying the `trace_id`
field plus method, normalized route, status, response size, and duration.

Logs contain zero secret material: the access log never records the
`Authorization` header, the request body, or the query string — only the method,
route, and status. This is asserted by a test.

## Dashboards & alerts

Baseline operator assets ship under
[`deploy/observability/`](https://github.com/ctlplne/trstctl/tree/main/deploy/observability):

- **`alerts.yml`** — Prometheus alerting rules for control-plane health, error
  rate/latency (including the per-`PERF-SLO-*` SLO group, which mirrors the
  hot-path table in [performance.md](performance.md)), signer health, and the
  async-spine/fleet metrics in the table below. Every `trstctl_` metric a rule
  references is one the control plane actually emits, checked in both directions
  by test.
- **`dashboard.json`** — a Grafana dashboard: request rate, error ratio, latency
  percentiles, throughput by status code, signer up/restarts, event-log replica
  health, projection/outbox lag, snapshot/CRL/audit freshness/failure panels, and
  fleet-health panels.
- **`prometheus.example.yml`** — a ready-to-use scrape + rules config.

## Ops-critical signal matrix

| Failure mode | Primary metric | Alert |
| --- | --- | --- |
| A committed hot-path p99 SLO is exceeded | `trstctl:slo_p99_latency_seconds` | `TrstctlPerfSLOLatencyPERFSLO###` |
| A committed 0.10% hot-path error budget is burning too fast | `trstctl:slo_error_ratio:5m`, `trstctl:slo_error_ratio:1h` | `TrstctlPerfSLOBurnRatePERFSLO###` |
| Read model is lagging; a poisoned tail also makes `/readyz` fail | `trstctl_projection_lag_events` | `TrstctlProjectionLagHigh` |
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
surface or worker registers its metrics, logs, health/readiness, and tracing
through one shared library — the same registry, middleware, readiness checks,
tracer, and signer-metrics helpers — rather than rolling its own. Background
workers stop cleanly on cancellation, and new `trstctl_` alert metrics are held to
the same reality test, so a dashboard or alert can never reference a metric the
code does not emit.

Two SLOs still deserve tighter direct instrumentation: `PERF-SLO-007`
(`signer.rpc`) and `PERF-SLO-008` (`spine.projection_replay`) use served route
families as their latency/error alert denominator, while direct signer health and
projection backlog are covered by `TrstctlSignerDown`, `TrstctlSignerRestarting`,
and `TrstctlProjectionLagHigh`. Adding first-class signer RPC and projection replay
histograms would make those SLO alerts more exact without weakening AN-4.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `TRSTCTL_LOG_FORMAT` | `json` | `json` or `text`. |

`/metrics` and `/readyz` are always served and unauthenticated; restrict them at
your ingress / network policy if you do not want them publicly reachable.
