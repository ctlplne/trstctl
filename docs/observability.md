# Observability

trustctl's serving control plane is instrumented so an operator can answer "is it
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

```bash
curl -fksS https://localhost:8443/readyz   # {"status":"ok","checks":{"db":"ok","nats":"ok","signer":"ok"}}
curl -fksS https://localhost:8443/metrics  # # TYPE trustctl_http_requests_total counter ...
```

## Metrics

The control plane emits, at minimum:

- **`trustctl_http_requests_total{method,route,code}`** — a counter of HTTP
  requests by method, normalized route, and status code.
- **`trustctl_http_request_duration_seconds{method,route}`** — a latency histogram
  (with `_bucket`, `_sum`, `_count`).
- **`trustctl_signer_up`** — `1` when the out-of-process signer is healthy, else `0`.
- **`trustctl_signer_restarts_total`** — cumulative relaunches of the signer child
  by the supervisor.

The signer is a separate, HTTP-less process (AN-4), so it cannot expose its own
`/metrics`; the control plane samples its health and restart count on a fixed
cadence and publishes them on the same registry as everything else. The sampler is
a background worker that stops cleanly on shutdown.

Routes are **normalized** — opaque path segments (UUIDs, long hex ids, numeric
ids) are collapsed to `:id` — so per-id paths do not explode label cardinality and
no identifier leaks into a label.

Scrape it with the example config in
[`deploy/observability/prometheus.example.yml`](https://github.com/imfeelingtheagi/trustctl/blob/main/deploy/observability/prometheus.example.yml).

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

The control plane logs in **structured JSON** (or text — set `TRUSTCTL_LOG_FORMAT`)
via `log/slog`, wired into the serving path. Each request emits one access-log
record carrying the **`trace_id`** correlation field plus the method, normalized
route, status, response size, and duration.

Logs contain **zero secret material** (AN-8): the access log never records the
`Authorization` header, the request body, or the query string — only the method,
the normalized route, and the status. This is asserted by a test.

## Dashboards & alerts

Baseline operator assets ship under
[`deploy/observability/`](https://github.com/imfeelingtheagi/trustctl/tree/main/deploy/observability):

- **`alerts.yml`** — Prometheus alerting rules: control plane down, 5xx error rate
  above 5%, p99 latency above 1s, **signer down**, and **signer restarting
  repeatedly**. Every metric the rules reference is one the control plane actually
  emits (asserted by a test, so a rule can't reference a metric that does not exist).
- **`dashboard.json`** — a Grafana dashboard: request rate, error ratio, latency
  percentiles, throughput by status code, and **signer up / restarts**.
- **`prometheus.example.yml`** — a ready-to-use scrape + rules config.

## Plugging a new component in

Observability is a default of the codebase, not a per-sprint afterthought: a new
serving surface or background worker registers its metrics, structured logs,
health/readiness, and tracing through the shared `internal/observ` library (the
same `Registry`, `Middleware`, `Readiness`, `Tracer`, and the `SignerMetrics`-style
helpers) rather than rolling its own. Background workers take a context and stop on
cancellation so shutdown stays graceful. New `trustctl_` alert metrics are held to
the same reality test, so a dashboard or alert can never reference a metric the code
does not emit.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRUSTCTL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `TRUSTCTL_LOG_FORMAT` | `json` | `json` or `text`. |

`/metrics` and `/readyz` are always served and unauthenticated; restrict them at
your ingress / network policy if you do not want them publicly reachable.
