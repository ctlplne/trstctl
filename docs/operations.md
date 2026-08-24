# Operations & resilience

This page is for the operator responsible for keeping a running trstctl deployment
available. It explains the controls, signals, and recovery behavior for overload,
slow external systems, shutdown, and signer failure. Before changing production,
have a verified backup, alert access, the current configuration, and a tested
rollback path. Start diagnostics in **Trust Operations**, then use `/healthz`,
`/readyz`, and `/metrics` to separate service health from tenant work.

The serving control plane is built so one overloaded or failing part cannot take
down the rest: each subsystem runs in its own bounded lane and rejects fast when
full. This page covers the resilience controls in the live path: bulkheads, the
per-tenant rate limiter, graceful drain, and the fail-closed signer timeout.

## Bulkheads (isolation + backpressure)

Each subsystem runs on its own **bounded worker pool with a bounded queue**: the
API, projection workers, outbox dispatcher, signing path, heavy query path, policy
engine, served issuance protocols, and the agent steady-state gRPC channel. When a
pool is saturated it **rejects fast** rather than blocking — an API flood returns
**503** with a `Retry-After` header, and an agent heartbeat/renewal flood returns
gRPC `ResourceExhausted` with retry guidance, instead of consuming capacity another
subsystem needs.

Because the pools are isolated, a saturated API **cannot starve** the things you
rely on to observe and recover: `/healthz`, `/readyz`, and `/metrics` are served
**outside** the API bulkhead and keep answering even while the API sheds load. The
continuous outbox dispatcher runs on its own pool, so a backlog of external calls
applies backpressure to itself (it sheds a sweep rather than piling up) without
touching API capacity. The agent pool similarly isolates reconnect storms and
certificate-renewal waves from the API/protocol/outbox pools, and the agent gRPC
listener also caps streams per connection.

The pool sizes ship with conservative defaults and are tuned per deployment.

## Outbox delivery fairness

The outbox worker does not keep a PostgreSQL transaction open while it calls an
external CA, connector, webhook, or notification target. It first **leases** one
due row in a short transaction (`processing`, `worker_id`, `lease_until`), commits,
does the external call, then records success or retry state in a second short
transaction. If a worker dies after claiming a row, the lease expires and another
worker returns the row to pending.

Dispatch is also fair by tenant and destination. Each sweep rotates across tenants
and destinations, with explicit in-flight caps per tenant and per destination, so
one down connector or one noisy tenant cannot occupy every outbox worker while
unrelated tenants wait behind it.

Each delivery also has a per-message deadline. If a connector, plugin, webhook, or
notification target does not return before that deadline, the row is marked
pending again through the normal retry/backoff path, and the served binary increments
`trstctl_outbox_delivery_timeouts_total{tenant_id,destination}`. That counter is the
operator's direct signal that one destination is timing out without starving the
rest of the outbox.

## Rate limiting (per tenant, PostgreSQL-backed)

A **per-tenant token bucket**, persisted in PostgreSQL (no Redis — the limit holds
across every replica), sheds load on the guarded routes: each tenant may make
`requests` calls per `window`, admitting a burst of `requests` and refilling
steadily. Over-budget requests get **429 Too Many Requests** with a `Retry-After`
header. The check runs **after** authentication and authorization, so one noisy
tenant cannot exhaust the control plane while others are unaffected.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_RATE_LIMIT_ENABLED` | `true` | Turn per-tenant rate limiting on/off. |
| `TRSTCTL_RATE_LIMIT_REQUESTS` | `600` | Burst/budget per window, per tenant. |
| `TRSTCTL_RATE_LIMIT_WINDOW` | `1m` | The refill window (Go duration). |

## Graceful drain on shutdown

On `SIGTERM` the control plane drains **without losing in-flight work**: it stops
accepting new connections, stops the outbox dispatcher, drains the per-subsystem
worker pools (finishing queued and running tasks), runs a final outbox sweep so no
enqueued external effect is lost (the journaled outbox guarantees at-least-once
delivery), then closes the event log and datastore in order.

## Fail-closed signing

Issuance is bounded by a per-operation timeout. If the out-of-process signer
is **slow, unreachable, or stopped**, `IssueLeaf` **fails closed** — it
returns an error within the timeout and **never** falls back to an in-process
signature. This is exercised by fault injection (a deliberately slow signer) in
the test suite.

## What an operator should watch

Pair this with [Observability](observability.md): the `trstctl_http_requests_total`
counter shows 429/503 shedding as it happens, and the alert rules fire on
sustained error rate or latency. A rising 503 rate points at a saturated
subsystem; a rising 429 rate points at a tenant over budget. A rising
`trstctl_outbox_delivery_timeouts_total` series points at a slow destination and
includes the affected tenant and destination labels.

For metadata-only SIEM pipelines, enable OTLP export to your OpenTelemetry
Collector. Served HTTP spans arrive as OTLP traces, and event-sourced audit records
arrive as OTLP logs with `trstctl.audit.sequence` and `trstctl.tenant.id`
attributes. Use the sequence attribute to dedupe restarted streams and alert on
gaps.

For native evidence delivery, configure a Splunk HEC or Microsoft Sentinel feed
and watch `GET /api/v1/audit/feeds`. A non-zero `lag_records` means one exact batch
is still owed; `retrying` is recoverable and carries `next_attempt_at`; `failed` is
terminal and keeps its safe error code and collector request ID. Re-saving a
corrected configuration emits a new immutable configuration version. Never repair
the cursor, outbox row, or feed projection with SQL: startup reconciliation checks
the queued event against the retained audit range and either recreates the exact
intent or fails closed.
