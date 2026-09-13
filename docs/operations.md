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

## Notification delivery evidence

Open an alert in **Alerts and delivery** to see which channels accepted it and
which routing policy selected each successful channel. These receipts describe
transport acceptance; they do not prove that a person read the alert.

The dispatcher records each successful channel separately. A failed channel can
retry without sending again to channels whose receipts already exist. The receipt
keeps the policy ID, policy level and a SHA-256 digest of the routing settings used
for that delivery. Later policy changes or deletion do not rewrite that history.
Renewal failures follow the affected identity's route, even when the alert also
carries the certificate from its last completed deployment.

`GET /api/v1/notifications/{id}` includes `deliveries` for the exact tenant,
notification destination, idempotency-key digest and payload digest. A receipt's
`routing_source` distinguishes an explicitly requested policy, an automatically
selected policy, configured defaults, all-channel fallback and a direct channel
test. Historical receipts without that field have unknown routing history; the
console never fills it from today's configuration. Only successful effects have
receipts. Pending or failed delivery still needs investigation. If the detail read
fails, the console labels the displayed snapshot as potentially stale and offers
a retry.

## Investigating a failed renewal attempt

A failed renewal warning records the host job and attempt that failed. Open
**Open exact run and current retry status** to see whether that same run is still
working, recovered, failed, or was cancelled. The historical warning does not
change when a later attempt succeeds.

The link uses `/operations?run=<run-id>` and reads the exact run, including runs
outside the currently loaded history page. For a bound host job, the detail shows
its current status, number of attempts started, and terminal completion time.
An attempt failure can coexist with an ongoing retry; notification delivery
attempts count a different operation.

`GET /api/v1/notifications/{id}` returns `rotation_run_id`, `renewal_job_id`, and
`renewal_attempt` when retained. The server resolves these from the authenticated
job claim and checks the tenant, identity, run key, and predecessor certificate.
`GET /api/v1/lifecycle/rotation-runs/{id}` includes optional `host_job` metadata
for that exact retained child command. Missing historical bindings remain unknown;
the console does not choose the latest run as a substitute. The run detail refreshes
every ten seconds while visible. A failed read displays an error and labels any
previous result as the last successful read, rather than proof of current status.

Alerts opens with the newest 100 notifications. Use **Older alerts** and
**Newer alerts** to page through history, or **Latest alerts** to return to the
current page. Counts and filters describe the displayed page, not the entire
notification history. List readers can request `order=desc`; retain that order
with every cursor. The API default remains `order=asc` for existing clients.
New notifications do not shift an older page's ID cursor.

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

### Datastore backpressure and idempotent retries

The PostgreSQL pool is bounded too. A request that cannot obtain a connection
within the acquire window (10 s by default, `TRSTCTL_POSTGRES_ACQUIRE_TIMEOUT`),
or whose statement is cancelled by the server-side statement deadline, or that
runs into its own request deadline while the datastore is busy, is refused with
**503** and a `Retry-After` header; the problem detail says so ("datastore is
busy ... retry"). It is safe to retry such a request with the **same**
`Idempotency-Key`: the mutation either never claimed the key (the retry executes
it) or completed (the retry replays the recorded response).

Two more answers are part of the idempotency contract under concurrency:

- **409 with `Retry-After`, "still in progress"**: an identical request with the
  same `Idempotency-Key` is executing at that moment (a client retry storm, or
  two replicas). The control plane waits briefly for it; if it has not finished,
  the retry is told to come back. The next retry replays the recorded response.
- **409, "effect is indeterminate"**: the original request's command ran but its
  result could not be recorded (for example the datastore became unavailable
  right after the effect committed). The key is walled rather than re-executed,
  because re-running would duplicate the effect. Inspect the resource, then
  retry with a **new** key if the effect is missing.

### Connection budget

Each replica opens five PostgreSQL pools from the same DSN. The request pool
carries client commands; the four small pools carry work that must keep moving
while the request pool sheds load, and request handlers can never borrow from
them:

| Pool | Default | Setting | Carries |
| --- | --- | --- | --- |
| request | 16 | `TRSTCTL_POSTGRES_MAX_CONNS` / `postgres.max_conns` | client commands and their transactions |
| probe | 2 | `TRSTCTL_POSTGRES_PROBE_CONNS` / `postgres.probe_conns` | the readiness `db` check |
| reserved | 2 | `TRSTCTL_POSTGRES_RESERVED_CONNS` / `postgres.reserved_conns` | the durable projection tail (apply and checkpoint) |
| bookkeeping | 4 | `TRSTCTL_POSTGRES_BOOKKEEPING_CONNS` / `postgres.bookkeeping_conns` | idempotency claim, record and release statements |
| lock | 8 | `TRSTCTL_POSTGRES_LOCK_CONNS` / `postgres.lock_conns` | sessions holding projection, lifecycle issuance/revocation, and host-result advisory locks |

The default budget is **32 connections per replica** (each small pool keeps one
connection warm, so an idle replica holds about five). Size PostgreSQL so that
`max_connections` ≥ replicas × 32 + `superuser_reserved_connections` + every
other client of the database (backup tooling, the doctor, dashboards). Every
pool is opened and pinged at startup: a PostgreSQL that cannot honour the budget
fails the process closed with a message naming the budget and the settings,
instead of starving at runtime. The control plane logs `store: connection
budget` at startup and exports `trstctl_store_pool_connections{pool,state}`
(max, total, acquired, idle) on every `/metrics` scrape.

A tenant burst that holds every request-pool connection is shed with 503s as
above, but it cannot make `/readyz` time out (probe pool), starve the tail into
"projection tail worker stopped; retrying" (reserved pool), leave a completed
command's result unrecorded and wall its key as "indeterminate" (bookkeeping
pool), or convoy commands behind the projection lock in acquire-window steps
(lock pool).

### Readiness under load

The `db` check pings the probe pool and fails readiness when PostgreSQL is
unreachable. The datastore-reading checks (`nats` samples, `projection`,
`secret_sync_recovery_authority`, `application_secret_reconciliation`) read
through the request pool under a one-second budget. When one of them is shed by
load (the store's busy signal, or the budget runs out) `/readyz` still answers
**200** so the replica stays in rotation, but the check reads `degraded: …`,
the body carries a `degraded` list naming the checks, and
`trstctl_readiness_probe_shed{check}` is 1 for as long as it lasts. Shedding
that outlasts the **two-minute grace window** fails the check: a datastore that
has been too slow for that long is a stall, not a burst. A check that fails for
a real reason (a stalled projection, a missing recovery authority) fails
readiness immediately, as before.

One more retryable answer: **503 with `Retry-After`, "rolled back because of a
concurrent transaction"** (extensions `retryable: true` and `sqlstate` 40001 or
40P01). PostgreSQL detected a serialization failure or a deadlock (for example
the request's inline projection racing the durable tail on the same rows) and
rolled the current transaction back. The idempotency claim is released, so the
same request retries as-is; commands that span several transactions recover
their own committed steps through their durable fences and receipts, so the
retry never duplicates them. Anything that still answers **500** is logged by
the control plane (`api: internal error answered as 500`) with the response's
`traceparent`, the error's type chain, the SQLSTATE and constraint when it is a
PostgreSQL error, and a message with every quoted literal masked; row values
never reach the log.

Approval decisions (`/api/v1/approval-requests/{id}/approvals` and
`/denials`, `/api/v1/identities/{id}/approvals`) run on this claim path too:
identical in-flight decisions execute once and replay; a retry that arrives
after the idempotency retention window re-executes the decision and finds it
already recorded for that approver, so the answer is the recorded decision and
never a second one.

Every mutation claims its `Idempotency-Key` in a short transaction, runs the
command with **no pooled connection held**, and records the result in a second
short transaction (the same discipline the outbox uses for external calls), so
parallel writes never deadlock on the pool waiting for each other. A claim
abandoned by a crashed process is taken over after ten minutes.

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
