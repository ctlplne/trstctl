# Operations & resilience

The serving control plane is built so one overloaded or failing part cannot take
down the rest (AN-7). This page covers the resilience controls in the live path:
bulkheads, the per-tenant rate limiter, graceful drain, and the fail-closed signer
timeout.

## Bulkheads (isolation + backpressure)

Each subsystem runs on its own **bounded worker pool with a bounded queue**: the
API, the projection workers, the outbox dispatcher, and the signing path. When a
pool is saturated it **rejects fast** rather than blocking — an API flood returns
**503** with a `Retry-After` header instead of consuming capacity another
subsystem needs.

Because the pools are isolated, a saturated API **cannot starve** the things you
rely on to observe and recover: `/healthz`, `/readyz`, and `/metrics` are served
**outside** the API bulkhead and keep answering even while the API sheds load. The
continuous outbox dispatcher runs on its own pool, so a backlog of external calls
applies backpressure to itself (it sheds a sweep rather than piling up) without
touching API capacity.

The pool sizes ship with conservative defaults and are tuned per deployment.

## Rate limiting (per tenant, PostgreSQL-backed)

A **per-tenant token bucket**, persisted in PostgreSQL (no Redis — the limit holds
across every replica), sheds load on the guarded routes: each tenant may make
`requests` calls per `window`, admitting a burst of `requests` and refilling
steadily. Over-budget requests get **429 Too Many Requests** with a `Retry-After`
header. The check runs **after** authentication and authorization, so one noisy
tenant cannot exhaust the control plane while others are unaffected (AN-1).

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_RATE_LIMIT_ENABLED` | `true` | Turn per-tenant rate limiting on/off. |
| `TRSTCTL_RATE_LIMIT_REQUESTS` | `600` | Burst/budget per window, per tenant. |
| `TRSTCTL_RATE_LIMIT_WINDOW` | `1m` | The refill window (Go duration). |

## Graceful drain on shutdown

On `SIGTERM` the control plane drains **without losing in-flight work**: it stops
accepting new connections, stops the outbox dispatcher, drains the per-subsystem
worker pools (finishing queued and running tasks), runs a final outbox sweep so no
enqueued external effect is lost (AN-6), then closes the event log and datastore
in order.

## Fail-closed signing

Issuance is bounded by a per-operation timeout. If the out-of-process signer
(AN-4) is **slow, unreachable, or stopped**, `IssueLeaf` **fails closed** — it
returns an error within the timeout and **never** falls back to an in-process
signature. This is exercised by fault injection (a deliberately slow signer) in
the test suite.

## What an operator should watch

Pair this with [Observability](observability.md): the `trstctl_http_requests_total`
counter shows 429/503 shedding as it happens, and the alert rules fire on
sustained error rate or latency. A rising 503 rate points at a saturated
subsystem; a rising 429 rate points at a tenant over budget.
