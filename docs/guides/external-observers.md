# External observers: reporting what an endpoint serves

An external observer is a monitor outside trstctl — probectl, a synthetic
checker, a load balancer's health probe — that looks at endpoints from where
clients stand. trstctl takes its reports as evidence independent of its own
agents, matches each one to the certificate the endpoint should serve, and tells
the observer when that certificate changes. This page is the contract for an
observer's side.

## Register the observer

An operator registers each observer once (`notifications:write`):

```json
POST /api/v1/observers
Idempotency-Key: register-probectl

{
  "name": "probectl-eu",
  "events_url": "https://probectl.example.com/trstctl/events",
  "credential_ref": "secret://observers/probectl-eu/hmac",
  "enabled": true
}
```

`events_url` must be `https` with no credentials in it; leave it out to report
without receiving events. `credential_ref` names a tenant secret
(`POST /api/v1/secrets/store`) whose value signs every event; leave it out to
receive unsigned events. `PUT /api/v1/observers/{id}` replaces the configuration
and `GET /api/v1/observers` lists it. CLI: `trstctl observers register|update|list`.

## Report an observation

The observer reports with an API token scoped to `discovery:write`, the same
scope an agent's inventory reports use:

```json
POST /api/v1/observations
Idempotency-Key: probectl-eu/2026-10-26T12:00:00Z/checkout.example.com:443

{
  "observer_id": "<observer id>",
  "endpoint": "checkout.example.com:443",
  "vantage": "eu-west-1 synthetic",
  "observed_at": "2026-10-26T12:00:00Z",
  "reachable": true,
  "health": "healthy",
  "served_fingerprint": "<lowercase hex SHA-256 of the served leaf's DER>",
  "chain_fingerprints": ["<intermediate>", "<root>"],
  "detail": "TLS 1.3, 41 ms"
}
```

- `endpoint` is `host:port` as the observer dialed it. trstctl compares it with the
  addresses its own endpoint verification checks, so use the same name clients use.
- `health` is `healthy`, `degraded`, `unhealthy` or `unknown`.
- An unreachable endpoint (`"reachable": false`) served nothing: leave
  `served_fingerprint` empty.
- The `Idempotency-Key` makes a retried report converge on the same observation;
  use one key per observation.

The response is the recorded observation with trstctl's `verdict`:

| Verdict | Meaning |
| --- | --- |
| `match` | The endpoint served the certificate trstctl deployed there. |
| `mismatch` | It served a different certificate. trstctl raises an `external-observation-mismatch` finding. |
| `unreachable` | The observer could not reach it. |
| `unexpected` | Nothing trstctl verifies names this endpoint, so there was nothing to compare with. |

An `unhealthy` or unreachable endpoint within seven days after the renewal that
produced the certificate it should serve raises an
`endpoint-unhealthy-after-rotation` finding. Both findings land in the Findings
queue under the source `external-observer:<name>`.

A matching observation becomes independent evidence on the certificate's
assurance record (`GET /api/v1/certificates/{id}/assurance-record`), listed apart
from trstctl's own agents' verification. `GET /api/v1/observations` lists
observations by `observer_id`, `endpoint` or `fingerprint`.

## Receive rotation and rollback events

When a renewal completes or a connector rollback restores a certificate, trstctl
queues one event per enabled observer with an `events_url`, in the same
transaction that records the renewal or rollback, and posts it:

```http
POST <events_url>
Content-Type: application/json
X-Trstctl-Signature: sha256=<hex HMAC-SHA256 of the body, keyed by the credential>

{
  "id": "rotation:<run id>",
  "type": "rotation.completed",
  "tenant_id": "<tenant>",
  "occurred_at": "2026-10-26T12:00:00Z",
  "identity_id": "<lifecycle identity>",
  "previous_fingerprint": "<what the endpoints served before>",
  "current_fingerprint": "<what they should serve now>",
  "endpoints": ["checkout.example.com:443"],
  "targets": ["checkout-edge"],
  "rotation_run_id": "<run id>"
}
```

A rollback is `"type": "rollback.completed"` with `rollback_receipt_id`.
`endpoints` are the addresses trstctl verifies for either certificate; `targets`
are the connector targets that delivered them.

- Verify the signature over the exact body bytes before acting on an event.
- Delivery is at least once: drop an event whose `id` you have seen.
- Answer `2xx` to accept. A `4xx` other than 408 or 429 refuses it for good;
  anything else is retried with backoff.
- A useful observer re-probes `endpoints` for `current_fingerprint` and reports
  what it sees, which closes the loop: the observation lands on the renewed
  certificate's assurance record.
