# PCAS Operations Runbook

Proof-Carrying Algorithm Succession (PCAS) lets an identity move from one
algorithm epoch to the next without asking relying parties to guess which key is
current. The control plane records a tenant-scoped request, the outbox drains it,
and the isolated signer mints or zeroizes key material. Private keys stay in the
signer process.

## Health Signals

Scrape `/metrics` on the control plane. PCAS feature work is exposed through the
shared feature metrics:

- `trstctl_feature_operations_total{feature="pcas_succession",action="mint",outcome="success"}`
- `trstctl_feature_operations_total{feature="pcas_kem",action="rewrap",outcome="success"}`
- `trstctl_feature_operations_total{feature="pcas_retirement",action="worker",outcome="success"}`
- `trstctl_feature_operations_total{feature="pcas_checkpoint",action="worker",outcome="success"}`
- `trstctl_feature_operations_total{feature="pcas_monitor",action="worker",outcome="success"}`
- `trstctl_feature_operation_duration_seconds_count{feature="pcas_succession",action="mint"}`

The labels are fixed strings. They never include tenant IDs, identities, serials,
handles, ciphertexts, shared secrets, or other secret material.

Also watch:

- `trstctl_signer_up`: must be `1` on a healthy node.
- `trstctl_signer_restarts_total`: should not grow during normal operation.
- Outbox lag and timeout metrics for `pcas.*` destinations.
- Bulkhead metrics for queue depth and rejection spikes.

## SLO

The per-PR release gate is intentionally small and deterministic:

```bash
make pcas-release-gate
```

That target proves:

- every delivered PCAS mechanism has a non-test production caller;
- gate tests do not call `t.Skip`;
- the INT-20 full-stack e2e runs over real embedded PostgreSQL, embedded
  NATS/JetStream, a cross-process signer, and WASM verifier parity;
- the INT-21 ops test handles a small multi-tenant burst, drains durable outbox
  work, emits PCAS feature metrics, and proves duplicate redelivery does not
  double-mint.

For local investigation, run only the ops gate:

```bash
go test ./internal/succession/conformance -run TestINT21_PCASOpsSLOBackpressureAndCrash -count=1 -timeout=10m
```

## Backpressure Model

PCAS mutations use the normal API path, so the global API rate limiter applies
before a request is accepted. Accepted asynchronous work is durable outbox work:
one row per tenant-scoped external effect. Delivery is retried by the outbox
worker with leases, retry backoff, and destination/tenant fairness.

Operationally:

1. If the API rate limit trips, the request is rejected before it can create more
   work.
2. If an outbox destination is slow, other tenants and destinations can still be
   claimed by workers.
3. If a PCAS worker crashes after minting but before publish, the idempotency key
   makes redelivery return the original result instead of minting again.

## Common Checks

Check a succession chain:

```bash
curl -fsS "$TRSTCTL_URL/api/v1/pcas/chain?identity_id=$IDENTITY_ID"
```

Check a KEM re-wrap:

```bash
curl -fsS "$TRSTCTL_URL/api/v1/pcas/rewrap?identity_id=$IDENTITY_ID&predecessor_epoch=$EPOCH"
```

Check retirement:

```bash
curl -fsS "$TRSTCTL_URL/api/v1/pcas/retirement?identity_id=$IDENTITY_ID&predecessor_epoch=$EPOCH"
```

Check posture:

```bash
curl -fsS "$TRSTCTL_URL/api/v1/pcas/posture?identity_id=$IDENTITY_ID"
```

## Crash Recovery

After a control-plane or signer restart:

1. Confirm `trstctl_signer_up` returns to `1`.
2. Confirm PCAS outbox rows continue to drain.
3. Re-fetch the chain for the affected identity.
4. Verify there is exactly one record for the requested successor epoch.
5. Check the feature metric outcome labels for `outcome="error"` growth.

The signer floor is monotonic and durable. A restarted signer must refuse a stale
asserted predecessor epoch; that is the key property that prevents floor
regression and double minting.

## Escalation

Escalate immediately if:

- `pcas_succession/mint` errors grow while `trstctl_signer_up` is `1`;
- retirement worker errors persist after re-wrap completion;
- two different records appear for the same tenant, identity, and epoch;
- KEM re-wrap stays incomplete while its outbox rows are delivered;
- `pcas_monitor/misissuance` records a finding.

Do not manually delete PCAS rows. The event log, outbox, and RLS tables are the
evidence trail. If repair is needed, use a new idempotent operation that records
what was changed.
