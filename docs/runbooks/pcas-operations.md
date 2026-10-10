# PCAS Operations Runbook

Proof-Carrying Algorithm Succession (PCAS) lets an identity move from one
algorithm epoch to the next without asking relying parties to guess which key is
current. The control plane records a tenant-scoped request, the outbox drains it,
and the isolated signer mints or zeroizes key material. Private keys stay in the
signer process.

## First use: register, verify, then succeed an identity

Use a tenant principal with `keys:write` to register the immutable starting
anchor. The control plane queues the operation; the isolated signer creates the
tenant trust root and identity key. Registration is complete only after the
request status says `delivered` and the chain endpoint returns `genesis` and
`trust_root_public_der`. A `certs:read` principal can read status and chain;
`certs:write` is needed to request a succession.

```bash
cat > /secure/operator-genesis.json <<'JSON'
{"identity_id":"spiffe://example.test/workload/api","algorithm":"ECDSA-P256","deployment_scope":"spiffe://example.test"}
JSON
trstctl pcas genesis register -f /secure/operator-genesis.json
trstctl pcas requests status REQUEST_ID
trstctl pcas chain get --identity_id spiffe://example.test/workload/api
```

Save the returned trust-root public key fingerprint in an independently
controlled trust store before distributing the chain. A fresh client must not
silently trust a root supplied in the same response it verifies. Confirm the
registered tenant, identity, scope, algorithm and epoch zero, then verify the
root signature on genesis. The Posture console shows the root fingerprint and
chain count for this review. Keep the output as public evidence; it contains no
private key.

After genesis is delivered, submit a different target algorithm and poll its
request. The successor record is returned in `records` as base64 JSON bytes;
verify both signatures, epoch continuity, policy and scope against the pinned
root before changing a relying party. The chain API does not deploy a new
credential or make a relying party adopt it.

```bash
cat > /secure/operator-succession.json <<'JSON'
{"identity_id":"spiffe://example.test/workload/api","credential_type":"workload-svid","target_algorithm":"ECDSA-P384","policy_ref":"policy:operator","deployment_scope":"spiffe://example.test"}
JSON
trstctl pcas succession request -f /secure/operator-succession.json
trstctl pcas requests status REQUEST_ID
trstctl pcas chain get --identity_id spiffe://example.test/workload/api
```

Use distinct idempotency keys for distinct POST operations. A request for an
unregistered identity returns 409 with the registration path; it never creates
an unanchored chain. Do not register the same identity under a different scope
or algorithm to recover an error: the anchor is immutable. A previously used
unscoped signer handle requires an explicit custody migration, as described in
[PCAS key custody](../pcas-key-custody.md).

## Health Signals

Scrape `/metrics` on the control plane. PCAS feature work is exposed through the
shared feature metrics:

- `trstctl_feature_operations_total{feature="pcas_succession",action="mint",outcome="success"}`
- `trstctl_feature_operations_total{feature="pcas_succession",action="genesis",outcome="success"}`
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

## Integration checks

PCAS ships in the core. Run its conformance suite locally:

```bash
bash scripts/pcas_no_skip_gate.sh
go test ./internal/succession/conformance -count=1 -timeout=10m
```

The suite includes the real embedded PostgreSQL, NATS/JetStream, cross-process
signer, and WASM verifier checks. It also exercises a multi-tenant burst, durable
outbox draining, metrics, and duplicate delivery without a second mint. The
no-skip check rejects tests that silently bypass missing infrastructure. Missing
prerequisites must be resolved before treating the run as passed.

For a focused operations investigation:

```bash
go test ./internal/succession/conformance -run TestINT21_PCASOpsSLOBackpressureAndCrash -count=1 -timeout=10m
```

The shared `make test` and `make editions-gate` checks cover the core package and
edition boundary; there is no separate proprietary PCAS release target.

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
