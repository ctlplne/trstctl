# Run trstctl in production

## Goal

When you finish this journey you will have trstctl running the way it is meant to run
for real: encrypted transport with your own certificate, health and metrics endpoints
wired to your monitoring, a tested backup-and-restore drill, a passive-region
federation drill, and the tamper-evident audit log producing signed evidence for compliance. It is for the operator taking
trstctl past evaluation into a deployment people depend on. In plain terms: you turn
off the eval shortcuts, point your dashboards at the right endpoints, prove you can
recover from a datastore loss, and confirm you can hand an auditor a verifiable record.

## Before you start

- A working control plane and an API token, set up in
  [Getting started](../getting-started.md).
- External PostgreSQL and NATS (the bundled eval datastores are not for production).
  The serving and resilience behavior is described in [Operations & resilience](../operations.md).
- The properties of how trstctl runs — transport, multi-tenancy, the API surface —
  are in [Platform & API](../features/platform-and-api.md), and the governance and
  audit model in [Policy & governance](../features/policy-and-governance.md).
- If the production environment is disconnected, read
  [Air-gapped install](../airgap.md) first. It adds the no-phone-home egress guard
  and the strict Helm egress overlay to the same production posture below.

## Steps

1. **Serve over your own certificate, not the self-signed eval one.** TLS is on out
   of the box, but for production point it at a real certificate:

   ```yaml
   server:
     tls:
       mode: file
   ```

   ```sh
   export TRSTCTL_SERVER_TLS_CERT_FILE=/etc/trstctl/tls.crt
   export TRSTCTL_SERVER_TLS_KEY_FILE=/etc/trstctl/tls.key
   ```

   You should see the control plane serve over your certificate. The transport and
   isolation properties are covered in
   [Platform & API](../features/platform-and-api.md).

2. **Confirm readiness against the real dependencies.** `/readyz` probes PostgreSQL,
   NATS, and the signer, so make it your readiness probe:

   ```sh
   curl -fksS https://localhost:8443/readyz   # {"status":"ok","checks":{"db":"ok","nats":"ok","signer":"ok"}}
   ```

   You should get `{"status":"ok",...}` with each dependency `ok`. If one drops,
   readiness flips to `503` while `/healthz` (liveness) stays green.

3. **Scrape metrics and wire the alerts.** The control plane emits Prometheus metrics
   at `/metrics`, served outside the API load-shedding lane so they keep answering
   under load:

   ```sh
   curl -fksS https://localhost:8443/metrics   # # TYPE trstctl_http_requests_total counter ...
   ```

   You should see series such as `trstctl_http_requests_total` and `trstctl_signer_up`.
   A rising `503` rate points at a saturated subsystem and a rising `429` rate at a
   tenant over budget. The full metric and alert set is in
   [Observability & risk](../features/observability-and-risk.md).

4. **Run a backup, then prove you can restore it.** Take a full DR artifact and
   rehearse recovery into a fresh, empty datastore — recovery is not real until it is
   drilled:

   ```sh
   TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE=/secure/trstctl-full-backup.key \
     trstctl --full-backup-dir=/backups/trstctl-$(date +%F)
   ```

   You should see a confirmation that the full backup was written with its artifacts.
   The complete backup set, restore procedure, and the DR scenarios are in the
   [disaster-recovery runbook](../disaster-recovery.md).

5. **Query the tamper-evident audit log and export evidence.** Every change is
   recorded as an immutable event, and the audit log is a hash-chained view of that
   history. Pull events, download a signed bundle, and produce a framework pack:

   ```sh
   trstctl-cli audit events --type policy.decision --since 2026-01-01T00:00:00Z --limit 100
   trstctl-cli audit export --since 2026-01-01T00:00:00Z --until 2026-06-01T00:00:00Z
   trstctl-cli compliance evidence-pack soc2
   ```

   You should get back the matching events, a signed evidence bundle, and a signed
   SOC 2 evidence pack with CBOM/FIPS posture an auditor can verify offline. The
   compliance-reporting and audit model is in
   [Policy & governance](../features/policy-and-governance.md).

6. **Tune backpressure for your traffic.** Per-tenant rate limiting sheds a noisy
   tenant before it can starve the rest. Set the budget for your load:

   ```sh
   export TRSTCTL_RATE_LIMIT_REQUESTS=600
   export TRSTCTL_RATE_LIMIT_WINDOW=1m
   ```

   You should see over-budget callers get `429` with a `Retry-After` header instead of
   degrading the whole control plane. The bulkheads, rate limiter, and graceful drain
   are described in [Operations & resilience](../operations.md).

7. **Rehearse passive-region federation and failover.** On the passive cluster, point
   federation at the primary cluster's external NATS endpoint and set the RPO/RTO you
   will use in the runbook:

   ```sh
   export TRSTCTL_FEDERATION_ENABLED=true
   export TRSTCTL_FEDERATION_CLUSTER_ID=us-west-passive
   export TRSTCTL_FEDERATION_REGION=us-west-2
   export TRSTCTL_FEDERATION_PEER_ID=us-east-primary
   export TRSTCTL_FEDERATION_PEER_REGION=us-east-1
   export TRSTCTL_FEDERATION_PEER_NATS_URL=nats://nats.us-east.example:4222
   export TRSTCTL_FEDERATION_INTERVAL=1s
   export TRSTCTL_FEDERATION_RPO=5s
   export TRSTCTL_FEDERATION_RTO=30s
   ```

   Create or update a trust issuer in the primary region, then wait for the passive
   region's `trstctl_projection_lag_events` metric to return to zero and confirm the
   issuer is readable there. During a drill, stop primary writes, confirm the passive
   peer cursor is caught up within the RPO target, move ingress or client endpoints to
   the passive region, and complete a read smoke test inside the RTO target. Keep one
   writable region for a tenant at a time; federation is event-log import plus local
   projection, not a two-writer conflict resolver.

8. **For disconnected environments, verify no public egress.** Enable air-gap mode
   and use the Helm overlay:

   ```sh
   export TRSTCTL_AIRGAP_ENABLED=true
   export TRSTCTL_AIRGAP_ALLOW_PRIVATE=true
   ```

   Then issue a test certificate and create/rotate a native secret while your
   network monitor watches for outbound public traffic. The detailed offline bundle,
   Helm values, and verification flow are in
   [Air-gapped install](../airgap.md).

## Where next

- [Respond to a key or certificate compromise](respond-to-compromise.md)
- [Build on the API, CLI, and SDKs](build-on-the-api.md)

**Journey:** J10
**Steps through:** F15, F62, F52, F9, F19, F41
