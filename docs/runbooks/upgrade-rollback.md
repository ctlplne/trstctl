# Runbook: chart upgrade and rollback

This runbook upgrades the Helm chart and rolls it back when readiness, signer
health, agent heartbeat, or inventory checks fail. It covers the control-plane
chart in `deploy/helm/trstctl` and the fleet surfaces that chart exposes.

## Prerequisites

- Save the current release revision: `helm history trstctl -n trstctl`.
- Export the current values:

```sh
helm get values trstctl -n trstctl -o yaml > trstctl-values.before.yaml
```

- Confirm `/readyz` is `200`.
- Confirm `trstctl_signer_up == 1`.
- Set `TRSTCTL_CA_FILE` to the trusted public CA bundle for the control-plane
  certificate; never disable TLS verification to get through an outage.
- Record `trstctl-cli agents list` and inventory counts before the upgrade.
- Run `trstctl --check-config` in the candidate environment and confirm the
  `agent_channel.*` lines match the planned fleet topology.

## Idempotency keys across this upgrade

An idempotency key is a retry label. It tells trstctl that two copies of the
same command must produce one effect. The upgraded API also binds that label to
the authenticated caller, method, path, canonical query, and request-body
digest. This prevents a changed command from silently receiving an earlier
command's cached response.

Bodyless, queryless commands keep their previous binding and replay normally.
An older successful mutation that had a body or query cannot be proved to match
after the upgrade because the older row did not record those input digests. Its
first retry therefore fails closed with `409 Conflict` and this detail:

```text
Idempotency-Key was already used for a different authenticated request
```

When this happens, confirm the intended effect in trstctl, then submit the
intended command once with a new unique idempotency key. Do not delete or edit
the old idempotency row: it is the durable proof that the earlier command ran.
Record the old and new key references in the change ticket. Never place the
request body or a credential value in either key.

## Agent registration binding across this upgrade

Agent certificates now identify the tenant's registration as well as its UUID.
Deleting a tenant and registering the same UUID must not give an old agent access
to the replacement tenant. The CA stamps the retained registration identifier;
authenticated agent operations and both renewal paths verify it.

Certificates issued before this binding was introduced require authorized
re-enrollment. A missing, duplicate or different binding is refused even when the
certificate is otherwise trusted and unexpired. Renewal cannot upgrade that old
identity: the operator must authorize a new bootstrap token for the intended
current tenant. The error includes `enroll again` guidance. Plan this interruption
before upgrading a fleet; existing cached credentials do not migrate automatically.

For each affected agent:

1. Stop that agent's service and retain its exact old certificate/key paths in
   protected storage for investigation. Do not copy private keys into a ticket.
2. Using the intended tenant's authenticated CLI context, run
   `trstctl-cli agents enroll-token` with the intended `allowed_identity` and
   role grants, as in the [fleet rollout runbook](fleet-rollout.md). Store each
   single-use token in a separate owner-readable file with mode `0600`.
3. Keep the agent's verified server address, name, CA bundle and execution
   settings. Supply `--bootstrap-token-file` and new, unused `--key` and `--cert`
   paths in a protected directory. Both paths must be unused: an existing cached
   identity takes precedence over a fresh bootstrap token. Update the service
   configuration to keep these new paths across restarts.
4. Start the agent and verify a successful heartbeat, expected inventory and job
   eligibility. Verify renewal and reconnection with the successor certificate.
   Preserve failed results; token creation or a TLS handshake alone is insufficient.

Do not disable tenant checks or edit the certificate SANs to recover service.
An ordinary restart or read-model rebuild retaining the same registration event
does not authorize a new tenant generation. Missing registration history requires
source recovery before enrollment can proceed.

## Commands: preflight

Render the chart with the exact values file and inspect the agent channel and
isolated-signer surfaces:

```sh
helm template trstctl deploy/helm/trstctl \
  --namespace trstctl \
  -f trstctl-values.before.yaml > rendered.before.yaml

grep -n 'agent-grpc\|TRSTCTL_AGENT_CHANNEL\|trstctl-signer' rendered.before.yaml
```

If the upgrade changes signer mode, verify the signer key store, KEK, signer auth
Secret, and mTLS Secret are present before applying. The signer must keep the same
key material unless a key ceremony explicitly says otherwise.

## Commands: upgrade

```sh
helm upgrade trstctl deploy/helm/trstctl \
  --namespace trstctl \
  -f trstctl-values.before.yaml \
  --wait --timeout=10m

kubectl -n trstctl rollout status deployment/trstctl --timeout=10m
kubectl -n trstctl rollout status daemonset/trstctl-agent --timeout=10m
```

If isolated signer mode is enabled:

```sh
kubectl -n trstctl rollout status deployment/trstctl-signer --timeout=10m
```

## Expected metrics and logs

- `/readyz` returns `200` after each Deployment becomes Ready.
- `trstctl_signer_up` stays `1`, or returns to `1` before the control plane is
  marked ready.
- `sum(increase(trstctl_agent_enrollments_total{result="failed"}[15m]))` stays
  `0`; an upgrade should not break fresh agent bootstrap.
- `sum(increase(trstctl_agent_heartbeats_total{result="failed"}[10m])) /
  clamp_min(sum(increase(trstctl_agent_heartbeats_total[10m])), 1)` stays at or
  below `0.02`.
- `trstctl_agents_stale_total / clamp_min(trstctl_agents_total, 1)` stays at or
  below `0.02`; stale means the control plane has not seen an agent for two
  heartbeat intervals.
- `sum(increase(trstctl_agent_bulkhead_rejections_total[5m]))` stays `0`.
- Agent logs return to `heartbeat ok`.
- `trstctl-cli agents list` keeps the same fleet count and shows expected versions.
- Inventory counts stay stable. Upgrade should not remove certificate, SSH, or
  agent inventory rows.
- Kubernetes events do not show repeated crash loops, failed mounts, or readiness
  probe failures.

## Abort criteria

Rollback immediately when:

- `/readyz` stays `503` for longer than two readiness probe periods.
- `trstctl_signer_up == 0` after signer rollout completes.
- `TrstctlAgentEnrollmentFailures`, `TrstctlAgentHeartbeatFailures`, or
  `TrstctlAgentFleetStale` fires; these alerts encode the 2 percent
  missed-heartbeat threshold.
- `TrstctlAgentBulkheadSaturated` fires continuously.
- `trstctl-cli agents list` loses hosts that were healthy before the upgrade.
- Inventory counts decrease without an explicit migration note.
- The rendered chart opens or closes the agent channel differently from the
  `trstctl --check-config` output.

## Rollback commands

```sh
helm history trstctl -n trstctl
helm rollback trstctl <last-good-revision> -n trstctl --wait --timeout=10m

kubectl -n trstctl rollout status deployment/trstctl --timeout=10m
kubectl -n trstctl rollout status daemonset/trstctl-agent --timeout=10m
kubectl -n trstctl rollout status deployment/trstctl-signer --timeout=10m
```

If the rollback itself cannot reach readiness, stop fleet churn first, then use
the signer or DR runbook depending on the failing dependency:

```sh
kubectl -n trstctl rollout pause daemonset/trstctl-agent
curl -fsS --cacert "$TRSTCTL_CA_FILE" https://cp.example.com/readyz
curl -fsS --cacert "$TRSTCTL_CA_FILE" https://cp.example.com/metrics | grep trstctl_signer_up
```

## Post-checks

1. `/readyz` is `200`.
2. `trstctl_signer_up == 1`.
3. `trstctl_agents_stale_total / clamp_min(trstctl_agents_total, 1) <= 0.02`.
4. `trstctl-cli agents list` has the expected host count.
5. Inventory counts match the pre-upgrade baseline.
6. Store `helm history`, rendered manifests, and the before/after counts in the
   change ticket.
