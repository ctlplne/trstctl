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
- Record `trstctl-cli agents list` and inventory counts before the upgrade.
- Run `trstctl --check-config` in the candidate environment and confirm the
  `agent_channel.*` lines match the planned fleet topology.

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
curl -fksS https://cp.example.com/readyz
curl -fksS https://cp.example.com/metrics | grep trstctl_signer_up
```

## Post-checks

1. `/readyz` is `200`.
2. `trstctl_signer_up == 1`.
3. `trstctl_agents_stale_total / clamp_min(trstctl_agents_total, 1) <= 0.02`.
4. `trstctl-cli agents list` has the expected host count.
5. Inventory counts match the pre-upgrade baseline.
6. Store `helm history`, rendered manifests, and the before/after counts in the
   change ticket.
