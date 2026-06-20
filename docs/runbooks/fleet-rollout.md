# Runbook: fleet rollout

This runbook rolls out trstctl agents to Kubernetes nodes and Windows hosts. The
agent is the small in-network process that enrolls once with a bootstrap token,
then keeps a mutual-TLS channel open so the control plane can see heartbeat,
version, and coarse inventory counts.

Use [fleet rollback](fleet-rollback.md) if any abort criterion trips.

## Prerequisites

- A healthy control plane: `/readyz` returns `200` and names `db`, `nats`, and
  `signer` as `ok`.
- Prometheus can scrape `/metrics`, and `trstctl_signer_up` is `1`.
- The Helm release publishes the agent channel on `:9443` and uses the DNS name
  agents will verify. `deploy/helm/trstctl/values.yaml` controls the setting and
  `deploy/helm/trstctl/templates/service.yaml` renders the `agent-grpc` port:

```sh
helm upgrade --install trstctl deploy/helm/trstctl \
  --namespace trstctl --create-namespace \
  --set agentChannel.enabled=true \
  --set agentChannel.serverName=trstctl
```

- The bootstrap CA bundle exists as `ConfigMap/trstctl-ca-bundle` and matches the
  control-plane certificate used by `/enroll/bootstrap` and the agent channel.
- You can mint one-time tokens with `trstctl-cli agents enroll-token`.
- You have a pre-rollout count from `trstctl-cli agents list` and the inventory
  pages you care about, for example `trstctl-cli certificates list`.

## Commands: Kubernetes canary

Mint one short-lived token, store it in the Secret the DaemonSet mounts, render the
DaemonSet with the immutable release image digest, then apply the packaged
manifests:

The render script reads `deploy/kubernetes/daemonset.yaml` as a template and
refuses to produce a manifest unless `TRSTCTL_AGENT_IMAGE` is a real
`.../trstctl@sha256:<release-image-digest>` reference.

```sh
export TRSTCTL_AGENT_IMAGE='ghcr.io/imfeelingtheagi/trstctl@sha256:<release-image-digest>'
TOKEN="$(trstctl-cli agents enroll-token | jq -r .token)"
rendered_agent_daemonset="$(mktemp)"

kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl -n trstctl create secret generic trstctl-agent-bootstrap \
  --from-literal=token="$TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n trstctl create configmap trstctl-ca-bundle \
  --from-file=ca-bundle.pem=/path/to/agent-channel-ca.pem \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deploy/kubernetes/rbac.yaml
scripts/release/render-kubernetes-agent-daemonset.sh "$TRSTCTL_AGENT_IMAGE" > "$rendered_agent_daemonset"
kubectl apply -f "$rendered_agent_daemonset"
kubectl -n trstctl rollout status daemonset/trstctl-agent --timeout=10m
```

Canary by node label when the cluster is large. Patch the DaemonSet with a
temporary `nodeSelector`, wait for one node to heartbeat, then remove the selector
and continue the rollout.

## Commands: Windows canary

Build or download the signed MSI from the installer definition in
`deploy/windows/trstctl-agent.wxs`, place the CA bundle on the host, mint a token,
and install one host first:

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\trstctl | Out-Null
$token = (trstctl-cli agents enroll-token | ConvertFrom-Json).token
Set-Content -Path C:\ProgramData\trstctl\bootstrap-token.txt -Value $token -NoNewline

msiexec /i trstctl-agent.msi /qn `
  ENROLLURL=https://cp:8443 `
  SERVER=cp:9443 `
  SERVERNAME=cp `
  CABUNDLE=C:\ProgramData\trstctl\ca-bundle.pem `
  BOOTSTRAPTOKENFILE=C:\ProgramData\trstctl\bootstrap-token.txt
```

For a manual service install, use the same runtime flags:

```bat
trstctl-agent.exe --service=install --enroll-url https://cp:8443 ^
  --bootstrap-token-file C:\ProgramData\trstctl\bootstrap-token.txt ^
  --ca-bundle C:\ProgramData\trstctl\ca-bundle.pem --server cp:9443 ^
  --server-name cp --name %COMPUTERNAME%
```

## Expected metrics and logs

- `/readyz` stays `200`; if it flips to `503`, read the JSON body before changing
  more hosts.
- `trstctl_signer_up` stays `1`; agent enrollment and renewal need the signer-held
  agent CA.
- `sum(increase(trstctl_agent_enrollments_total{result="failed"}[15m]))` stays
  `0` during the canary.
- `sum(increase(trstctl_agent_heartbeats_total{result="failed"}[10m])) /
  clamp_min(sum(increase(trstctl_agent_heartbeats_total[10m])), 1)` stays at or
  below `0.02`.
- `trstctl_agents_stale_total / clamp_min(trstctl_agents_total, 1)` stays at or
  below `0.02`; stale means the control plane has not seen an agent for two
  heartbeat intervals.
- `sum(increase(trstctl_agent_bulkhead_rejections_total[5m]))` stays `0`.
- Kubernetes pod logs contain `trstctl-agent: heartbeat ok`.
- Windows service logs contain `heartbeat ok` after first enrollment.
- `trstctl-cli agents list` grows by the number of canary hosts, and each row has
  the expected name/version.
- Inventory counts change only by the assets the canary hosts can see. A sudden
  drop in certificate or SSH inventory means the rollout is hiding or replacing
  data, not only adding agents.

## Abort criteria

Abort immediately when any of these are true for more than one heartbeat interval:

- `/readyz` is not `200`.
- `trstctl_signer_up` is `0`.
- `TrstctlAgentEnrollmentFailures`, `TrstctlAgentHeartbeatFailures`, or
  `TrstctlAgentFleetStale` fires for the canary window.
- The agent channel returns `ResourceExhausted` continuously, which means the
  agent bulkhead is protecting the rest of the system and the rollout is too fast
  (`TrstctlAgentBulkheadSaturated`).
- `trstctl-cli agents list` does not show the canary after the pod or service is
  running.
- Inventory counts drop unexpectedly.

## Rollback commands

For Kubernetes, undo the DaemonSet or pause before it reaches more nodes:

```sh
kubectl -n trstctl rollout pause daemonset/trstctl-agent
kubectl -n trstctl rollout undo daemonset/trstctl-agent
kubectl -n trstctl rollout status daemonset/trstctl-agent --timeout=10m
```

For Windows, stop and uninstall the service on the canary host:

```bat
trstctl-agent.exe --service=uninstall
```

If the MSI installed the service, uninstall the MSI:

```powershell
msiexec /x trstctl-agent.msi /qn
```

## Post-checks

1. Confirm `/readyz` is `200`.
2. Confirm `trstctl_signer_up == 1`.
3. Confirm every canary has a recent agent heartbeat in `trstctl-cli agents list`.
4. Confirm inventory counts are at or above the pre-rollout baseline unless the
   change intentionally removed a destination.
5. Delete or rotate every bootstrap token file after the agent has persisted its
   client certificate.
