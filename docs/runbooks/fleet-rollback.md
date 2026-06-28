# Runbook: fleet rollback and re-enrollment

This runbook rolls back a bad agent rollout and safely re-enrolls agents whose
bootstrap token, client certificate, or local service configuration must be
rotated. It does not restore lost server data; use [disaster recovery](../disaster-recovery.md)
for database, event-log, or object-store recovery.

## Prerequisites

- Capture the current failure shape: `/readyz`, `trstctl_signer_up`,
  `trstctl-cli agents list`, agent logs, and inventory counts.
- Know the last good Kubernetes DaemonSet revision or the last good Windows MSI.
- Have permission to mint a replacement one-time token with
  `trstctl-cli agents enroll-token`.
- Do not revoke the old agent certificate until the host has stopped using it or
  has a new certificate. This prevents a host from getting stuck between identities.

## Commands: stop the rollout

Kubernetes:

```sh
kubectl -n trstctl rollout pause daemonset/trstctl-agent
kubectl -n trstctl get daemonset/trstctl-agent -o wide
kubectl -n trstctl logs -l app.kubernetes.io/name=trstctl-agent --tail=100
```

Windows:

```powershell
Get-Service trstctl-agent
Get-EventLog -LogName Application -Source trstctl-agent -Newest 50
Stop-Service trstctl-agent
```

## Commands: rollback the agent package

Kubernetes DaemonSet:

```sh
kubectl -n trstctl rollout undo daemonset/trstctl-agent
kubectl -n trstctl rollout status daemonset/trstctl-agent --timeout=10m
```

If the problem came from the Helm agent-channel configuration instead of the
DaemonSet image or flags, roll back the chart release:

```sh
helm history trstctl -n trstctl
helm rollback trstctl <last-good-revision> -n trstctl --wait --timeout=10m
```

Windows MSI:

```powershell
msiexec /x trstctl-agent.msi /qn
msiexec /i trstctl-agent-last-good.msi /qn `
  ENROLLURL=https://cp:8443 `
  SERVER=cp:9443 `
  SERVERNAME=cp `
  CABUNDLE=C:\ProgramData\trstctl\ca-bundle.pem `
  BOOTSTRAPTOKENFILE=C:\ProgramData\trstctl\bootstrap-token.txt
Start-Service trstctl-agent
```

## Commands: rotate bootstrap token and re-enroll

Use this when the token leaked, expired before use, or was written to the wrong
Secret/file. For Kubernetes, mint one replacement token per failed node, update
the node-named Secret keys, and restart only those pods. For a whole-DaemonSet
re-enrollment, set `FAILED_NODES` to the full node list from `kubectl get nodes`.

```sh
FAILED_NODES="node-a node-b"
umask 077
bootstrap_token_dir="$(mktemp -d)"
trap 'rm -rf "$bootstrap_token_dir"' EXIT

for node in $FAILED_NODES; do
  trstctl-cli agents enroll-token | jq -r .token > "$bootstrap_token_dir/$node"
done
kubectl -n trstctl create secret generic trstctl-agent-bootstrap \
  --from-file="$bootstrap_token_dir" \
  --dry-run=client -o yaml | kubectl apply -f -
for node in $FAILED_NODES; do
  kubectl -n trstctl delete pod \
    -l app.kubernetes.io/name=trstctl-agent \
    --field-selector spec.nodeName="$node"
done
```

Windows:

```powershell
$token = (trstctl-cli agents enroll-token | ConvertFrom-Json).token
Set-Content -Path C:\ProgramData\trstctl\bootstrap-token.txt -Value $token -NoNewline
Restart-Service trstctl-agent
```

After the replacement heartbeat succeeds, revoke or expire the old agent
certificate according to your incident policy. Do not reuse a one-time token.

## Expected metrics and logs

- `/readyz` returns `200`.
- `trstctl_signer_up` remains `1`; if it is `0`, rollback the agent package only
  after signer recovery starts.
- Bad-version heartbeat failures stop, and logs return to `heartbeat ok`.
- `trstctl-cli agents list` shows the expected pre-rollback host count.
- Inventory counts return to the pre-rollout baseline, plus any hosts that
  legitimately re-enrolled.

## Abort criteria

Escalate to incident response instead of continuing the rollback when:

- `/readyz` stays `503` after the chart or DaemonSet rollback.
- `trstctl_signer_up` stays `0`.
- Agents heartbeat with a tenant or name that does not match the host.
- Inventory counts keep decreasing after the old package is restored.
- Re-enrollment repeatedly consumes tokens without producing new heartbeats.

## Rollback commands for this rollback

If the rollback itself makes things worse, stop the agent surface and keep the
control plane serving API traffic:

```sh
kubectl -n trstctl delete daemonset/trstctl-agent
helm rollback trstctl <pre-rollback-revision> -n trstctl --wait --timeout=10m
```

Windows:

```powershell
Stop-Service trstctl-agent
Set-Service trstctl-agent -StartupType Disabled
```

## Post-checks

1. `/readyz` is green.
2. `trstctl_signer_up == 1`.
3. Every restored host has a fresh agent heartbeat.
4. `trstctl-cli agents list` has the expected host count and versions.
5. Certificate and SSH inventory counts match the rollback baseline.
6. All replaced bootstrap token files and Kubernetes Secret values have been
   rotated or deleted.
