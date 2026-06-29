# Runbook: isolated signer recovery

The signer is the separate process that holds private-key operations. In an
isolated Helm topology it runs as its own Deployment from
`deploy/helm/trstctl/templates/signer-deployment.yaml`, speaks only gRPC over
mTLS, and uses the signer key store plus either a local KEK mount or Helm
`externalKMS` DEK wrapping. Recovery means getting that same signer identity and
key store healthy again, not silently making a new CA.

## Prerequisites

- Decide whether this is a restart failure, storage failure, or key compromise.
  Use [incident response](incident-response.md) for suspected compromise.
- Confirm the signer PVC or configured key store, signer auth Secret, signer mTLS
  Secret, and the configured custody input still exist. Local-KEK installs need the
  KEK Secret; externalKMS installs need the same provider, keyRef, wrapper adapter,
  and provider credentials.
- Confirm the control plane can still answer `/healthz`; `/readyz` may be `503`
  because it checks the signer.
- Capture `trstctl_signer_up`, signer pod logs, control-plane logs, agent
  heartbeat age, and inventory counts before changing anything.
- Have a recent full backup if the signer key store, signer auth Secret, local KEK,
  or externalKMS adapter configuration must be restored.

## Commands: inspect and restart

```sh
kubectl -n trstctl get deploy,pod,pvc,secret | grep -E 'trstctl|signer'
kubectl -n trstctl logs deploy/trstctl-signer --tail=200
kubectl -n trstctl describe deploy/trstctl-signer

kubectl -n trstctl rollout restart deployment/trstctl-signer
kubectl -n trstctl rollout status deployment/trstctl-signer --timeout=10m
```

Then check the control plane:

```sh
curl -fksS https://cp.example.com/readyz
curl -fksS https://cp.example.com/metrics | grep trstctl_signer_up
trstctl-cli agents list
trstctl-cli certificates list
```

## Commands: restore signer storage

If the signer pod cannot open `/data/signer/keys`, `/etc/trstctl/kek/kek.bin`, or
the configured `externalKMS` wrapper, restore the key store and the matching
custody input from the last known-good operational backup. Do not delete and
recreate the key store as a "quick fix"; that changes the CA identity.

```sh
kubectl -n trstctl scale deployment/trstctl --replicas=0
kubectl -n trstctl scale deployment/trstctl-signer --replicas=0

# Restore the signer PVC and custody input using your storage backup tooling.
# Local KEK mode must restore /data/signer/keys and /etc/trstctl/kek/kek.bin.
# externalKMS mode must restore /data/signer/keys and the same provider/keyRef/wrapper adapter.

kubectl -n trstctl scale deployment/trstctl-signer --replicas=1
kubectl -n trstctl rollout status deployment/trstctl-signer --timeout=10m
kubectl -n trstctl scale deployment/trstctl --replicas=1
kubectl -n trstctl rollout status deployment/trstctl --timeout=10m
```

If the key store is lost and no backup exists, stop. Open a CA
[key ceremony](key-ceremony.md) and re-issue under a new CA. That is a planned
trust migration, not signer recovery.

## Expected metrics and logs

- `/readyz` changes from signer-degraded to `200`.
- `trstctl_signer_up` changes from `0` to `1`.
- Signer logs show a listener on `:9443` and no KEK, externalKMS, or key-store open
  errors.
- Control-plane logs stop reporting signer health failures.
- Existing agents heartbeat again without re-enrollment.
- Inventory counts remain stable; signer restart should not erase certificates,
  agents, or SSH keys.

## Abort criteria

Stop and escalate when:

- `trstctl_signer_up` remains `0` after one clean signer rollout.
- `/readyz` still reports signer failure after the pod is Ready.
- The signer starts with an empty key store when a non-empty one was expected.
- Agent heartbeats resume under a different tenant or CA bundle.
- Inventory counts drop after signer recovery.
- Any log suggests private-key compromise, KEK mismatch, externalKMS unwrap
  failure, or unauthorized handle use.

## Rollback commands

Rollback means return to the last known-good signer Deployment and storage
snapshot:

```sh
helm history trstctl -n trstctl
helm rollback trstctl <last-good-revision> -n trstctl --wait --timeout=10m
kubectl -n trstctl rollout status deployment/trstctl-signer --timeout=10m
```

If the new signer pod is unsafe, stop issuance while you investigate:

```sh
kubectl -n trstctl scale deployment/trstctl-signer --replicas=0
```

This makes issuance and renewal fail closed; it is better than serving with an
unknown key store.

## Post-checks

1. `/readyz` is `200`.
2. `trstctl_signer_up == 1`.
3. Agent heartbeat age returns to the normal interval.
4. `trstctl-cli agents list` still has the expected fleet count.
5. `trstctl-cli certificates list` and other inventory counts match the
   pre-incident baseline.
6. Record whether recovery used restart only, storage restore, or CA key ceremony.
