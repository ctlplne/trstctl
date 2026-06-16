# trstctl control-plane Helm chart

Deploys the trstctl **control plane** (API + web UI) to Kubernetes with the
**signing service isolated** and wired to **external PostgreSQL and NATS**. This is
the production-shaped install for the remediated Phase 1 artifact; the main plan's
**S15.1** verifies and extends it (HA, a fully separate signer pod over mTLS, and a
Kubernetes **Operator** — see "Not yet" below).

## What it deploys

One pod with two containers:

- **`trstctl`** — the control plane: serves the API/UI on `:8443` (HTTPS by
  default), connects to external PostgreSQL and NATS, and reaches the signer in
  *external* mode over a shared in-memory Unix socket.
- **`signer`** — the signing service (AN-4) as its own **locked-down** container
  with **no network listener at all**. It talks to the control plane only over the
  shared `emptyDir{medium: Memory}` socket, so nothing on the cluster network can
  reach it. Its CA key is **sealed at rest** in a persistent key store, so a
  restart preserves the issuing CA (R3.2).

Plus a `ConfigMap`, `Secret`s (KEK + DB DSN, or your own), a `Service`, a
default-deny `NetworkPolicy`, a `ServiceAccount` (no cluster RBAC, token not
mounted), PVCs, and a `PodDisruptionBudget`. Both containers run non-root,
read-only root filesystem, all capabilities dropped, `seccompProfile:
RuntimeDefault`.

## Quick start

Provide external datastores + a stable KEK, then install:

```bash
helm install trstctl deploy/helm/trstctl \
  --namespace trstctl --create-namespace \
  --set postgres.dsn='postgres://user:pass@pg-host:5432/trstctl?sslmode=require' \
  --set nats.url='nats://nats-host:4222' \
  --set kek.generate=true        # eval only; supply kek.existingSecret in production
```

Then:

```bash
kubectl -n trstctl rollout status deploy/trstctl
kubectl -n trstctl port-forward svc/trstctl 8443:8443   # https://localhost:8443 (-k)
```

## Key values

| Key | Default | Notes |
|---|---|---|
| `postgres.dsn` / `postgres.existingSecret` | `""` | External PostgreSQL (required). |
| `nats.url` | `""` | External NATS JetStream (required). |
| `kek.existingSecret` / `kek.generate` | `""` / `false` | Deployment KEK (R3.1/R3.2). **Stable & required.** |
| `tls.mode` | `internal` | `internal` (self-signed), `file` (`tls.existingSecret`), or `disabled`. |
| `persistence.enabled` | `true` | PVCs for the CA cert, audit key, and sealed signer keys. |
| `networkPolicy.enabled` | `true` | Default-deny; opens `:8443` in, PG/NATS/DNS out. |
| `replicaCount` | `1` | Single replica by design — see below. |

## Not yet (tracked for S15.1)

- **Multi-replica HA / a fully separate signer pod over mTLS.** The signer holds
  the CA key with a per-pod sealed key store and a UDS-only transport, so scaling
  horizontally needs a shared/separate signer reachable over **mTLS** — that
  network transport is not yet implemented, so this chart runs **one** control-plane
  replica.
- **A Kubernetes Operator.** A CRD-driven operator is planned for S15.1; today this
  chart is the supported Kubernetes install for the control plane.

`helm lint` and `helm template` run in CI; the chart templates are also
syntax-checked by `deploy/helm` tests.
