# trstctl control-plane Helm chart

Deploys the trstctl **control plane** (API + web UI) to Kubernetes with the
**signing service isolated behind AN-4** and wired to **external PostgreSQL and
NATS**. The default topology runs the signer as a locked-down sidecar over an
in-memory Unix socket. For stricter process and pod isolation, set
`signer.mode=isolated` and provide the `signer.mtls.*` trust material; the chart
then renders a separate signer Deployment reached over mutually pinned mTLS.

## What it deploys

By default, one control-plane pod contains two containers:

- **`trstctl`** — the control plane: serves the API/UI on `:8443` (HTTPS by
  default), connects to external PostgreSQL and NATS, and reaches the signer in
  *external* mode over a shared in-memory Unix socket.
- **`signer`** — the signing service (AN-4) as its own **locked-down** container
  with **no network listener at all**. It talks to the control plane only over the
  shared `emptyDir{medium: Memory}` socket, so nothing on the cluster network can
  reach it. Its CA key is **sealed at rest** in a persistent key store, so a
  restart preserves the issuing CA (R3.2).

With `signer.mode=isolated`, the chart removes the sidecar from the control-plane
pod and renders a separate **`trstctl-signer`** Deployment, Service, and
NetworkPolicy. The control plane dials `:9443` over mutually pinned mTLS using
operator-supplied Secrets; the signer pod mounts the same sealed key store, KEK,
and signer authorization secret.

Plus a `ConfigMap`, `Secret`s (KEK + DB DSN, or your own), a `Service`, a
default-deny `NetworkPolicy`, a `ServiceAccount` (no cluster RBAC, token not
mounted), PVCs, and a `PodDisruptionBudget`. All application containers run
non-root, read-only root filesystem, all capabilities dropped, `seccompProfile:
RuntimeDefault`.

## Quick start

The chart fails at template time if the required install inputs are missing. Provide
external datastores + a stable KEK, then install:

```bash
helm install trstctl deploy/helm/trstctl \
  --namespace trstctl --create-namespace \
  --set image.digest='sha256:<release-image-digest>' \
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
| `image.digest` | `""` | Production image digest. When set, pods render `image.repository@sha256:...` and ignore `image.tag`. |
| `postgres.dsn` / `postgres.existingSecret` | `""` | External PostgreSQL (required). |
| `nats.url` | `""` | External NATS JetStream (required). |
| `nats.replicas` | `3` | Required JetStream replicas for the source-of-truth event stream. Startup/readiness fail if NATS cannot honor it. |
| `nats.allowSingleReplica` | `false` | Eval-only opt-in for `nats.replicas=1`; leave false for production. |
| `kek.existingSecret` / `kek.generate` | `""` / `false` | Deployment KEK (R3.1/R3.2). **Stable & required.** |
| `tls.mode` | `internal` | `internal` (self-signed), `file` (`tls.existingSecret`), or `disabled`. `disabled` also requires `tls.allowPlaintextDev=true` and a loopback `server.addr`; never use it in production. |
| `tls.allowPlaintextDev` | `false` | Explicit local-dev override required when `tls.mode=disabled`. |
| `persistence.enabled` | `true` | PVCs for the CA cert, audit key, and sealed signer keys. |
| `networkPolicy.enabled` | `true` | Default-deny; opens `:8443` in, PG/NATS/DNS out, plus signer mTLS egress in isolated mode. |
| `airGap.enabled` | `false` | Enables the runtime no-phone-home egress guard. Use `values-airgap.yaml` for disconnected installs. |
| `networkPolicy.egress.allowedCIDRs` | `[]` | Optional CIDRs that scope PostgreSQL/NATS egress. The air-gap overlay sets private ranges; replace them with your cluster/VPC ranges. |
| `replicaCount` | `2` | Multi-replica control plane by default; leader election gates continuous workers. |
| `bulkheads.<subsystem>.workers` / `bulkheads.<subsystem>.queue` | see `values.yaml` | Per-subsystem AN-7 worker and queue limits rendered into `TRSTCTL_BULKHEAD_*`; tune agent/protocol/outbox separately for fleet size. |
| `signer.mode` | `sidecar` | `sidecar` uses a co-located UDS-only signer; `isolated` renders a separate signer pod over mTLS. |
| `signer.mtls.serverName` | `""` | Required for `signer.mode=isolated`; must match the signer certificate SAN. |
| `signer.mtls.signerSecret` | `""` | Secret for the signer pod: `tls.crt`, `tls.key`, `peer-ca.pem`, and `peer-pin`. |
| `signer.mtls.controlPlaneSecret` | `""` | Secret for the control plane: `tls.crt`, `tls.key`, `peer-ca.pem`, and `peer-pin`. |

## Operational notes

- **Multi-replica HA is the default.** The chart runs `replicaCount: 2`,
  `RollingUpdate maxUnavailable: 0`, a PodDisruptionBudget, and leader election so
  only one replica runs continuous background workers. Use an RWX-capable
  StorageClass for the default `ReadWriteMany` volumes.
- **Sidecar signer is the default HA topology.** Every replica's sidecar loads the
  same sealed signer key store, so all replicas are the same CA while the signer
  remains outside the control-plane process.
- **Isolated signer is opt-in.** `signer.mode=isolated` is implemented, but the
  operator must provision both mTLS Secrets out of band. The chart fails fast if
  isolated mode is selected without `signer.mtls.serverName`.
- **Air-gapped install is an overlay.** `values-airgap.yaml` sets
  `airGap.enabled=true`, leaves product telemetry off, and scopes datastore egress
  to private CIDRs. Edit those CIDRs for your cluster before installing.
- **The Kubernetes Operator is intentionally smaller than Helm.** The operator
  reconciles Deployment image/replica basics; Helm remains the complete production
  install for Services, Secrets, NetworkPolicies, signer topology, PostgreSQL, and
  NATS.

`helm lint` and `helm template` run in CI; the chart templates are also
syntax-checked by `deploy/helm` tests.
