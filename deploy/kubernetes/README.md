# trstctl agent on Kubernetes

The trstctl agent runs as a **DaemonSet** (one pod per node). It installs
certificates into Kubernetes **Secrets** and acts as a **cert-manager external
issuer**, signing `CertificateRequest`s through trstctl.

The agent talks to the Kubernetes API server directly over its JSON/HTTPS wire
protocol, authenticating with the pod's service-account token and trusting the
in-cluster CA — no `client-go` dependency.

## Deploy

```sh
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/rbac.yaml
kubectl apply -f deploy/kubernetes/daemonset.yaml
```

These are also embedded in the agent binary (`deploy/kubernetes`.`Manifests`) and
validated in tests. The `ClusterRole` grants least privilege: write Secrets, and
read `CertificateRequest`s plus update their status — nothing else.

The DaemonSet runs `trstctl-agent --k8s`, which:

1. bootstraps the agent identity (mutual-TLS, S5.1);
2. publishes that certificate into the Secret named by `--k8s-secret`
   (`namespace/name`), as a `kubernetes.io/tls` Secret (`tls.crt` / `tls.key`);
3. if `--cert-manager-issuer` and `--bridge-signer-url` are set, reconciles
   cert-manager `CertificateRequest`s for that issuer, forwarding each CSR to the
   control plane for signing and writing the result back to the request status.

## cert-manager bridge

Point a cert-manager `Issuer`/`ClusterIssuer` (or a raw `CertificateRequest`) at
trstctl by `issuerRef` (`name: trstctl`, `group: trstctl.com`). The agent signs
matching requests and sets their `Ready` condition with the issued certificate.
Only a CSR ever crosses the wire to the control plane — never a private key.

## End-to-end test

`test/e2e/kubernetes` exercises the secret destination and the cert-manager
bridge against a real API server. CI runs it on a `kind` cluster with the
cert-manager CRDs installed (the `kubernetes / kind e2e` job). The agent uses
its restricted service-account token (`K8S_TOKEN`); fixtures and verification
use an admin token (`K8S_ADMIN_TOKEN`), because the agent service account is
least-privilege and cannot create `CertificateRequest`s. Locally:

```sh
export K8S_SERVER=... K8S_TOKEN=... K8S_ADMIN_TOKEN=... K8S_CA_FILE=... K8S_NAMESPACE=trstctl
go test -tags e2e ./test/e2e/kubernetes/...
```

The bridge merges into a request's status (it preserves conditions such as
cert-manager's `Approved`, upserting `Ready`), so it composes with cert-manager's
approval flow; exercising that full controller/approval path end-to-end is a
follow-up. The platform-neutral logic is covered on every platform by unit
tests against an in-process Kubernetes API double (`internal/agent/k8s`).
