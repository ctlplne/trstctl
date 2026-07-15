# trstctl agent on Kubernetes

The trstctl agent runs as a **DaemonSet** (one pod per node). It installs
certificates into Kubernetes **Secrets** and acts as a **cert-manager external
issuer**. It ships trstctl `Issuer` and `ClusterIssuer` CRDs, marks them Ready,
signs cert-manager `CertificateRequest`s through a served trstctl issuance
endpoint, signs approved native Kubernetes `CertificateSigningRequest`s, and
fulfils trstctl-native `Certificate` CRDs directly into TLS Secrets.

The agent talks to the Kubernetes API server directly over its JSON/HTTPS wire
protocol, authenticating with the pod's service-account token and trusting the
in-cluster CA — no `client-go` dependency.

## Files in this directory

- `namespace.yaml` — creates the `trstctl` namespace.
- `certmanager-issuer-crds.yaml` — the trstctl `Issuer`, `ClusterIssuer`,
  `Certificate`, and `TrustBundle` CRDs.
- `rbac.yaml` — the agent's `ServiceAccount` and least-privilege `ClusterRole`
  (write Secrets; read and status-update only on CSRs and trstctl CRDs).
- `daemonset.yaml` — the DaemonSet template; render it with a real release
  digest via `scripts/release/render-kubernetes-agent-daemonset.sh` before
  applying it (see Deploy below).
- `manifests.go` / `manifests_test.go` — `//go:embed` these manifests into the
  agent binary (`kubernetes.Manifests`) and test them.
- `sigstore-policy.yaml` — a Sigstore policy-controller example that admits
  only release images signed by this repository's GitHub Actions workflow.

## Deploy

First make the control plane publish the agent steady-state channel. The packaged
DaemonSet connects to the in-namespace `trstctl` Service on `:9443`, so the chart
must enable that port and mint the channel certificate with `trstctl` as a DNS SAN:

```sh
helm upgrade --install trstctl deploy/helm/trstctl \
  --namespace trstctl --create-namespace \
  --set agentChannel.enabled=true \
  --set agentChannel.serverName=trstctl
```

Then choose the immutable release image, mint one bootstrap token per
Kubernetes node, store those tokens as node-named keys in the Secret the DaemonSet
mounts, create the CA bundle ConfigMap, render the DaemonSet with that release
digest, and apply the agent manifests:

```sh
export TRSTCTL_SERVER=https://cp.example.com
export TRSTCTL_TOKEN=trst_...
export TRSTCTL_AGENT_IMAGE='ghcr.io/ctlplne/trstctl@sha256:<release-image-digest>'

umask 077
bootstrap_token_dir="$(mktemp -d)"
rendered_agent_daemonset="$(mktemp)"
trap 'rm -rf "$bootstrap_token_dir" "$rendered_agent_daemonset"' EXIT

kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' |
  while IFS= read -r node; do
    [ -n "$node" ] || continue
    jq -nc --arg allowed_identity "$node" '{allowed_identity:$allowed_identity}' |
      trstctl-cli agents enroll-token -f - | jq -r .token > "$bootstrap_token_dir/$node"
  done
kubectl -n trstctl create secret generic trstctl-agent-bootstrap \
  --from-file="$bootstrap_token_dir" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n trstctl create secret generic trstctl-cert-manager-issuer \
  --from-literal=signer-url="https://trstctl:8443/api/v1/ca/authorities/<ca-authority-id>/issue" \
  --from-literal=token="$TRSTCTL_TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n trstctl create configmap trstctl-ca-bundle \
  --from-file=ca-bundle.pem=/path/to/agent-channel-ca.pem \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deploy/kubernetes/certmanager-issuer-crds.yaml
kubectl apply -f deploy/kubernetes/rbac.yaml
scripts/release/render-kubernetes-agent-daemonset.sh "$TRSTCTL_AGENT_IMAGE" > "$rendered_agent_daemonset"
kubectl apply -f "$rendered_agent_daemonset"
```

Each bootstrap token is single-use and short-lived. The Secret must contain one
key per node, and each key name must exactly match that node's
`metadata.name`. The DaemonSet uses `subPathExpr: $(NODE_NAME)` to mount only the
matching Secret key at `/var/run/trstctl/bootstrap-token`, then passes
`--bootstrap-token-file`; no token is placed directly on the agent command line.
Each token is pinned to the same node name through `allowed_identity`, so
`/enroll/bootstrap` rejects a CSR whose common name or identity SANs ask for a
different agent identity.
The enrollment URL must be an `https://` control-plane base URL
(`https://trstctl:8443`); the agent appends `/enroll/bootstrap` itself.

`TRSTCTL_AGENT_IMAGE` must be a real `.../trstctl@sha256:<64-hex-digest>` release
image; the render script rejects tags, short digests, and the all-zero placeholder.
Create `ConfigMap/trstctl-ca-bundle` with `ca-bundle.pem` before applying the
rendered DaemonSet. The PEM bundle may contain more than one certificate; the agent
uses only this bundle to pin bootstrap HTTPS before posting the one-time token and
for the steady-state mTLS channel. The DaemonSet intentionally treats the ConfigMap
as required so a missing bundle fails before the pod can attempt enrollment.
The agent identity key and certificate are stored on the node at
`/var/lib/trstctl-agent` through a `hostPath` volume, so a pod replacement does not
consume another bootstrap token. The DaemonSet initContainer uses the same
`trstctl-agent` binary to prepare that host directory for the non-root agent uid.
Delete that host directory only when you intend to force re-enrollment for the node.

Create `Secret/trstctl-cert-manager-issuer` with:

- `signer-url`: the served trstctl issuance endpoint that accepts a PEM CSR, for
  example `/api/v1/ca/authorities/{id}/issue`;
- `token`: an API token with permission to issue through that endpoint.

The token is mounted as a file at `/var/run/trstctl/cert-manager/token`; it is not
put on the command line or in an environment variable. The agent sends a stable
`Idempotency-Key` per CSR, so cert-manager retries do not mint duplicate
certificates.

These are also embedded in the agent binary (`deploy/kubernetes`.`Manifests`) and
validated in tests. The `ClusterRole` grants least privilege: write Secrets, and
read cert-manager `CertificateRequest`s, native Kubernetes
`CertificateSigningRequest`s, and trstctl `Issuer`/`ClusterIssuer`/`Certificate`
resources; it updates only status subresources for request/controller resources
and writes Secrets for issued workload certificates — nothing else.

The DaemonSet runs `trstctl-agent --k8s`, which:

1. bootstraps the agent identity (mutual-TLS, S5.1);
2. publishes that certificate into the Secret named by `--k8s-secret`
   (`namespace/name`), as a `kubernetes.io/tls` Secret (`tls.crt` / `tls.key`);
3. if `--cert-manager-controller`, `--bridge-signer-url`, and
   `--bridge-signer-token-file` are set, reconciles trstctl `Issuer` and
   `ClusterIssuer` CRDs, marks them Ready, signs matching cert-manager
   `CertificateRequest`s, signs approved native Kubernetes
   `CertificateSigningRequest`s, fulfils trstctl-native `Certificate` resources
   into their requested TLS Secrets, and writes status back to the owning
   resource.

For node-level certificate inventory, add read-only hostPath mounts for the public
certificate directories you want to enumerate and pass
`--inventory-cert-roots=/host/etc/ssl,/host/etc/pki/tls/certs`. The agent reports
fingerprints and metadata over the mTLS agent channel; it does not send private keys or
secret values.

For node trust-store inventory, add read-only hostPath mounts for the public trust
anchor directories and pass `--inventory-os-trust-roots=/host/etc/ssl/certs`.
Java, NSS, and browser trust-store exports use the corresponding
`--inventory-java-trust-stores`, `--inventory-nss-trust-roots`, and
`--inventory-browser-trust-roots` flags.

For private-key-material discovery, mount only the directories you intentionally
want inspected and pass `--inventory-private-key-roots=/host/etc/ssl/private,/host/etc/ssh`.
The agent classifies key format/algorithm locally, derives a public-key fingerprint
when possible, wipes file buffers after inspection, and reports `private_key`
findings without sending PEM/DER key bytes.

## Learn more

The agent's cert-manager `Issuer`/`ClusterIssuer` integration, the native
Kubernetes `CertificateSigningRequest` path, `TrustBundle` CA distribution, the
trstctl-native `Certificate` API, and the e2e/kind test procedure now live in
[Kubernetes agent integrations and e2e testing](../../docs/guides/kubernetes-agent.md).
