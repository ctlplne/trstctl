# Kubernetes agent integrations and e2e testing

This guide covers the trstctl Kubernetes agent's integration paths — cert-manager,
native `CertificateSigningRequest`s, `TrustBundle` distribution, and the
trstctl-native `Certificate` API — plus how to exercise all of them end-to-end,
including the kind-based CI path. Deploy the agent first with
`deploy/kubernetes/README.md` in the source checkout; come here once
it is running and you need to wire in one of these integrations or reproduce the
e2e/kind test locally.

## How the controller runs

With `--cert-manager-controller` the agent runs one controller for every path
below. It watches its resources through the Kubernetes API — trstctl `Issuer`,
`ClusterIssuer`, `Certificate` and `TrustBundle` objects, cert-manager
`CertificateRequest`s, native `CertificateSigningRequest`s, and the ConfigMaps
it distributed — and a work queue converges each object as its watch event
arrives, so an approved request is signed and a changed bundle is copied within
about a second. It also re-checks every object every `--k8s-resync` (default
ten minutes) for what no watch reports, such as a deleted certificate Secret,
and sends its posture report after each burst of changes and every
`--reconcile-every` (default thirty seconds). cert-manager is optional: without
its CRDs the other paths run and the cert-manager posture is complete and
empty. The DaemonSet's pods elect one controller through a
`coordination.k8s.io` Lease; a pod that loses the lease stops its watches.

## cert-manager external issuer

Install the CRDs and create a trstctl `ClusterIssuer`:

```yaml
apiVersion: trstctl.com/v1alpha1
kind: ClusterIssuer
metadata:
  name: trstctl
spec:
  signerURL: https://trstctl:8443/api/v1/ca/authorities/<ca-authority-id>/issue
  caAuthorityID: <ca-authority-id>
  ttlSeconds: 7200
```

Then point a cert-manager `Certificate` at it:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: web
  namespace: apps
spec:
  secretName: web-tls
  dnsNames:
    - web.apps.svc.cluster.local
  issuerRef:
    name: trstctl
    kind: ClusterIssuer
    group: trstctl.com
```

cert-manager creates the `CertificateRequest`. A separate Kubernetes approver
must set `Approved=True` first; the trstctl agent does not approve its own
requests and ignores unapproved or denied requests. Put the same exact HTTPS
issuance endpoint in the operator-owned `Secret/trstctl-cert-manager-issuer`'s
`signer-url` value and in the Issuer's `spec.signerURL`. A mismatch, an invalid
`ttlSeconds`, or a `caAuthorityID` that differs from the URL leaves the Issuer
`Ready=False`; it never silently selects the configured CA. `ttlSeconds` caps
the requested lifetime for cert-manager, native Kubernetes CSRs, and trstctl
Certificates. The CA's own profile can restrict it further. The earlier
`profileName` field is unsupported by this endpoint and is no longer offered by
the CRD; an old stored object that still sets it is NotReady. This deployment
configures one CA endpoint for its issuer controller.

The older `--cert-manager-issuer` fixed-name bridge signs only requests in the
agent namespace and does not read Issuer resources. It cannot run alongside
`--cert-manager-controller`; the shipped DaemonSet uses only the resource-aware
controller so Issuer configuration governs every signing decision.

The agent confirms the named
trstctl issuer resource exists in the correct scope: a `ClusterIssuer` can serve
requests in any namespace, while an `Issuer` serves only requests in its own
namespace. It forwards the CSR and requested
`CertificateRequest.spec.duration` to the configured issuance endpoint, and sets
the request `Ready=True` with the issued certificate. When duration is absent,
the agent requests 24 hours; the CA profile may cap the issued lifetime. cert-manager
then writes `Secret/web-tls`. Only a CSR crosses the wire to the control plane —
never a private key. A `Ready=True` Issuer proves that its configuration matches
the operator endpoint; the issued CertificateRequest and Secret prove that the
network, token, and CA can actually complete issuance.

After each burst of changes, and on its heartbeat, the enrolled agent sends a metadata-only report over its
authenticated agent connection. `GET /api/v1/kubernetes/cert-manager-certificate-requests`
shows the current `CertificateRequest` UID, parent `Certificate` UID, state, and
SHA-256 fingerprint of the issued leaf. The agent verifies the request signature
and that the leaf contains the request's exact public key before reporting a
ready binding. `GET /api/v1/certificates/{id}` and the
certificate inventory return `kubernetes_provenance` only when that fingerprint
matches a certificate issued by trstctl. The event projection retains this
exact binding after cert-manager removes the request. The Certificates console
labels the leaf **cert-manager renewal observed**, links to the exact request
under Workloads & Machines, and shows both UIDs. A name, SAN, or idempotency-key
prefix never creates the link. Earlier leaves for which no authenticated report
exists remain unlinked.

This observation proves that the agent saw the issued leaf in the approved
request's status. Check `Secret/web-tls` with `kubectl`, then read the actual
listener with a stock TLS client to prove delivery and serving. The provenance
field and console never claim those later effects on their own. A stale report
also does not prove the controller is currently healthy; the Workloads view
shows report freshness and reconcile completion separately.

Grant a distinct approver only the signer name it reviews. This example creates
its own identity, gives it request read and status update access only in `apps`,
and limits its signer approval grant to the `trstctl` ClusterIssuer. cert-manager
stores the approval condition on `certificaterequests/status`; it does not expose
an `approval` subresource. The status grant can also change other request
conditions, so keep this identity separate from the issuer agent. The agent
service account needs neither grant:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: trstctl-web-approver
  namespace: apps
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: trstctl-web-approver
rules:
  - apiGroups: [cert-manager.io]
    resources: [signers]
    resourceNames: [clusterissuers.trstctl.com/trstctl]
    verbs: [approve]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: trstctl-web-approver
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: trstctl-web-approver
subjects:
  - kind: ServiceAccount
    name: trstctl-web-approver
    namespace: apps
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: trstctl-web-request-approver
  namespace: apps
rules:
  - apiGroups: [cert-manager.io]
    resources: [certificaterequests]
    verbs: [get, list]
  - apiGroups: [cert-manager.io]
    resources: [certificaterequests/status]
    verbs: [update]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: trstctl-web-request-approver
  namespace: apps
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: trstctl-web-request-approver
subjects:
  - kind: ServiceAccount
    name: trstctl-web-approver
    namespace: apps
```

After inspecting the generated request, the approver can approve it with a
short-lived token minted for this identity and a kubeconfig containing that
token:

```sh
kubectl -n apps get certificaterequest
KUBECONFIG=<approver-kubeconfig> cmctl approve -n apps <request-name> --reason pki-review
```

cert-manager documents the [exact signer
RBAC syntax](https://cert-manager.io/docs/usage/certificaterequest/) and
[`cmctl approve`](https://cert-manager.io/docs/reference/cmctl/).

## Native Kubernetes CertificateSigningRequest

Kubernetes clients can use the built-in `certificates.k8s.io/v1`
`CertificateSigningRequest` API without cert-manager. The request must be
approved by Kubernetes policy first; the trstctl agent does not approve requests.
When `spec.signerName` maps to a trstctl `ClusterIssuer`, the agent forwards only
the CSR bytes and `spec.expirationSeconds` to the configured issue endpoint with
a stable idempotency key, then writes `status.certificate` on the CSR status
subresource. Kubernetes CSRs have no namespace. To choose a namespaced trstctl
`Issuer`, set `trstctl.com/issuer-kind: Issuer` and
`trstctl.com/issuer-namespace: <namespace>` annotations; otherwise the agent
will not infer a namespaced issuer from a same-named resource. If present,
`trstctl.com/issuer-name` must exactly match the issuer name in
`spec.signerName`; annotations cannot redirect a CSR to another CA. The agent
requests 24 hours if `spec.expirationSeconds` is absent, subject to the CA profile.
An approved CSR with a conflicting annotation is reported as
`failed/issuer_binding_mismatch`; an extra path segment in `spec.signerName` is
`failed/invalid_signer_name`. Correct the request and submit a new CSR instead
of looking for a missing Issuer.

```yaml
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: web
  annotations:
    trstctl.com/issuer-kind: ClusterIssuer
spec:
  signerName: trstctl.com/trstctl
  request: <base64-pem-csr>
  expirationSeconds: 3600
  usages:
    - digital signature
    - key encipherment
    - server auth
```

Kubernetes checks `signers` authorization again when the agent writes the
certificate. The shipped agent ClusterRole grants `sign` only on
`trstctl.com/trstctl`. For another issuer name, grant the agent ServiceAccount
`sign` on that **exact** `trstctl.com/<issuer-name>` resource name, then bind
the role to `trstctl-agent` in namespace `trstctl`. A Ready ClusterIssuer does
not replace this permission; the API server returns 403 without it. Keep the
approver separate: it needs `get` on CSRs, `update` on
`certificatesigningrequests/approval`, and `approve` on the same exact signer
name. The agent must not receive that approval grant. Kubernetes documents the
[approval and signing RBAC](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#certificate-signing-authorization).

Use `trstctl-cli kubernetes csr` or
`GET /api/v1/kubernetes/certificate-signing-requests` to inspect the served
CAP-K8S-04 posture, supported signer names, required RBAC, and residuals.

## TrustBundle CA-bundle distribution

To distribute a public CA bundle into multiple namespaces, create a cluster-scoped
trstctl `TrustBundle`. The agent validates that `spec.caBundlePEM` contains only
PEM `CERTIFICATE` blocks, writes a ConfigMap in each target namespace, and marks
the TrustBundle Ready with the target count and bundle hash.

```yaml
apiVersion: trstctl.com/v1alpha1
kind: TrustBundle
metadata:
  name: platform-roots
spec:
  caBundlePEM: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  target:
    configMapName: platform-ca-bundle
    key: ca-bundle.pem
    namespaces:
      - apps
      - payments
```

The agent creates or updates `ConfigMap/platform-ca-bundle` in `apps` and
`payments`, setting `data["ca-bundle.pem"]` to the public CA bundle. In a
ConfigMap that already exists it changes only that key, its own labels and the
`trstctl.com/bundle-sha256` annotation, keeping any other keys, and it writes
nothing when a copy already holds the bundle. It watches the copies too, so an
edited or deleted one is put back within about a second. It does not
copy private keys, bearer tokens, or workload credentials into the ConfigMap. Use
`trstctl-cli kubernetes trust-bundles` or
`GET /api/v1/kubernetes/trust-bundles` to inspect the served CAP-K8S-07 posture,
required RBAC, status fields, and residuals.

A bundle that cannot be distributed (an invalid spec, a target it may not
write, an API the cluster does not serve) is marked `Ready=False` with reason
`DistributionFailed` and the cause in its message, so `kubectl get trustbundle`
shows why; the agent retries and marks it Ready once the cause is fixed.

### Secret and ClusterTrustBundle targets

Some consumers read CA bundles from Secrets, and Kubernetes can mount a
`ClusterTrustBundle` into pods through a projected volume. A TrustBundle can
name either or both, next to its ConfigMaps:

```yaml
  target:
    namespaces: [apps, payments]
    secret:
      name: platform-ca      # an Opaque Secret in each target namespace
      key: ca.crt            # optional; default ca.crt
    clusterTrustBundle:
      name: platform-roots   # cluster-scoped, no signer name
```

Both hold the same public CA certificates and carry the agent's labels
(`app.kubernetes.io/managed-by: trstctl-agent`, `trstctl.com/trust-bundle`);
the agent never changes a Secret or ClusterTrustBundle of that name that
someone else created, and reports it instead. The TrustBundle's status adds
`secretTargets` and `clusterTrustBundle`.

- **Secrets** outside the agent's own namespace need the opt-in grant in
  `deploy/kubernetes/rbac-trust-secrets.yaml`. It lets the agent read any
  Secret by name, so apply it only where that is acceptable, or bind a
  namespaced Role with `get`, `create`, `update` and `patch` on Secrets in each
  target namespace instead. Without a grant, the TrustBundle names the
  namespace it could not write and the file to apply.
- **ClusterTrustBundles** need a cluster that serves
  `certificates.k8s.io/v1beta1` `clustertrustbundles` (beta, and off by default
  through Kubernetes 1.35: enable the `ClusterTrustBundle` feature gate and that
  API in the API server's `--runtime-config`), and, for pods to mount one, the
  `ClusterTrustBundleProjection` feature gate on the kubelets. The agent's
  ClusterRole in `rbac.yaml` already carries the verbs. On a cluster without the
  API the TrustBundle says how to enable it. A pod mounts it like this:

  ```yaml
  volumes:
    - name: trust
      projected:
        sources:
          - clusterTrustBundle:
              name: platform-roots
              path: ca.crt
  ```

### Inline CSI volumes

Where neither suits, `deploy/kubernetes/csi-trust.yaml` installs a node plugin
(CSI driver `trust.csi.trstctl.com`) that serves a TrustBundle to a pod as an
inline volume, with no copy per namespace:

```yaml
  volumes:
    - name: trust
      csi:
        driver: trust.csi.trstctl.com
        readOnly: true
        volumeAttributes:
          trustBundle: platform-roots
          key: ca.crt          # optional; default ca.crt
```

The plugin runs the agent binary in its CSI mode
(`trstctl-agent --csi-trust-socket`) on every node, beside the upstream node
driver registrar. It reads TrustBundles with its own service account, which may
only `get` them, needs no enrollment or control-plane connection, and writes
the bundle's certificates into the volume as one read-only file. It never
mounts anything and drops every capability, but runs as root because the
kubelet's pod directories are root-owned. The CSIDriver asks the kubelet to
republish volumes periodically, so a changed TrustBundle reaches running pods
on the next republish rather than at once. Render the image digest before
applying it:

```sh
TRSTCTL_AGENT_DAEMONSET_TEMPLATE=deploy/kubernetes/csi-trust.yaml \
  scripts/release/render-kubernetes-agent-daemonset.sh ghcr.io/<owner>/trstctl@sha256:<digest> \
  | kubectl apply -f -
```

## Rolling a TrustBundle out to several clusters

Instead of applying the same TrustBundle in each cluster, roll it out from the
control plane to the clusters whose controllers report there. Pick the clusters
by the ids their reports carry (`trstctl-cli kubernetes trust-bundles` lists the
reporting controllers); the first is the canary:

```sh
jq -n --rawfile pem roots.pem '{name:"platform-roots", ca_bundle_pem:$pem,
  namespaces:["apps","payments"], clusters:["sha256:<canary>","sha256:<next>"]}' \
  | trstctl-cli kubernetes trust-rollouts start -f -
```

The control plane accepts public CERTIFICATE blocks only and records the
bundle's SHA-256. The canary's agent receives the bundle in the answer to its
next posture report, creates or updates `TrustBundle/platform-roots` as an
object it owns (label `app.kubernetes.io/managed-by: trstctl-agent`, annotation
`trstctl.com/rollout-id`), and its controller distributes it as above. The
canary reads verified only when its own controller reports the bundle
distributed with that hash; then the other clusters receive it, and the
rollout completes when each has reported the same. A failure is shown with
its reason and holds the rest back while the canary has not verified. Pause a
rollout to hold the canary gate, and resume it to continue. Starting a new
rollout of the same name replaces the earlier one cluster by cluster: a
cluster keeps the bundle it has until the new rollout reaches it.

The agent never changes a TrustBundle of that name that someone else created;
the rollout then waits on that cluster. To keep rollouts out of a cluster, run
its agent with `--k8s-trust-rollouts=false` and remove the TrustBundle
create/update/patch verbs from its ClusterRole. `GET
/api/v1/kubernetes/trust-rollouts/{id}`, `trstctl-cli kubernetes trust-rollouts
get`, and the Workloads console show each cluster's state and the report that
verified it.

## trstctl native Certificate API

If you do not want cert-manager to own the workload object, create a trstctl
`Certificate` directly. The agent verifies the referenced trstctl `Issuer` or
`ClusterIssuer` exists, generates the workload key locally, forwards only the CSR
to the served trstctl issuance endpoint, writes `Secret/<secretName>` as a
`kubernetes.io/tls` Secret, and marks the `Certificate` Ready.

```yaml
apiVersion: trstctl.com/v1alpha1
kind: Certificate
metadata:
  name: web
  namespace: apps
spec:
  secretName: web-tls
  commonName: web.apps.svc.cluster.local
  dnsNames:
    - web.apps.svc.cluster.local
    - web.apps
  keyAlgorithm: ECDSA-P256
  issuerRef:
    name: trstctl
    kind: ClusterIssuer
    group: trstctl.com
```

The private key is generated inside the agent process, carried as `[]byte`, wiped
after the Kubernetes Secret write, and never sent to the control plane. The
served controller test proves the path: `Certificate` -> local CSR -> trstctl
signer -> `Secret` -> `Certificate.status.conditions[Ready=True]`.

The agent renews the certificate with a new key two thirds of the way through
the validity it had when issued. `status.notBefore` and `status.notAfter` record
the issued validity, `status.renewalTime` when the replacement is due, and
`status.specHash` the spec it was issued for: a changed spec (another name, key
algorithm or Secret) is reissued at once, and a deleted Secret is reissued at
the next re-check. The issuer's `ttlSeconds` and the CA profile bound the
lifetime; without either, a certificate lasts 24 hours and is renewed after
about 16.

## End-to-end test

`test/e2e/kubernetes` exercises the secret destination, the legacy raw
`CertificateRequest` bridge, the full cert-manager
`Certificate` -> trstctl `ClusterIssuer` -> `Secret` flow, and the event-driven
controller (with its re-check ten minutes away: a TrustBundle copied and a
deleted copy restored, an approved native CSR signed, a trstctl `Certificate`
issued and renewed) against a real API server. The unit acceptance suite also exercises the trstctl-native
`Certificate` -> local CSR -> `Secret` flow and the native Kubernetes
`CertificateSigningRequest` -> status.certificate flow plus `TrustBundle` ->
namespace ConfigMap distribution through the same controller. CI runs the kind path with cert-manager installed (the
`kubernetes / kind e2e` job). The agent uses its restricted service-account token
(`K8S_TOKEN`); fixtures and verification use an admin token (`K8S_ADMIN_TOKEN`),
because the agent service account is least-privilege and cannot create
cert-manager resources. Locally:

```sh
export K8S_SERVER=... K8S_TOKEN=... K8S_ADMIN_TOKEN=... K8S_CA_FILE=... K8S_NAMESPACE=trstctl
go test -tags e2e ./test/e2e/kubernetes/...
```

Manual kind check for the RUNOPS-002 multi-node bootstrap path:

```sh
kind create cluster --name trstctl-runops-002 --config - <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
  - role: worker
YAML

kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
# Then run the deploy block above and confirm Secret/trstctl-agent-bootstrap has
# one key per listed node before applying the rendered DaemonSet.
```

The controller merges into a request's status (it preserves conditions such as
cert-manager's `Approved`, upserting `Ready`), so it composes with cert-manager's
approval flow. The kind test's separate admin fixture explicitly approves each
request before the restricted agent signs it. The platform-neutral logic is
covered on every platform by unit tests against an in-process Kubernetes API double.
