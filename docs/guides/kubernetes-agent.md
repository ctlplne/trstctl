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

The controller reduces list page size when a Kubernetes API response exceeds
its 4 MiB read bound, then starts a new consistent collection snapshot at that
size. If even a one-object page cannot fit, that collection reports
`reconcile_failed` and the
agent log identifies `api_response_too_large` and the collection path. Check the
agent log and reduce the oversized resource before relying on signing or bundle
posture for that collection. The controller does not mark an incomplete list as
synced.

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
must set `Approved=True` first; the trstctl agent does not approve
cert-manager requests and ignores unapproved or denied ones.

**Native CSRs approved by the CA's profile (opt-in).** For native
`CertificateSigningRequest`s addressed to a trstctl signer name
(`trstctl.com/trstctl`, `trstctl.com/<issuer-name>`), the agent can decide
approval itself: start it with `--k8s-csr-approver` beside
`--cert-manager-controller`, and apply `deploy/kubernetes/rbac-csr-approver.yaml`
(update on `certificatesigningrequests/approval`, approve on the trstctl signer
names; add your named issuers' signer names to it). For each pending request the
agent asks the issuing CA whether it would issue it — the CA authority's
`/issue/evaluate`, the checks issuance makes, without signing — and writes
`Approved`, or `Denied` with the CA's reason, both with condition reason
`TrstctlProfilePolicy`. An approved request is signed in the same pass. Without
the flag a Kubernetes approver decides, as before. Put the same exact HTTPS
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

To distribute a public CA bundle into multiple namespaces, first set the
controller's DaemonSet arg to `--k8s-trust-namespaces=apps,payments`, using the
exact namespace names that should receive trust. The shipped value is empty and
permits no namespaces. The list applies to locally created TrustBundles and
control-plane rollouts. Names beginning `kube-` are always refused. Keep the
Kubernetes RBAC grants for the intended targets.

Create a cluster-scoped trstctl `TrustBundle`. The agent parses each X.509
certificate, re-encodes the public PEM in the supplied order, and compares the
SHA-256 of those canonical bytes. The same bytes go to each admitted target.

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

The agent writes `data["ca-bundle.pem"]` in `ConfigMap/platform-ca-bundle` in
`apps` and `payments`. A new object gets the labels
`app.kubernetes.io/managed-by: trstctl-agent` and
`trstctl.com/trust-bundle: platform-roots`. Both labels must match on an
existing object before it can be updated. Other data keys are preserved. The
controller rewrites an edited or missing owned copy on a watch event or resync.
An already matching copy is left alone.

The shipped DaemonSet can write ConfigMaps only in its own `trstctl` namespace.
For each `apps` or `payments` target in this example, copy
`deploy/kubernetes/rbac-trust-configmaps.yaml`, set both Role and RoleBinding
`metadata.namespace` values to that exact namespace, and apply that copy.
The opt-in grant has `get`, `create`, `update` and `patch` on ConfigMaps only
within its namespace. Without it, distribution reports an authorization
failure for that target; the default agent cannot write `kube-system`.

Use exact Kubernetes names for namespaces and targets. A TrustBundle name
must fit in its 63-character ownership label. The target names
`trstctl-ca-bundle` and `trstctl-secrets-csi` are reserved, including when they
carry matching labels. Omit optional fields to use their defaults. The CRD
preserves an explicit `null` for the controller to refuse. A bad target or
namespace anywhere in the list blocks the bundle before it touches any target.
An API failure after preflight can leave a partial distribution, since
Kubernetes writes each object independently.

`kubectl get trustbundle` shows `Ready=False` and the `DistributionFailed`
reason when distribution fails for an eligible local CR or a CR with a valid
agent-owned rollout identity. The agent leaves status untouched for reserved
names and unowned remote identities. Correct the spec, local
allowlist or Kubernetes grant and verify the next reconcile. Use
`trstctl-cli kubernetes trust-bundles` or `GET /api/v1/kubernetes/trust-bundles`
for CAP-K8S-07 posture, required RBAC, and status fields.

### Secret and ClusterTrustBundle targets

Some consumers read CA bundles from Secrets, and Kubernetes can mount a
`ClusterTrustBundle` into pods through a projected volume. A locally authored TrustBundle can
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
the canonical certificates into the volume as one read-only file. Local
TrustBundles are eligible by default. For remote-origin TrustBundles, set
`--k8s-trust-rollouts=true` on the CSI driver DaemonSet itself. The driver
checks the object's rollout identity and admitted bundle hash before serving it.
The namespace allowlist controls the controller's object fan-out. CSI volume
access uses Kubernetes Pod admission and kubelet volume authorization. The plugin never
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

### Secrets as inline CSI volumes

`deploy/kubernetes/csi-secrets.yaml` installs a second, separate node plugin
(CSI driver `secrets.csi.trstctl.com`) that hands a pod its secrets as an inline
volume in a memory filesystem, read with the pod's own service-account token,
with no Kubernetes Secret object. The control plane needs a `kubernetes`
machine-login method for this cluster's service-account issuer and the
`trstctl` audience. Put the server, its CA and the tenant in the
`trstctl-secrets-csi` ConfigMap, then render the image digest and apply:

```sh
TRSTCTL_AGENT_DAEMONSET_TEMPLATE=deploy/kubernetes/csi-secrets.yaml \
  scripts/release/render-kubernetes-agent-daemonset.sh ghcr.io/<owner>/trstctl@sha256:<digest> \
  | kubectl apply -f -
```

Unlike the trust plugin it is privileged, because it mounts a tmpfs for each
volume. Its volume attributes and its trust boundary are in
[secrets](../features/secrets.md#secret-volumes-for-pods-with-no-kubernetes-secret-a238).

## Rolling a TrustBundle out to several clusters

Enable remote rollout execution on each participating controller by setting
`--k8s-trust-rollouts=true` on its DaemonSet. Configure the same local
`--k8s-trust-namespaces` list for all namespaces the rollout needs. The shipped
controller and CSI driver both default to `false`. With the opt-in off, the
controller refuses stored remote-origin CRs and incoming remote rollouts.

To schedule a rollout, pick the cluster IDs their controllers reported to the
control plane. `trstctl-cli kubernetes trust-bundles` lists the reporting
controllers. The first cluster is the canary.

```sh
jq -n --rawfile pem roots.pem '{name:"platform-roots", ca_bundle_pem:$pem,
  namespaces:["apps","payments"], clusters:["sha256:<canary>","sha256:<next>"]}' \
  | trstctl-cli kubernetes trust-rollouts start -f -
```

New rollouts record the canonical public PEM and its SHA-256. The canary
receives the desired revision on its next posture report. The cluster agent
creates or revises the remote-owned `TrustBundle/platform-roots` and records
`trstctl.com/rollout-id` and `trstctl.com/rollout-sha256`. A rollout can update
only a prior TrustBundle it can identify as rollout-owned. Remote TrustBundles
can distribute to ConfigMaps. Secret and ClusterTrustBundle fan-out require a
locally authored CR.

A matching Ready posture report allows the canary gate to advance. Check the
live TrustBundle annotations and read back each intended target when verifying
a revision. Posture compares name and public PEM hash, so the same hash alone
cannot establish which revision or target set was applied. Use `trstctl-cli
kubernetes trust-rollouts get`, `GET /api/v1/kubernetes/trust-rollouts/{id}`, or
the Workloads console to see the report and each cluster's state. Starting a
new rollout of the same name replaces the earlier one cluster by cluster.

### Upgrade and recover trust rollouts

1. Stop older controller and CSI processes or remove their effective update
   and mount authority. Pause holds future canary progression. An older agent
   can still receive dispatched work or reconcile stored rollout CRs.
2. Apply the updated TrustBundle CRD. Inventory existing CRs, ConfigMaps, and
   CSI mounts before opting in. An older agent may have put its labels on an
   existing object. Use known-good configuration to restore any such object
   and retain intentionally managed targets. The old CRD may already have
   converted an explicit null to an omitted or defaulted field.
3. Upgrade all control-plane writers and projectors before resuming writes.
   New starts use event schema v2. The upgraded projector preserves the
   original bytes and hash of a v1 event. If the agent refuses an older bundle
   because its hash differs after canonicalization, create a new rollout from
   the intended public certificates. A validated delivery is required to
   re-admit a stored remote CR that predates the hash annotation.
4. Enable the participating agents. Verify a known canary's actual targets
   before widening distribution. Turning opt-in off fences new agent work and
   keeps previously published objects and mount files in place. Keep older
   agents fenced on rollback. Once v2 events exist, keep v2-capable projectors
   or stop incompatible projectors until they can read the journal.

If a rollout start was interrupted between append and projection, keep the
same `Idempotency-Key`. A 503 can indicate that an exact retained event is
awaiting its read-model row. For a known or suspected interruption, stop
writers, live and warm projectors, and consumers of desired state before
recovery. On external PostgreSQL and external NATS, run `trstctl --rebuild`
against the retained journal, then check the rebuilt rollout and cluster
states and independently verify the desired revision for each cluster before
reopening. A successful retry or warm restart alone cannot establish
that earlier dispatches were rebuilt in source order. On bundled PostgreSQL
or embedded NATS, keep the affected rollout writes, desired delivery, and
remote execution fenced pending qualified ordered recovery. The shipped
`--rebuild` command requires both datastores to be external.

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
