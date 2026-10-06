# Kubernetes agent integrations and e2e testing

This guide covers the trstctl Kubernetes agent's integration paths — cert-manager,
native `CertificateSigningRequest`s, `TrustBundle` distribution, and the
trstctl-native `Certificate` API — plus how to exercise all of them end-to-end,
including the kind-based CI path. Deploy the agent first with
`deploy/kubernetes/README.md` in the source checkout; come here once
it is running and you need to wire in one of these integrations or reproduce the
e2e/kind test locally.

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

Grant a distinct approver only the signer name it reviews. For example, bind
the following `ClusterRole` to a separate approver identity, and give that
identity `get` on `certificaterequests` plus `update` on
`certificaterequests/approval` in the workload namespace. The agent service
account needs neither grant:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: trstctl-web-approver
rules:
  - apiGroups: [cert-manager.io]
    resources: [signers]
    resourceNames: [clusterissuers.trstctl.com/trstctl]
    verbs: [approve]
```

After inspecting the generated request, the authorized approver can approve it:

```sh
kubectl -n apps get certificaterequest
cmctl approve -n apps <request-name> --reason pki-review
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
will not infer a namespaced issuer from a same-named resource. The agent requests
24 hours if `spec.expirationSeconds` is absent, subject to the CA profile.

```yaml
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: web
  annotations:
    trstctl.com/issuer-kind: ClusterIssuer
spec:
  signerName: trstctl.com/trstctl
  request: <base64-der-csr>
  usages:
    - digital signature
    - key encipherment
    - server auth
```

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
`payments`, setting `data["ca-bundle.pem"]` to the public CA bundle. It does not
copy private keys, bearer tokens, or workload credentials into the ConfigMap. Use
`trstctl-cli kubernetes trust-bundles` or
`GET /api/v1/kubernetes/trust-bundles` to inspect the served CAP-K8S-07 posture,
required RBAC, status fields, and residuals.

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

## End-to-end test

`test/e2e/kubernetes` exercises the secret destination, the legacy raw
`CertificateRequest` bridge, and the full cert-manager
`Certificate` -> trstctl `ClusterIssuer` -> `Secret` flow against a real API
server. The unit acceptance suite also exercises the trstctl-native
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
