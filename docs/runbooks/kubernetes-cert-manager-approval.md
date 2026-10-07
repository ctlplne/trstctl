# Keep cert-manager renewal approved for a trstctl external issuer

cert-manager creates a new `CertificateRequest` for every issuance and renewal.
The trstctl agent signs only after Kubernetes records `Approved=True`; it cannot
approve its own request. If no separate approver handles the new request, the old
TLS Secret remains in service until it expires. A green trstctl issuer and an
older Ready `Certificate` do not prove the listener has a valid leaf.

Use an independent cert-manager approver with a policy bound to the **requester**
ServiceAccount. The example below is for one workload. Replace the namespace,
issuer name, DNS name, CertificateRequest name prefix, and duration with the
reviewed values for your deployment. A broad signer list or a wildcard DNS rule
would approve requests outside that intent.

## Install the independent approver

The cert-manager project publishes `cert-manager-approver-policy`. Pin a reviewed
chart and image digest, mirror both into your registry for an air-gapped cluster,
and install the chart separately from the trstctl agent. The following v0.27.0
values grant this approver Kubernetes `approve` permission for **one** external
signer; the digest is the published multi-platform image index. Use your mirrored
repository in place of `quay.io` when the cluster has no external egress.

```yaml
# approver-values.yaml
image:
  repository: quay.io/jetstack/cert-manager-approver-policy
  digest: sha256:74799ce00f4715f671843306d53bdaf388c1b435804f6e91507cc506717ede02
app:
  approveSignerNames:
    - clusterissuers.trstctl.com/trstctl
```

```sh
helm upgrade --install trstctl-approver-policy \
  oci://quay.io/jetstack/charts/cert-manager-approver-policy \
  --version v0.27.0 --namespace cert-manager --values approver-values.yaml --wait
```

If you already configured cert-manager's default approver to auto-approve this
external signer, remove that grant before relying on a restrictive policy.
Leave built-in issuer approval in place unless you have equivalent policies for
those issuers. In a multi-node production cluster, size and replicate the
approver for your availability requirement; one pod on a single kind node
does not establish high availability.

## Bind one request policy

The example requires cert-manager's own controller ServiceAccount to create a
request for `web.apps.svc.cluster.local`, under the named ClusterIssuer in the
`apps` namespace. It refuses a CA certificate, a missing or different DNS SAN,
another requester, another request name prefix, a lifetime other than two hours,
or a key other than ECDSA P-256. The `use` Role binds only that policy to that
ServiceAccount. If your cert-manager installation uses a different ServiceAccount,
inspect the live request's `spec.username` and change both the CEL rule and the
RoleBinding subject.

```yaml
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  name: trstctl-web
spec:
  selector:
    issuerRef: {group: trstctl.com, kind: ClusterIssuer, name: trstctl}
    namespace:
      matchNames: [apps]
  allowed:
    dnsNames:
      required: true
      values: [web.apps.svc.cluster.local]
      validations:
        - rule: 'cr.username == "system:serviceaccount:cert-manager:cert-manager" && cr.name.startsWith("web-")'
          message: The request must come from cert-manager for the approved web workload.
    isCA: false
  constraints:
    minDuration: 2h
    maxDuration: 2h
    privateKey: {algorithm: ECDSA, minSize: 256, maxSize: 256}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: trstctl-web-policy-use
rules:
  - apiGroups: [policy.cert-manager.io]
    resources: [certificaterequestpolicies]
    resourceNames: [trstctl-web]
    verbs: [use]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: trstctl-web-policy-use
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: trstctl-web-policy-use
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager
```

Check that the policy reports `Ready=True`. Confirm the requester can `use` this
policy while unrelated ServiceAccounts cannot. Create disposable negative
`CertificateRequest`s with an excessive duration and a wrong DNS name; both
must gain `Denied=True` without a signed certificate. Delete only those exact
canaries after recording the denial.

Then use stock `cmctl renew <certificate-name> --namespace <namespace>` to
exercise a new request. Read its `Approved` condition: the reason should be
`policy.cert-manager.io` and the message should name the exact policy. Wait for
`Ready=True`, then compare the issued leaf to the Secret key and check the
**served** TLS endpoint with a stock client that verifies the hostname and CA.
Observe at least one later scheduled renewal without another operator action
before calling the recurring path unattended. Monitor the request's pending age,
the Certificate's `notAfter` and `renewalTime`, Secret projection, and the
listener. Alert while there is enough time to recover before expiry.

The policy controller's Kubernetes request condition records the decision and
policy name. trstctl's Workloads view and
`GET /api/v1/kubernetes/cert-manager-certificate-requests` report the signed
request UID and public fingerprint; they do not prove that a workload has loaded
the Secret. Retain stock Kubernetes and TLS readback for that last step.
