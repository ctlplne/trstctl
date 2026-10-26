// SPDX-License-Identifier: BUSL-1.1

// Package operator carries the Kubernetes Operator packaging for the trstctl
// control plane (S15.1): the TrstctlControlPlane CRD (crd.yaml) and the operator
// Deployment + RBAC (operator.yaml).
//
// STATUS — SHIPPED, FOCUSED. The reconcile-loop controller is implemented in
// cmd/trstctl-operator (logic in internal/operator). It is a real, functional
// controller — not a stub: each reconcile reads every TrstctlControlPlane custom
// resource, reads the live control-plane Deployment, diffs the declared spec
// against the actual state, and CONVERGES it (creates the Deployment when it is
// missing, patches it when replica count, image, PostgreSQL/NATS env, sidecar
// signer wiring, or operator-owned config has drifted, does nothing when it
// already matches). It also reconciles TrstctlSecretSync custom resources into
// Kubernetes Secrets, resolves source values through the served trstctl secret
// API, and patches opted-in Deployments/StatefulSets/DaemonSets with a content
// hash annotation so Kubernetes rolls pods after a secret changes. It also
// reconciles TrstctlSecretInjection resources into no-code workload pod-template
// patches: an app-facing memory volume, env valueFrom references, and the shipped
// trstctl-agent secret-injection sidecar. It writes the observed phase back to
// each resource status.
// It is level-based (poll, diff, act), so a missed change is corrected on the
// next reconcile. When deployed with two replicas, cmd/trstctl-operator uses a
// real coordination.k8s.io Lease so exactly one replica reconciles while the
// other remains a hot follower. It speaks the Kubernetes API directly over
// JSON-over-HTTPS with no client-go / controller-runtime dependency (none is in
// go.mod), and builds its TLS trust through the crypto boundary (AN-3).
//
// The controller binary SHIPS in the single multi-binary control-plane image the
// release pipeline builds (deploy/docker/Dockerfile builds ./cmd/trstctl-operator
// into it; .github/workflows/release.yml builds, signs, and publishes that image).
// operator.yaml runs it via an entrypoint override of that built image — the same
// packaging the agent DaemonSet uses (OPS-002) — so the image it references is a
// real, built, signed artifact, NOT a placeholder.
//
// SCOPE / MATURITY (no over-claim): this is a focused CRD-driven operator. It
// owns the managed control-plane Deployment and the runtime config that fits in
// that Deployment: replicas, image, PostgreSQL DSN Secret reference, NATS URL /
// replica knobs, sidecar-signer socket/volumes, signer authorization (the
// independent token command, or the evaluation co-resident authorizer), and
// managed-key provider enablement. It owns the control plane's network surface
// the way the Helm chart renders it: a Service on the API/UI port, a default-deny
// NetworkPolicy that admits only the named ingress controller and namespaces and
// lets the control plane reach DNS, PostgreSQL, NATS and its signer, and an
// optional Ingress. With signerMode isolated it runs the signer as its own pod
// with its own Service and a NetworkPolicy that admits only this control plane,
// over a mutually pinned mTLS channel whose two Secrets it generates (and renews
// a month before they expire) unless the resource names Secrets you provide.
// Every object it creates carries its managed-by and owner labels and an owner
// reference; it deletes only objects carrying both, and refuses to take over an
// object of the same name that it does not own. It also owns the
// TrstctlSecretSync projection path: CRD -> Kubernetes Secret -> workload reload
// annotation, and TrstctlSecretInjection: CRD -> workload pod-template injection
// -> app mount/env. It is not a full informer/work-queue controller (it polls).
// The Helm chart (deploy/helm/trstctl) remains the path for what the CRD does not
// model yet, for example generated KEK and authorization Secrets, the
// PodDisruptionBudget, the ServiceMonitor and external KMS custody arguments; see
// docs/limitations.md ("Kubernetes deployment").
//
// Coverage: internal/operator's reconcile_test.go and networking_test.go drive
// the controller against an in-memory Kubernetes API and assert it
// creates/patches/no-ops correctly for each desired-vs-actual diff, including full
// config, the network surface, the isolated signer and its mTLS pair, and
// two-replica leader election; test/e2e/kubernetes runs the reconciler against a
// real API server (kind in CI) with only the RBAC operator.yaml grants;
// deploy/operator/operator_test.go validates the CRD and manifests;
// deploy/deploycheck_test.go confirms the operator image is one a workflow
// actually builds and that the manifest's flags are defined by the binary.
package operator
