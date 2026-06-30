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
// replica knobs, sidecar-signer socket/volumes, and managed-key provider enablement.
// It also owns the TrstctlSecretSync projection path: CRD -> Kubernetes Secret ->
// workload reload annotation, and TrstctlSecretInjection: CRD -> workload
// pod-template injection -> app mount/env. It does NOT yet manage Services, ingress,
// NetworkPolicy, or the cross-pod isolated-signer Service topology, and it is not a full
// informer/work-queue controller (it polls). For a complete, production-shaped
// control-plane install — ingress/service wiring, default-deny NetworkPolicy,
// secret generation, and cross-pod signer mTLS — the Helm chart
// (deploy/helm/trstctl) remains the richer and recommended path; see
// docs/limitations.md ("A Kubernetes Operator").
//
// Coverage: internal/operator's reconcile_test.go drives the controller against
// an in-memory Kubernetes API and asserts it creates/patches/no-ops correctly for
// each desired-vs-actual diff, including full config and two-replica leader
// election; deploy/operator/operator_test.go validates the CRD and manifests;
// deploy/deploycheck_test.go confirms the operator image is one a workflow
// actually builds and that the manifest's flags are defined by the binary.
package operator
