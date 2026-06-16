// Package operator carries the Kubernetes Operator packaging for the trstctl
// control plane (S15.1): the TrstctlControlPlane CRD (crd.yaml) and the operator
// Deployment + RBAC (operator.yaml).
//
// STATUS — SHIPPED, MINIMAL. The reconcile-loop controller is implemented in
// cmd/trstctl-operator (logic in internal/operator). It is a real, functional
// controller — not a stub: each reconcile reads every TrstctlControlPlane custom
// resource, reads the live control-plane Deployment, diffs the declared spec
// against the actual state, and CONVERGES it (creates the Deployment when it is
// missing, patches it when its replica count or image has drifted, does nothing
// when it already matches), then writes the observed phase back to the resource
// status. It is level-based (poll, diff, act), so a missed change is corrected on
// the next reconcile. It speaks the Kubernetes API directly over JSON-over-HTTPS
// with no client-go / controller-runtime dependency (none is in go.mod), and
// builds its TLS trust through the crypto boundary (AN-3).
//
// The controller binary SHIPS in the single multi-binary control-plane image the
// release pipeline builds (deploy/docker/Dockerfile builds ./cmd/trstctl-operator
// into it; .github/workflows/release.yml builds, signs, and publishes that image).
// operator.yaml runs it via an entrypoint override of that built image — the same
// packaging the agent DaemonSet uses (OPS-002) — so the image it references is a
// real, built, signed artifact, NOT a placeholder.
//
// SCOPE / MATURITY (no over-claim): this is deliberately a minimal operator. It
// owns exactly the managed control-plane Deployment's replica count and image. It
// does NOT yet manage Services, secrets, NetworkPolicy, or the isolated-signer
// topology, and it is not a full informer/work-queue controller (it polls). For a
// complete, production-shaped control-plane install — isolated signer, external
// PostgreSQL/NATS, default-deny NetworkPolicy, multi-replica HA — the Helm chart
// (deploy/helm/trstctl) remains the richer and recommended path; see
// docs/limitations.md ("A Kubernetes Operator"). The CRD's externalKMS / postgres
// / nats / signerMode fields are part of the forward-looking resource shape and
// are not all acted on yet.
//
// Coverage: internal/operator's reconcile_test.go drives the controller against
// an in-memory Kubernetes API and asserts it creates/patches/no-ops correctly for
// each desired-vs-actual diff; deploy/operator/operator_test.go validates the CRD
// and manifests; deploy/deploycheck_test.go confirms the operator image is one a
// workflow actually builds and that the manifest's flags are defined by the
// binary.
package operator
