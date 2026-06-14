// Package operator carries the Kubernetes Operator packaging for the trustctl
// control plane (S15.1): the TrustctlControlPlane CRD (crd.yaml) and the operator
// Deployment + RBAC (operator.yaml). The operator would reconcile a
// TrustctlControlPlane custom resource into the same resources the Helm chart
// renders — control-plane Deployment, the signer (AN-4), Services, and secrets.
//
// STATUS — PLANNED, NOT YET SHIPPED (S15.1). The reconcile-loop controller is not
// implemented: there is no cmd/trustctl-operator, and no workflow builds a
// trustctl-operator image, so operator.yaml's image reference is not yet
// buildable (OPS-002). docs/limitations.md ("A Kubernetes Operator") discloses
// this: today the Helm chart is the supported control-plane install. This package
// holds the forward-looking CRD + RBAC + Deployment manifests and their
// structural validation only; it is not a deployable controller until the
// controller binary and its image build land.
package operator
