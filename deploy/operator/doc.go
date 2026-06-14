// Package operator carries the Kubernetes Operator packaging for the trustctl
// control plane (S15.1): the TrustctlControlPlane CRD (crd.yaml) and the operator
// Deployment + RBAC (operator.yaml). The operator reconciles a TrustctlControlPlane
// custom resource into the same resources the Helm chart renders — control-plane
// Deployment, the network-policy-isolated signer pod (AN-4), Services, and
// external-KMS-backed secrets (AN-8). The reconcile-loop controller image is built
// and integration-tested on CI (kind); this package holds the deployable manifests
// and their structural validation.
package operator
