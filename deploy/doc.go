// Package deploy holds the cross-cutting, behavioural deployment checks that span
// every deploy/ subtree (Docker, Helm, raw Kubernetes manifests, the operator).
//
// The per-subtree packages (deploy/docker, deploy/helm, deploy/kubernetes,
// deploy/operator) validate their own artifacts. This package adds the checks
// that must hold ACROSS them and that string-matching could not catch (OPS-008):
// every flag a manifest passes to a trstctl binary is a flag that binary really
// defines, and every container image a manifest references is one a workflow
// actually builds (or is explicitly marked as a not-yet-built placeholder).
package deploy
