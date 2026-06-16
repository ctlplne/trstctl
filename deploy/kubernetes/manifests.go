// Package kubernetes embeds the Kubernetes deployment manifests for the trstctl
// agent — the namespace, the service account and RBAC, and the DaemonSet — so
// they ship inside the binary and are validated by tests.
package kubernetes

import "embed"

// Manifests holds the agent's Kubernetes YAML (namespace, RBAC, DaemonSet).
//
//go:embed *.yaml
var Manifests embed.FS
