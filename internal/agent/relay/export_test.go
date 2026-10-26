// SPDX-License-Identifier: BUSL-1.1

package relay

import "trstctl.com/trstctl/internal/agent/k8s"

// SetKubernetesClientForTest points the k8s_secret executor at a test API
// server instead of the pod's in-cluster service account. It returns the
// restore function.
func SetKubernetesClientForTest(f func() (*k8s.Client, error)) func() {
	previous := newKubernetesClient
	newKubernetesClient = f
	return func() { newKubernetesClient = previous }
}
