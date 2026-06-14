package helm

import "testing"

// TestSignerIsolationChart (S15.1) verifies the chart can deploy the signer as its
// own network-policy-isolated pod with a hardened security context, and that the
// external-KMS values exist (AN-4/AN-8). It reuses the read/containsAll helpers
// from helm_test.go.
func TestSignerIsolationChart(t *testing.T) {
	dep := read(t, "templates", "signer-deployment.yaml")
	containsAll(t, "signer-deployment.yaml", dep,
		"kind: Deployment",
		"app.kubernetes.io/component: signer",
		"readOnlyRootFilesystem: true",
		"runAsNonRoot: true",
		`drop: ["ALL"]`,
		`eq .Values.signer.mode "isolated"`,
	)
	np := read(t, "templates", "signer-networkpolicy.yaml")
	containsAll(t, "signer-networkpolicy.yaml", np,
		"kind: NetworkPolicy",
		"Ingress",
		"Egress",
		"port: 9443",
	)
	svc := read(t, "templates", "signer-service.yaml")
	containsAll(t, "signer-service.yaml", svc, "kind: Service", "grpc-mtls")

	vals := read(t, "values.yaml")
	containsAll(t, "values.yaml", vals, "signer:", "mode: sidecar", "externalKMS:", "provider:")
}
