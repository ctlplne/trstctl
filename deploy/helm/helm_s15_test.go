package helm

import (
	"strings"
	"testing"
)

// TestSignerIsolationChart (S15.1) verifies the chart still CARRIES the forward-
// looking isolated-signer topology (its own pod, hardened security context,
// network policy), and that the external-KMS values exist (AN-4/AN-8). It reuses
// the read/containsAll helpers from helm_test.go.
//
// OPS-001: the isolated topology is GATED OFF at render time (cross-node mTLS is
// unimplemented; the signer is UDS-only). The render-behaviour of that gate — and
// the proof that the signer template no longer passes an undefined flag — are
// asserted below and, behaviourally, by deploy/deploycheck_test.go.
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

// TestIsolatedSignerModeIsGated (OPS-001) asserts the chart guards the
// not-yet-implemented isolated/mTLS signer topology instead of shipping a
// crash-looping pod:
//
//   - a guard helper exists and is invoked from an always-rendered template, so a
//     default install validates the mode and `--set signer.mode=isolated` fails
//     the render with guidance;
//   - the signer template no longer passes the undefined `--mtls-listen` flag and
//     no longer references an un-built `-signer` image.
//
// The full render-time behaviour (sidecar renders / isolated + bogus modes fail)
// is exercised against the binary's real flag set in deploy/deploycheck_test.go.
func TestIsolatedSignerModeIsGated(t *testing.T) {
	helpers := read(t, "templates", "_helpers.tpl")
	containsAll(t, "_helpers.tpl", helpers,
		`define "trustctl.signer.guardMode"`,
		`fail`,
	)

	// The guard is invoked from the always-rendered deployment.yaml, so every
	// render validates the signer mode (not only the gated isolated-mode files).
	dep := read(t, "templates", "deployment.yaml")
	if !strings.Contains(dep, `include "trustctl.signer.guardMode"`) {
		t.Error("deployment.yaml must invoke trustctl.signer.guardMode so a default render validates signer.mode (OPS-001)")
	}

	// The signer template must not pass the undefined --mtls-listen flag, and must
	// not reference a separate, un-built -signer image (OPS-001/OPS-002).
	signer := read(t, "templates", "signer-deployment.yaml")
	for _, forbidden := range []string{
		`"--mtls-listen"`,
		`{{ .Values.image.repository }}-signer`,
		`TRUSTCTL_KMS_PROVIDER`, // env the binary never reads
	} {
		if strings.Contains(signer, forbidden) {
			t.Errorf("signer-deployment.yaml still contains %q — the OPS-001/OPS-002 defect", forbidden)
		}
	}
	// It runs the signer from the single multi-binary image instead.
	containsAll(t, "signer-deployment.yaml runs the built image's signer", signer,
		`include "trustctl.image"`,
		"trustctl-signer",
	)
}
